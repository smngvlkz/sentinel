"""The dashboard API's notification endpoints and single-alert lookup, on a real Postgres
(skipped unless SENTINEL_TEST_DATABASE_URL is set)."""

import contextlib
import importlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

api = importlib.import_module("dashboard-api.main")
from common.migrations import migrate  # noqa: E402


class FakeRedis:
    def __init__(self, beat=None):
        self.beat = beat

    def get(self, key):
        assert key == api.NOTIFIER_HEARTBEAT_KEY
        return json.dumps(self.beat) if self.beat is not None else None


def beat(**kw):
    return {"at": time.time(), "enabled": True, "error": None, "channels": ["ntfy"],
            "min_severity": "high", "quiet_now": False, **kw}


@pytest.fixture
def app(database, monkeypatch):
    from fastapi.testclient import TestClient

    conn = database()
    migrate(conn)
    conn.autocommit = True

    @contextlib.contextmanager
    def test_db():
        c = database()
        c.autocommit = True
        try:
            yield c
        finally:
            c.close()

    redis = FakeRedis()
    monkeypatch.setattr(api, "get_db", test_db)
    monkeypatch.setattr(api, "get_redis", lambda: redis)
    monkeypatch.delenv("DASHBOARD_BIND", raising=False)
    with conn.cursor() as cur:
        yield TestClient(api.app), cur, redis
    conn.close()


def test_one_alert_with_device_names(app):
    client, cur, _ = app
    cur.execute("INSERT INTO device_names (ip, name) VALUES ('192.168.1.20', 'Front door camera')")
    cur.execute(
        """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip)
           VALUES (NOW(), 'SYN_FLOOD', '203.0.113.9', '192.168.1.20') RETURNING id"""
    )
    alert_id = cur.fetchone()[0]
    r = client.get(f"/alerts/{alert_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == alert_id and body["severity"] == "high"
    assert body["destination_device"] == "Front door camera"
    missing = client.get(f"/alerts/{alert_id + 1}")
    assert missing.status_code == 404 and "retention" in missing.json()["detail"]
    assert client.get("/alerts/summary").status_code == 200  # not taken for an id


def test_status_when_the_notifier_isnt_running(app):
    client, _, _ = app
    body = client.get("/notifications").json()
    assert body["running"] is False and body["enabled"] is False and body["channels"] == []
    assert body["last_sent"] is None and body["last_test"] is None and body["sent_24h"] == 0


def test_stale_heartbeat_means_not_running(app):
    client, _, redis = app
    redis.beat = beat(at=time.time() - 120)
    assert client.get("/notifications").json()["running"] is False


def test_status_with_history(app):
    client, cur, redis = app
    redis.beat = beat()
    cur.execute(
        """INSERT INTO notifications (message_id, kind, channel, message, status, sent_at)
           VALUES (1, 'alert', 'ntfy', '{"title": "Connection flood"}', 'sent', NOW()),
                  (2, 'alert', 'email', '{"title": "Request flood"}', 'pending', NOW())"""
    )
    cur.execute("UPDATE notifications SET last_error = 'couldn''t connect', attempts = 2 WHERE channel = 'email'")
    body = client.get("/notifications").json()
    assert body["running"] and body["enabled"] and body["channels"] == ["ntfy"]
    assert body["last_sent"]["title"] == "Connection flood" and body["sent_24h"] == 1
    assert body["problem"]["channel"] == "email" and body["problem"]["attempts"] == 2


def test_test_button(app):
    client, cur, redis = app
    redis.beat = beat()
    r = client.post("/notifications/test", json={})
    assert r.status_code == 200, r.text
    cur.execute("SELECT count(*) FROM notification_tests WHERE handled_at IS NULL")
    assert cur.fetchone()[0] == 1
    # The notifier sends it; the status then shows each channel's result.
    cur.execute("UPDATE notification_tests SET handled_at = NOW()")
    cur.execute(
        """INSERT INTO notifications (message_id, kind, channel, message, status, attempts, sent_at)
           VALUES (5, 'test', 'ntfy', '{}', 'sent', 1, NOW())"""
    )
    test = client.get("/notifications").json()["last_test"]
    assert test["handled_at"] and test["results"] == [
        {"channel": "ntfy", "status": "sent", "attempts": 1, "last_error": None}
    ]


# The heartbeat is built when the test runs, not when the file is collected: it
# must be under 30 seconds old, and a slow suite can take longer than that.
@pytest.mark.parametrize("state, message", [
    (None, "isn't running"),
    ({"error": "min_severity must be one of high, medium, low"}, "needs fixing"),
    ({"channels": []}, "No channel"),
])
def test_test_button_explains_why_it_cant(app, state, message):
    client, cur, redis = app
    redis.beat = None if state is None else beat(**state)
    r = client.post("/notifications/test", json={})
    assert r.status_code == 409 and message in r.json()["detail"]
    cur.execute("SELECT count(*) FROM notification_tests")
    assert cur.fetchone()[0] == 0


def test_test_button_needs_a_trusted_request(app):
    client, _, redis = app
    redis.beat = beat()
    r = client.post("/notifications/test", content="{}", headers={"Content-Type": "text/plain"})
    assert r.status_code in (403, 415)
