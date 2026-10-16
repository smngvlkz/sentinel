"""The notifier against a real Postgres (skipped unless SENTINEL_TEST_DATABASE_URL is set)."""

import datetime as dt
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from common.migrations import migrate
from notifier.channels import SendError
from notifier.config import Settings
from notifier.service import RETRY_DELAYS, Notifier
from notifier.store import Store

NTFY = {"server": "http://ntfy", "topic": "t", "token": ""}


@pytest.fixture
def db(database):
    conn = database()
    migrate(conn)
    conn.autocommit = False
    yield conn
    conn.close()


def add_alert(conn, threat="SYN_FLOOD", src="203.0.113.9", dst="192.168.1.20", age_s=0):
    with conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, source_name)
               VALUES (NOW() - make_interval(secs => %s), %s, %s, %s, 'scanner.example') RETURNING id""",
            [age_s, threat, src, dst],
        )
        return cur.fetchone()[0]


class Phone:
    def __init__(self):
        self.got, self.failing = [], False

    def __call__(self, settings, message):
        if self.failing:
            raise SendError("couldn't connect: refused")
        self.got.append(message)


def notifier(conn, **settings):
    phone = Phone()
    n = Notifier(Store(conn), senders={"ntfy": phone, "email": phone})
    n.settings = Settings(**{"enabled": True, "channels": {"ntfy": NTFY}, **settings})
    return n, phone


def now():
    return dt.datetime.now(dt.timezone.utc)


def test_starts_after_existing_alerts_and_sends_new_ones_with_device_names(db):
    add_alert(db)
    n, phone = notifier(db)
    n.run_once(now())
    assert phone.got == []
    with db, db.cursor() as cur:
        cur.execute("INSERT INTO device_names (ip, name) VALUES ('192.168.1.20', 'Front door camera')")
    new = add_alert(db)
    n.run_once(now())
    assert len(phone.got) == 1
    assert phone.got[0]["body"].startswith(
        "scanner.example (203.0.113.9) flooded Front door camera with connection requests."
    )
    with db, db.cursor() as cur:
        cur.execute("SELECT last_alert_id FROM notifier_state")
        assert cur.fetchone()[0] == new
        cur.execute("SELECT kind, channel, status, attempts, alert_ids FROM notifications")
        assert cur.fetchall() == [("alert", "ntfy", "sent", 1, [new])]


def test_a_restart_carries_on_without_repeats_or_gaps(db):
    n, phone = notifier(db)
    n.run_once(now())
    add_alert(db)
    n.run_once(now())
    add_alert(db, threat="REQUEST_FLOOD")
    # A new notifier on the same database, as after a restart.
    n2, phone2 = notifier(db)
    n2.run_once(now())
    assert [m["title"] for m in phone.got] == ["Connection flood"]
    assert [m["title"] for m in phone2.got] == ["Request flood"]


def test_hourly_limit_and_summary(db):
    n, phone = notifier(db, max_per_hour=2)
    n.run_once(now())
    ids = [add_alert(db, src=f"203.0.113.{i}") for i in range(5)]
    n.run_once(now())
    assert len(phone.got) == 2
    with db, db.cursor() as cur:
        cur.execute("SELECT alert_id FROM notification_digest ORDER BY 1")
        assert [r[0] for r in cur.fetchall()] == ids[2:]
    n.run_once(now() + dt.timedelta(minutes=61))
    assert phone.got[-1]["title"] == "3 alerts held back"
    with db, db.cursor() as cur:
        cur.execute("SELECT count(*) FROM notification_digest")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT alert_ids FROM notifications WHERE kind = 'digest'")
        assert cur.fetchone()[0] == ids[2:]


def test_held_alert_deleted_by_retention_is_dropped(db):
    n, phone = notifier(db, max_per_hour=1)
    n.run_once(now())
    add_alert(db)
    gone = add_alert(db, src="198.51.100.7")
    n.run_once(now())
    with db, db.cursor() as cur:
        cur.execute("DELETE FROM alerts WHERE id = %s", [gone])
    n.run_once(now() + dt.timedelta(minutes=61))
    assert len(phone.got) == 1  # nothing left to summarise
    with db, db.cursor() as cur:
        cur.execute("SELECT count(*) FROM notification_digest")
        assert cur.fetchone()[0] == 0


def test_repeats_within_the_hour_arent_sent(db):
    n, phone = notifier(db)
    n.run_once(now())
    add_alert(db)
    n.run_once(now())
    add_alert(db)
    n.run_once(now() + dt.timedelta(minutes=1))
    assert len(phone.got) == 1
    add_alert(db)
    n.run_once(now() + dt.timedelta(minutes=61))
    assert len(phone.got) == 2


def test_retry_then_give_up(db):
    n, phone = notifier(db)
    n.run_once(now())
    add_alert(db)
    phone.failing = True
    t = now()
    n.run_once(t)
    for wait in RETRY_DELAYS:
        t += wait
        n.run_once(t)
    with db, db.cursor() as cur:
        cur.execute("SELECT status, attempts, last_error FROM notifications")
        assert cur.fetchone() == ("failed", len(RETRY_DELAYS) + 1, "couldn't connect: refused")


def test_test_requests(db):
    n, phone = notifier(db)
    with db, db.cursor() as cur:
        cur.execute("INSERT INTO notification_tests DEFAULT VALUES")
        cur.execute("INSERT INTO notification_tests DEFAULT VALUES")
    n.run_once(now())
    assert [m["title"] for m in phone.got] == ["SentinelAI test notification"]  # one test for both clicks
    with db, db.cursor() as cur:
        cur.execute("SELECT count(*) FROM notification_tests WHERE handled_at IS NULL")
        assert cur.fetchone()[0] == 0


def test_prune_keeps_pending_and_recent(db):
    n, phone = notifier(db)
    n.run_once(now())
    add_alert(db)
    phone.failing = True
    n.run_once(now())
    with db, db.cursor() as cur:
        cur.execute("INSERT INTO notifications (message_id, kind, channel, message, status, created_at) "
                    "VALUES (99, 'alert', 'ntfy', '{}', 'sent', NOW() - interval '31 days')")
    n.store.prune(now())
    with db, db.cursor() as cur:
        cur.execute("SELECT status FROM notifications ORDER BY id")
        assert [r[0] for r in cur.fetchall()] == ["pending"]
