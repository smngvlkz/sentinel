"""The dashboard password, end to end through the API, against a real Postgres (CI runs these)."""

import contextlib
import importlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

api = importlib.import_module("dashboard-api.main")
auth = importlib.import_module("dashboard-api.auth")
set_password = importlib.import_module("dashboard-api.set_password")

from common.migrations import migrate  # noqa: E402

PASSWORD = "correct horse battery"
JSON = {"Content-Type": "application/json"}


@pytest.fixture
def app(database, monkeypatch):
    """A TestClient factory on a migrated, empty database, plus a cursor to inspect it."""
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

    monkeypatch.setattr(api, "get_db", test_db)
    monkeypatch.delenv("DASHBOARD_BIND", raising=False)
    with conn.cursor() as cur:
        yield (lambda: TestClient(api.app)), cur, conn
    conn.close()


def post(client, path, body):
    return client.post(path, json=body, headers=JSON)


def set_up(client):
    r = post(client, "/auth/setup", {"password": PASSWORD})
    assert r.status_code == 200, r.text
    return client


class TestBeforeAPasswordIsSet:

    def test_dashboard_is_open_as_before(self, app):
        new_client, _, _ = app
        c = new_client()
        assert c.get("/alerts").status_code == 200
        assert c.get("/auth/status").json() == {"password_set": False, "logged_in": False, "setup_allowed": True}

    def test_first_run_setup_logs_this_browser_in(self, app):
        new_client, _, _ = app
        c = set_up(new_client())
        assert c.get("/auth/status").json() == {"password_set": True, "logged_in": True, "setup_allowed": False}
        assert c.get("/alerts").status_code == 200

    def test_setup_only_once(self, app):
        new_client, _, _ = app
        set_up(new_client())
        r = post(new_client(), "/auth/setup", {"password": "someone else's"})
        assert r.status_code == 409

    def test_setup_refused_once_reachable_from_other_devices(self, app, monkeypatch):
        """Nobody else on the network may claim the password first; it's make password then."""
        new_client, _, _ = app
        monkeypatch.setenv("DASHBOARD_BIND", "0.0.0.0")
        c = new_client()
        assert c.get("/auth/status").json()["setup_allowed"] is False
        r = post(c, "/auth/setup", {"password": PASSWORD})
        assert r.status_code == 403 and "make password" in r.json()["detail"]

    def test_short_password_refused(self, app):
        new_client, _, _ = app
        r = post(new_client(), "/auth/setup", {"password": "short"})
        assert r.status_code == 422 and "8 characters" in r.json()["detail"]


class TestOnceAPasswordIsSet:

    @pytest.mark.parametrize("method,path,body", [
        ("get", "/alerts", None), ("get", "/stats", None), ("get", "/health", None), ("get", "/devices", None),
        ("get", "/top-ips", None), ("get", "/alerts/summary", None), ("get", "/traffic/live", None),
        ("post", "/devices/name", {"ip": "192.168.1.10", "name": "x"}), ("post", "/alerts/review", {"ids": [1]}),
        ("post", "/auth/logout", {}), ("post", "/auth/password", {"current": PASSWORD, "new": "another one"}),
    ])
    def test_every_endpoint_refuses_without_a_login(self, app, method, path, body):
        new_client, _, _ = app
        set_up(new_client())
        stranger = new_client()
        r = stranger.get(path) if method == "get" else post(stranger, path, body)
        assert r.status_code == 401, (path, r.status_code)

    def test_only_the_login_screens_needs_are_public(self, app):
        new_client, _, _ = app
        set_up(new_client())
        stranger = new_client()
        assert stranger.get("/auth/status").json() == {"password_set": True, "logged_in": False, "setup_allowed": False}
        assert post(stranger, "/auth/login", {"password": "wrong password"}).status_code == 401

    def test_login_and_logout(self, app):
        new_client, _, _ = app
        set_up(new_client())
        c = new_client()
        assert post(c, "/auth/login", {"password": "wrong password"}).json()["detail"] == "Wrong password."
        assert c.get("/alerts").status_code == 401
        assert post(c, "/auth/login", {"password": PASSWORD}).status_code == 200
        assert c.get("/alerts").status_code == 200
        assert post(c, "/auth/logout", {}).status_code == 200
        assert c.get("/alerts").status_code == 401

    def test_logout_ends_the_session_on_the_server_too(self, app):
        """A copied cookie stops working after logout, not just the browser's copy."""
        new_client, _, _ = app
        c = set_up(new_client())
        token = c.cookies.get(auth.COOKIE)
        post(c, "/auth/logout", {})
        thief = new_client()
        thief.cookies.set(auth.COOKIE, token)
        assert thief.get("/alerts").status_code == 401

    def test_sessions_expire(self, app):
        new_client, cur, _ = app
        c = set_up(new_client())
        cur.execute("UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second'")
        assert c.get("/alerts").status_code == 401
        assert c.get("/auth/status").json()["logged_in"] is False

    def test_cookie_is_httponly_strict_and_long_lived(self, app):
        new_client, _, _ = app
        r = post(new_client(), "/auth/setup", {"password": PASSWORD})
        cookie = r.headers["set-cookie"].lower()
        assert f"{auth.COOKIE}=" in cookie
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
        assert f"max-age={auth.SESSION_SECONDS}" in cookie

    def test_only_hashes_are_stored(self, app):
        new_client, cur, _ = app
        c = set_up(new_client())
        cur.execute("SELECT password_hash FROM admin_password")
        stored = cur.fetchone()[0]
        assert stored.startswith("$argon2id$") and PASSWORD not in stored
        cur.execute("SELECT token_hash FROM sessions")
        assert cur.fetchone()[0] == auth.token_hash(c.cookies.get(auth.COOKIE)) != c.cookies.get(auth.COOKIE)

    def test_login_from_another_site_refused(self, app):
        new_client, _, _ = app
        set_up(new_client())
        r = new_client().post("/auth/login", json={"password": PASSWORD},
                              headers={**JSON, "Origin": "https://evil.example"})
        assert r.status_code == 403


class TestLockout:

    def test_locks_after_repeated_wrong_passwords(self, app):
        new_client, _, _ = app
        set_up(new_client())
        c = new_client()
        for _ in range(auth.FREE_ATTEMPTS - 1):
            assert post(c, "/auth/login", {"password": "wrong password"}).status_code == 401
        r = post(c, "/auth/login", {"password": "wrong password"})
        assert r.status_code == 429 and r.headers["retry-after"] == str(auth.FIRST_LOCK_SECONDS)
        # While locked, even the right password is refused, without being checked.
        r = post(c, "/auth/login", {"password": PASSWORD})
        assert r.status_code == 429 and "Try again in 1 minute" in r.json()["detail"]

    def test_lock_ends_and_a_right_password_resets_the_count(self, app):
        new_client, cur, _ = app
        set_up(new_client())
        c = new_client()
        for _ in range(auth.FREE_ATTEMPTS):
            post(c, "/auth/login", {"password": "wrong password"})
        cur.execute("UPDATE login_lockout SET locked_until = NOW() - INTERVAL '1 second'")
        assert post(c, "/auth/login", {"password": PASSWORD}).status_code == 200
        cur.execute("SELECT count(*) FROM login_lockout")
        assert cur.fetchone()[0] == 0

    def test_lock_doubles_up_to_fifteen_minutes(self):
        assert [auth.lock_seconds(n) for n in range(4, 12)] == [0, 60, 120, 240, 480, 900, 900, 900]

    def test_wrong_current_password_counts_too(self, app):
        """Otherwise changing the password would be a way round the lockout."""
        new_client, _, _ = app
        c = set_up(new_client())
        for _ in range(auth.FREE_ATTEMPTS - 1):
            assert post(c, "/auth/password", {"current": "wrong password", "new": "new password!"}).status_code == 401
        assert post(c, "/auth/password", {"current": "wrong password", "new": "new password!"}).status_code == 429


class TestChangeAndReset:

    def test_change_needs_the_current_password(self, app):
        new_client, _, _ = app
        c = set_up(new_client())
        r = post(c, "/auth/password", {"current": "not it at all", "new": "new password!"})
        assert r.status_code == 401 and "current password" in r.json()["detail"]

    def test_change_logs_out_other_sessions_but_not_this_one(self, app):
        new_client, _, _ = app
        me = set_up(new_client())
        phone = new_client()
        post(phone, "/auth/login", {"password": PASSWORD})
        assert phone.get("/alerts").status_code == 200
        assert post(me, "/auth/password", {"current": PASSWORD, "new": "new password!"}).status_code == 200
        assert me.get("/alerts").status_code == 200
        assert phone.get("/alerts").status_code == 401
        assert post(new_client(), "/auth/login", {"password": PASSWORD}).status_code == 401
        assert post(new_client(), "/auth/login", {"password": "new password!"}).status_code == 200

    def test_make_password_resets_everything_but_the_data(self, app):
        new_client, cur, conn = app
        c = set_up(new_client())
        cur.execute("INSERT INTO alerts (timestamp, threat_type) VALUES (NOW(), 'PORT_SCAN')")
        cur.execute("INSERT INTO device_names (ip, name) VALUES ('192.168.1.10', 'Office NAS')")
        stranger = new_client()
        for _ in range(auth.FREE_ATTEMPTS):
            post(stranger, "/auth/login", {"password": "wrong password"})
        assert post(new_client(), "/auth/login", {"password": PASSWORD}).status_code == 429  # locked out

        set_password.reset(conn, "a brand new one")

        assert c.get("/alerts").status_code == 401  # every session logged out
        assert post(new_client(), "/auth/login", {"password": PASSWORD}).status_code == 401  # old one gone, not locked
        fresh = new_client()
        assert post(fresh, "/auth/login", {"password": "a brand new one"}).status_code == 200
        assert len(fresh.get("/alerts").json()["alerts"]) == 1
        assert fresh.get("/devices").json()["devices"][0]["name"] == "Office NAS"


class TestOpeningToOtherDevices:
    """DASHBOARD_BIND beyond this machine needs a password: the API won't start without one."""

    def test_refuses_to_start_without_a_password(self, app, monkeypatch):
        from fastapi.testclient import TestClient

        monkeypatch.setenv("DASHBOARD_BIND", "0.0.0.0")
        with pytest.raises(RuntimeError, match="make password"):
            with TestClient(api.app):  # runs startup, as uvicorn does
                pass

    def test_starts_once_a_password_is_set(self, app, monkeypatch):
        from fastapi.testclient import TestClient

        new_client, _, _ = app
        set_up(new_client())
        monkeypatch.setenv("DASHBOARD_BIND", "0.0.0.0")
        with TestClient(api.app) as c:
            assert c.get("/alerts").status_code == 401
            assert post(c, "/auth/login", {"password": PASSWORD}).status_code == 200
            assert c.get("/alerts").status_code == 200

    @pytest.mark.parametrize("bind", ["127.0.0.1", "localhost", "::1", None])
    def test_starts_without_a_password_on_this_machine_only(self, app, monkeypatch, bind):
        from fastapi.testclient import TestClient

        if bind:
            monkeypatch.setenv("DASHBOARD_BIND", bind)
        with TestClient(api.app) as c:
            assert c.get("/alerts").status_code == 200

    def test_a_password_removed_while_running_shuts_everything(self, app, monkeypatch):
        new_client, cur, _ = app
        c = set_up(new_client())
        monkeypatch.setenv("DASHBOARD_BIND", "0.0.0.0")
        cur.execute("DELETE FROM admin_password")
        r = c.get("/alerts")
        assert r.status_code == 503 and "make password" in r.json()["detail"]
        assert new_client().get("/devices").status_code == 503

    def test_only_the_dashboards_port_follows_the_setting(self):
        """The API, Postgres and Redis stay on this machine whatever DASHBOARD_BIND says."""
        path = os.path.join(os.path.dirname(__file__), "..", "docker", "docker-compose.yml")
        ports = [line.strip() for line in open(path) if line.strip().startswith('- "') and ":" in line]
        assert '- "${DASHBOARD_BIND:-127.0.0.1}:${DASHBOARD_UI_PORT:-3001}:3000"' in ports
        others = [p for p in ports if "DASHBOARD_UI_PORT" not in p]
        assert len(others) == 3 and all(p.startswith('- "127.0.0.1:') for p in others), others


def test_starts_while_the_database_is_down(monkeypatch):
    """So /health can say so; every other request is refused until it's back."""
    import psycopg2
    from fastapi.testclient import TestClient

    @contextlib.contextmanager
    def down():
        raise psycopg2.OperationalError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(api, "get_db", down)
    monkeypatch.setenv("DASHBOARD_BIND", "0.0.0.0")
    with TestClient(api.app) as c:
        assert c.get("/alerts").status_code == 503


def test_database_down_refuses_everything_but_health(monkeypatch):
    """Without the database a login can't be checked: refuse, except /health, which reports the outage."""
    import psycopg2
    from fastapi.testclient import TestClient

    @contextlib.contextmanager
    def down():
        raise psycopg2.OperationalError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(api, "get_db", down)
    monkeypatch.setattr(api, "_check_redis_and_pipeline", lambda: {"redis": {"ok": False}})
    c = TestClient(api.app)
    assert c.get("/alerts").status_code == 503
    assert c.get("/health").json()["services"]["database"]["ok"] is False
