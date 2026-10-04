"""Deleting old alerts, against a real Postgres (skipped unless SENTINEL_TEST_DATABASE_URL is set)."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from alert_service import retention
from alert_service.retention import Retention, delete_old, delete_over_cap
from common.migrations import migrate


@pytest.fixture
def db(database):
    """A migrated, empty database: (connection, cursor), autocommit."""
    conn = database()
    migrate(conn)
    conn.autocommit = True
    with conn.cursor() as cur:
        yield conn, cur
    conn.close()


def add_alerts(cur, n, age_days=0.0):
    cur.execute(
        """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, features)
           SELECT NOW() - make_interval(secs => %s), 'PORT_SCAN', '198.51.100.' || (i %% 250 + 1),
                  '192.168.1.10', jsonb_build_object('unique_dst_ports', 25, 'packet_rate', 79.5, 'i', i)
           FROM generate_series(1, %s) AS i""",
        [age_days * 86_400, n],
    )


def count(cur):
    cur.execute("SELECT count(*) FROM alerts")
    return cur.fetchone()[0]


def test_old_alerts_are_deleted_by_age(db):
    _, cur = db
    add_alerts(cur, 30, age_days=120)
    add_alerts(cur, 20, age_days=89)
    add_alerts(cur, 10)
    assert delete_old(cur, 90) == 30
    assert count(cur) == 30


def test_cap_keeps_exactly_the_newest(db):
    _, cur = db
    add_alerts(cur, 100)
    cur.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 40")
    newest = {r[0] for r in cur.fetchall()}
    assert delete_over_cap(cur, 40) == 60
    cur.execute("SELECT id FROM alerts")
    assert {r[0] for r in cur.fetchall()} == newest


def test_cap_is_safe_with_gaps_in_the_ids(db):
    """A big jump in ids (a restore, a skipped range) mustn't delete alerts under the limit."""
    _, cur = db
    add_alerts(cur, 30)
    cur.execute("SELECT setval('alerts_id_seq', 65000000)")
    add_alerts(cur, 30)
    assert delete_over_cap(cur, 100) == 0 and count(cur) == 60
    assert delete_over_cap(cur, 50) == 10 and count(cur) == 50


def test_nothing_to_do_under_the_limits(db):
    _, cur = db
    add_alerts(cur, 10, age_days=5)
    assert delete_old(cur, 90) == 0 and delete_over_cap(cur, 500) == 0


def test_deletes_in_batches(db, monkeypatch):
    _, cur = db
    monkeypatch.setattr(retention, "BATCH", 7)
    add_alerts(cur, 100, age_days=200)
    add_alerts(cur, 50)
    assert delete_old(cur, 90) == 100
    assert delete_over_cap(cur, 12) == 38 and count(cur) == 12


def test_background_thread_enforces_the_cap(database, monkeypatch):
    conn = database()
    migrate(conn)
    conn.autocommit = True
    monkeypatch.setattr(retention, "CAP_INTERVAL", 0.05)
    dsn = conn.get_dsn_parameters()
    dsn["password"] = os.environ["SENTINEL_TEST_DATABASE_URL"].split(":")[2].split("@")[0]
    keeper = Retention({k: dsn[k] for k in ("host", "port", "dbname", "user", "password")}, 90, 25)
    stop = keeper.start()
    try:
        with conn.cursor() as cur:
            add_alerts(cur, 100)
            deadline = time.monotonic() + 10
            while count(cur) > 25 and time.monotonic() < deadline:
                time.sleep(0.05)
            assert count(cur) == 25
    finally:
        stop.set()
    assert keeper.deleted_total == 75


def test_a_long_flood_levels_off(db):
    """
    A week-long flood, compressed: twenty waves, each as many alerts as the
    limit, with a retention pass after each (it runs every minute). The rows
    stay at the limit and the table stops growing once freed space is reused.
    """
    conn, cur = db
    keeper = Retention({}, 90, 2_000)
    sizes = []
    for _ in range(20):
        add_alerts(cur, 2_000)
        keeper.run_once(conn)
        assert count(cur) == 2_000
        cur.execute("SELECT pg_total_relation_size('alerts')")
        sizes.append(cur.fetchone()[0])
    # It settles within a few waves, then alternates as each wave reuses the
    # space the last pass freed (measured over 60 waves: 960 KB and 1,352 KB
    # throughout). Later waves must never grow past the settled peak.
    assert max(sizes[10:]) <= max(sizes[2:10]) * 1.05, sizes


def test_health_reports_database_size_and_oldest_alert(db):
    import contextlib
    import importlib.util

    if "dashboard_api_main" in sys.modules:
        api = sys.modules["dashboard_api_main"]
    else:
        spec = importlib.util.spec_from_file_location(
            "dashboard_api_main", os.path.join(os.path.dirname(__file__), "..", "dashboard-api", "main.py")
        )
        api = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = api
        spec.loader.exec_module(api)

    conn, cur = db
    add_alerts(cur, 40, age_days=3)
    add_alerts(cur, 10)

    @contextlib.contextmanager
    def test_db():
        yield conn

    from unittest.mock import patch
    with patch.object(api, "get_db", test_db):
        assert api._check_database()["alerts_estimate"] == 50  # not analyzed yet: counted exactly
        cur.execute("ANALYZE alerts")  # what autovacuum does; from then on it's Postgres's estimate
        health = api._check_database()
    assert health["ok"] is True
    assert health["size_bytes"] > 1_000_000
    assert health["alerts_estimate"] == 50
    cur.execute("SELECT min(timestamp) FROM alerts")
    assert health["oldest_alert"] == cur.fetchone()[0].isoformat()


def test_large_cleanup_fits_dockers_shared_memory(db):
    """
    Regression: after a large delete, a plain VACUUM uses parallel workers,
    which share memory through /dev/shm; Docker gives containers 64 MB of it
    (CI's Postgres and the compose file's included), and VACUUM failed with
    "could not resize shared memory segment". It takes a table this size to
    happen, so this reproduces it at full scale (about 15 s). On a server with
    more shared memory the test passes either way.
    """
    conn, cur = db
    padding = "x" * 1100  # about the size of a real alert's evidence numbers
    cur.execute(
        """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, features)
           SELECT NOW(), 'HIGH_FREQUENCY', '198.51.100.' || (i %% 250 + 1), '192.168.1.10',
                  jsonb_build_object('i', i, 'evidence', %s)
           FROM generate_series(1, 1000000) AS i""",
        [padding],
    )
    keeper = Retention({}, 90, 500_000)
    assert keeper.run_once(conn) == (0, 500_000)  # deletes, then VACUUMs; must not raise
    assert count(cur) == 500_000


def test_first_pass_checks_age_even_right_after_boot(monkeypatch):
    """time.monotonic() counts from boot; the first pass must not wait an hour after a reboot."""
    keeper = Retention({}, 90, 500_000)
    passes = []

    class Conn:
        closed = False

    monkeypatch.setattr(retention.psycopg2, "connect", lambda **_: Conn())
    monkeypatch.setattr(retention.time, "monotonic", lambda: 120.0)  # two minutes after boot
    monkeypatch.setattr(keeper, "run_once", lambda conn, check_age=True: passes.append(check_age))

    class StopAfterOne:
        def is_set(self):
            return bool(passes)

        def wait(self, _):
            pass

    keeper.loop(StopAfterOne())
    assert passes == [True]
