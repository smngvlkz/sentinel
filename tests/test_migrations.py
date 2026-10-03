"""Database migrations: the runner on its own, and against a real Postgres when one is configured."""

import os
import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from common.migrations import MIGRATIONS_DIR, available, migrate

FIXTURES = Path(__file__).parent / "fixtures"
# e.g. postgresql://postgres:postgres@localhost:5432/postgres (CI sets it).
TEST_DB_URL = os.getenv("SENTINEL_TEST_DATABASE_URL")


def write(directory, files):
    for name, sql in files.items():
        (directory / name).write_text(sql)
    return directory


class FakeConn:
    """Records statements; fails on any statement containing FAIL."""

    def __init__(self, applied=()):
        self.autocommit = True
        self.applied = set(applied)
        self.statements: list[str] = []
        self.commits = self.rollbacks = 0

    def cursor(self):
        conn = self

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, sql, params=None):
                if "FAIL" in sql:
                    raise RuntimeError("bad migration")
                conn.statements.append(sql)
                if sql.startswith("INSERT INTO schema_migrations"):
                    conn.applied.add(params[0])

            def fetchall(self):
                return [(v,) for v in conn.applied]

        return Cursor()

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class TestRunner:

    def test_shipped_migrations_are_numbered_in_order(self):
        versions = [v for v, _, _ in available(MIGRATIONS_DIR)]
        assert versions[:2] == [1, 2] and versions == sorted(set(versions))

    def test_bad_names_and_duplicates_are_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="0001_name.sql"):
            available(write(tmp_path, {"1_x.sql": ""}))
        other = tmp_path / "dup"
        other.mkdir()
        with pytest.raises(ValueError, match="two migrations numbered 0003"):
            available(write(other, {"0003_a.sql": "", "0003_b.sql": ""}))

    def test_only_pending_migrations_run_in_order(self, tmp_path):
        d = write(tmp_path, {"0002_b.sql": "B;", "0001_a.sql": "A;", "0003_c.sql": "C;"})
        conn = FakeConn(applied={1})
        assert migrate(conn, d) == [2, 3]
        ran = [s for s in conn.statements if s in ("A;", "B;", "C;")]
        assert ran == ["B;", "C;"]
        assert conn.commits == 2 and conn.autocommit is True
        assert any("pg_advisory_lock" in s for s in conn.statements)
        assert any("pg_advisory_unlock" in s for s in conn.statements)

    def test_a_failed_migration_is_rolled_back_and_stops_the_rest(self, tmp_path):
        d = write(tmp_path, {"0001_a.sql": "A;", "0002_b.sql": "FAIL;", "0003_c.sql": "C;"})
        conn = FakeConn()
        with pytest.raises(RuntimeError):
            migrate(conn, d)
        assert conn.applied == {1} and conn.rollbacks == 1
        assert "C;" not in conn.statements
        assert any("pg_advisory_unlock" in s for s in conn.statements)  # lock released anyway
        assert conn.autocommit is True


@pytest.fixture
def database():
    """A fresh, empty database on the test server, dropped afterwards."""
    if not TEST_DB_URL:
        pytest.skip("set SENTINEL_TEST_DATABASE_URL to run against a real Postgres")
    import psycopg2

    name = f"sentinel_test_{uuid.uuid4().hex[:10]}"
    admin = psycopg2.connect(TEST_DB_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f"CREATE DATABASE {name}")
    url = TEST_DB_URL.rsplit("/", 1)[0] + "/" + name
    try:
        yield lambda: psycopg2.connect(url)
    finally:
        with admin.cursor() as cur:
            cur.execute(f"DROP DATABASE {name} WITH (FORCE)")
        admin.close()


def column_type(cur, table, column):
    cur.execute(
        "SELECT data_type FROM information_schema.columns WHERE table_name = %s AND column_name = %s",
        [table, column],
    )
    row = cur.fetchone()
    return row[0] if row else None


def insert_alerts(cur, n, with_names=False):
    for i in range(n):
        cur.execute(
            "INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, features) "
            "VALUES (NOW(), 'PORT_SCAN', %s, '192.168.1.10', '{\"unique_dst_ports\": 25}')",
            [f"198.51.100.{i + 1}"],
        )


class TestAgainstPostgres:

    def test_fresh_database(self, database):
        conn = database()
        assert migrate(conn) == [v for v, _, _ in available()]
        with conn.cursor() as cur:
            for table in ("alerts", "device_names", "traffic_stats", "schema_migrations"):
                cur.execute("SELECT to_regclass(%s)", [table])
                assert cur.fetchone()[0] == table
            assert column_type(cur, "alerts", "id") == "bigint"
            assert column_type(cur, "alerts", "source_name") == "text"
        assert migrate(database()) == []  # the next start: nothing to do

    def test_refuses_a_connection_mid_transaction(self, database):
        conn = database()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")  # psycopg2 opens a transaction
        with pytest.raises(ValueError, match="no transaction in progress"):
            migrate(conn)

    def test_upgrade_from_0_1_0_keeps_alerts(self, database):
        conn = database()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute((FIXTURES / "schema-0.1.0.sql").read_text())
            insert_alerts(cur, 5)
            assert column_type(cur, "alerts", "source_name") is None
        migrate(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM alerts")
            assert cur.fetchone()[0] == 5
            assert column_type(cur, "alerts", "source_name") == "text"
            cur.execute("SELECT to_regclass('device_names')")
            assert cur.fetchone()[0] == "device_names"

    def test_upgrade_from_0_4_0_keeps_alerts_and_ids(self, database):
        conn = database()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute((FIXTURES / "schema-0.4.0.sql").read_text())
            cur.execute("SELECT setval('alerts_id_seq', 65798039)")  # like the author's install
            insert_alerts(cur, 3)
            cur.execute("INSERT INTO device_names (ip, name) VALUES ('192.168.1.10', 'Office NAS')")
            cur.execute("SELECT max(id) FROM alerts")
            last = cur.fetchone()[0]
            assert column_type(cur, "alerts", "id") == "integer"
        migrate(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM alerts")
            assert cur.fetchone()[0] == 3
            cur.execute("SELECT name FROM device_names")
            assert cur.fetchone()[0] == "Office NAS"
            assert column_type(cur, "alerts", "id") == "bigint"
            insert_alerts(cur, 1)
            cur.execute("SELECT max(id) FROM alerts")
            assert cur.fetchone()[0] == last + 1  # ids carry on where they were

    def test_two_services_starting_together(self, database):
        results, errors = [], []

        def start():
            try:
                results.append(migrate(database()))
            except Exception as e:  # pragma: no cover - reported below
                errors.append(e)

        threads = [threading.Thread(target=start) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert sorted(results, key=len) == [[], [v for v, _, _ in available()]]
