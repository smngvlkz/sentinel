"""The triage service: groups, settings, and the service against a real Postgres (skipped without one)."""

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.migrations import migrate  # noqa: E402
from triage_service import config, groups  # noqa: E402
from triage_service.service import MAX_WAIT, RETRY_AFTER, Triage  # noqa: E402
from triage_service.store import Store  # noqa: E402
from triage_service.triage import TriageError, Verdict  # noqa: E402

T0 = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.timezone.utc)


def alert(i, minute, threat="ANOMALY", src="192.168.1.20", dst="198.51.100.7"):
    return {"id": i, "timestamp": T0 + dt.timedelta(minutes=minute), "threat_type": threat,
            "source_ip": src, "destination_ip": dst}


class TestGroups:
    def test_alerts_within_ten_minutes_chain(self):
        open_groups = {}
        closed, changed = groups.add(open_groups, [alert(1, 0), alert(2, 9), alert(3, 18)])
        assert closed == [] and len(changed) == 1
        g = changed[0]
        assert (g.first_alert_id, g.last_alert_id, g.alert_count) == (1, 3, 3)

    def test_a_longer_gap_starts_a_new_group(self):
        open_groups = {}
        closed, changed = groups.add(open_groups, [alert(1, 0), alert(2, 11)])
        assert [g.first_alert_id for g in closed] == [1]
        assert [g.first_alert_id for g in changed] == [2]

    def test_many_host_rules_group_on_the_side_that_stays(self):
        sweep = [alert(1, 0, "NETWORK_SWEEP", dst="192.168.1.30"), alert(2, 1, "NETWORK_SWEEP", dst="192.168.1.31")]
        flood = [alert(3, 0, "DISTRIBUTED_FLOOD", src="203.0.113.1"), alert(4, 1, "DISTRIBUTED_FLOOD", src="203.0.113.2")]
        _, changed = groups.add({}, sweep + flood)
        assert sorted(g.key for g in changed) == [
            ("DISTRIBUTED_FLOOD", "*", "198.51.100.7"), ("NETWORK_SWEEP", "192.168.1.20", "*")]

    def test_different_ends_are_different_groups(self):
        _, changed = groups.add({}, [alert(1, 0), alert(2, 1, dst="198.51.100.8"), alert(3, 2, "SYN_FLOOD")])
        assert len(changed) == 3


def test_dashboard_lists_the_same_never_harmless_rules():
    """The alert drawer explains the guard for exactly the rules triage.py guards."""
    import re

    from triage_service.triage import NEVER_HARMLESS

    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "src", "components", "AlertDrawer.tsx")
    block = re.search(r"NEVER_HARMLESS = new Set\(\[(.*?)\]\)", open(path).read(), re.S)
    assert block and set(re.findall(r'"([A-Z_]+)"', block.group(1))) == NEVER_HARMLESS


class TestConfig:
    def write(self, tmp_path, text):
        path = tmp_path / "triage.toml"
        path.write_text(text)
        return str(path)

    def test_shipped_file_loads_and_is_off(self):
        s = config.load(config.DEFAULT_PATH)
        assert s == config.Settings() and s.enabled is False

    @pytest.mark.parametrize("text, message", [
        ("[triage]\nenabled = 'yes'", "enabled"),
        ("[triage]\nurl = 'ollama:11434'", "url"),
        ("[triage]\ndigest = 'latest'", "digest"),
        ("[triage]\ntimeout_seconds = 0", "timeout"),
        ("[triage]\nmodle = 'x'", "unknown setting"),
        ("[notify]\nenabled = true", "unknown section"),
        ("[triage", "valid TOML"),
    ])
    def test_settings_that_cant_work_say_what_to_fix(self, tmp_path, text, message):
        with pytest.raises(config.ConfigError, match=message):
            config.load(self.write(tmp_path, text))


# ── Against a real Postgres ─────────────────────────────────────────────


class FakeModel:
    """Stands in for OllamaTriage: records what it was shown and answers as told."""

    def __init__(self, answer=Verdict("worth checking", "Unusual for this device."), down=False):
        self.answer, self.down, self.shown = answer, down, []

    def check_model(self):
        if self.down:
            raise TriageError("Ollama at http://ollama: connection refused")

    def triage(self, group):
        if self.down:
            raise TriageError("Ollama at http://ollama: connection refused")
        self.shown.append(group)
        return self.answer


@pytest.fixture
def db(database):
    conn = database()
    migrate(conn)
    conn.autocommit = False
    yield conn
    conn.close()


def add_alert(conn, at, threat="ANOMALY", src="192.168.1.20", dst="198.51.100.7", name=None):
    with conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, destination_port,
                                   detection_source, features, destination_name)
               VALUES (%s, %s, %s, %s, '443', 'ml', '{"packet_rate": 3.5}', %s) RETURNING id""",
            [at, threat, src, dst, name],
        )
        return cur.fetchone()[0]


def alerts_table(conn):
    with conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM alerts ORDER BY id")
        return cur.fetchall()


def triage_rows(conn):
    with conn, conn.cursor() as cur:
        cur.execute("SELECT status, verdict, reason, alert_count, last_error FROM triage ORDER BY id")
        return cur.fetchall()


def service(db, model):
    t = Triage(Store(db), model=lambda s: model)
    t.settings = config.Settings(enabled=True)
    return t


class TestService:
    def test_a_group_is_triaged_once_quiet_and_alerts_are_untouched(self, db):
        model = FakeModel()
        t = service(db, model)
        t.run_once(T0)  # starts after the alerts already there
        add_alert(db, T0, name="cdn.example")
        add_alert(db, T0 + dt.timedelta(minutes=5))
        before = alerts_table(db)

        t.run_once(T0 + dt.timedelta(minutes=6))
        assert triage_rows(db) == [("open", None, None, 2, None)] and model.shown == []

        t.run_once(T0 + dt.timedelta(minutes=16))
        assert triage_rows(db) == [("triaged", "worth checking", "Unusual for this device.", 2, None)]
        shown = model.shown[0]
        assert [a["timestamp"] for a in shown["alerts"]] == [T0.timestamp(), (T0 + dt.timedelta(minutes=5)).timestamp()]
        assert shown["alerts"][0]["features"] == {"packet_rate": 3.5}
        assert shown["alerts"][0]["destination_name"] == "cdn.example"
        assert alerts_table(db) == before  # triage never writes to alerts

    def test_alerts_from_before_the_first_start_arent_triaged(self, db):
        add_alert(db, T0)
        t = service(db, FakeModel())
        t.run_once(T0 + dt.timedelta(hours=1))
        assert triage_rows(db) == []

    def test_ollama_down_waits_and_resumes(self, db):
        model = FakeModel(down=True)
        t = service(db, model)
        t.run_once(T0)
        add_alert(db, T0)
        later = T0 + dt.timedelta(minutes=11)
        t.run_once(later)
        assert triage_rows(db) == [("waiting", None, None, 1, None)]
        assert "connection refused" in t.model_error

        model.down = False
        t.run_once(later + dt.timedelta(minutes=1))  # too soon to check Ollama again
        assert triage_rows(db)[0][0] == "waiting"
        t.run_once(later + RETRY_AFTER)
        assert triage_rows(db)[0][:2] == ("triaged", "worth checking") and t.model_error is None

    def test_a_reply_outside_the_format_is_not_triaged(self, db):
        t = service(db, FakeModel(answer=None))
        t.run_once(T0)
        add_alert(db, T0)
        t.run_once(T0 + dt.timedelta(minutes=11))
        assert triage_rows(db)[0][:2] == ("not triaged", None)

    def test_low_severity_is_skipped(self, db):
        model = FakeModel()
        t = service(db, model)
        t.run_once(T0)
        add_alert(db, T0, threat="LARGE_PAYLOAD")
        t.run_once(T0 + dt.timedelta(minutes=11))
        assert triage_rows(db)[0][0] == "skipped" and model.shown == []

    def test_newest_group_first(self, db):
        model = FakeModel()
        t = service(db, model)
        t.run_once(T0)
        add_alert(db, T0, dst="198.51.100.1")
        add_alert(db, T0 + dt.timedelta(minutes=3), dst="198.51.100.2")
        t.run_once(T0 + dt.timedelta(minutes=20))
        assert [g["destination_ip"] for g in model.shown] == ["198.51.100.2", "198.51.100.1"]

    def test_groups_waiting_too_long_are_skipped(self, db):
        t = service(db, FakeModel(down=True))
        t.run_once(T0)
        add_alert(db, T0)
        t.run_once(T0 + dt.timedelta(minutes=11))
        t.run_once(T0 + MAX_WAIT + dt.timedelta(minutes=1))
        assert triage_rows(db)[0][0] == "skipped"

    def test_off_moves_past_alerts_without_grouping(self, db):
        model = FakeModel()
        t = service(db, model)
        t.settings = config.Settings(enabled=False)
        t.run_once(T0)
        add_alert(db, T0)
        t.run_once(T0 + dt.timedelta(minutes=11))
        assert triage_rows(db) == []
        t.settings = config.Settings(enabled=True)
        t.run_once(T0 + dt.timedelta(minutes=30))
        assert triage_rows(db) == [] and model.shown == []


def test_alert_rows_carry_their_groups_opinion(db, database, monkeypatch):
    """The dashboard's alert rows show the opinion on the group each alert is in, and only that one."""
    import contextlib
    import importlib

    api = importlib.import_module("dashboard-api.main")
    t = service(db, FakeModel(answer=Verdict("likely harmless", "A download.")))
    t.run_once(T0)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    in_group = add_alert(db, now)
    sweep = [add_alert(db, now, "NETWORK_SWEEP", dst=f"192.168.1.{i}") for i in (30, 31)]
    t.run_once(now + dt.timedelta(minutes=11))
    other = add_alert(db, now + dt.timedelta(minutes=12), src="192.168.1.21")  # a different device: no group yet

    @contextlib.contextmanager
    def test_db():
        c = database()
        try:
            yield c
        finally:
            c.close()

    monkeypatch.setattr(api, "get_db", test_db)
    rows = {r["id"]: r for r in api.get_alerts(limit=50, hours=24, severity=None, status="all")["alerts"]}
    assert (rows[in_group]["triage_status"], rows[in_group]["triage_verdict"]) == ("triaged", "likely harmless")
    assert {rows[i]["triage_status"] for i in sweep} == {"triaged"}
    assert rows[other]["triage_status"] is None
    assert api.get_alert(in_group)["triage_reason"] == "A download."
