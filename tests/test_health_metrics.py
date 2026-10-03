"""The /health metrics: table sizes and drops, stream backlog and loss, dropped hostnames."""

import importlib.util
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.analyzer import StreamLoss, send_heartbeat
from analysis_service.feature_extractor import FlowTracker
from analysis_service.names import NameCache
from analysis_service.pressure import PressureMonitor
from analysis_service.tables import TableReport, Tables
from capture_service.capture import STATS_KEY, write_stats
from capture_service.names import NameExtractor

if "dashboard_api_main" in sys.modules:  # already loaded by test_dashboard_api.py
    api = sys.modules["dashboard_api_main"]
else:
    _spec = importlib.util.spec_from_file_location(
        "dashboard_api_main", os.path.join(os.path.dirname(__file__), "..", "dashboard-api", "main.py")
    )
    api = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = api
    _spec.loader.exec_module(api)


def pkt(t, src, dst="192.168.1.10", sport=1000, dport=80):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6", "packet_size": "60", "flags": "S", "transport": "TCP"}


class FakeRedis:
    """Just the calls /health and the heartbeat make."""

    def __init__(self, groups=None):
        self.store: dict[str, str] = {}
        self.groups = groups or []

    def ping(self):
        return True

    def xrevrange(self, *_, **__):
        return [(f"{int(time.time() * 1000)}-0", {})]

    def xinfo_groups(self, _stream):
        return self.groups

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, ex=None):
        self.store[key] = value


class TestTableReport:

    def test_every_table_with_size_and_cap(self):
        names = NameCache(max_entries=10)
        report = TableReport(Tables(FlowTracker(), names=names)).report(0.0)
        assert set(report) == {"flows", "connections", "hosts", "services", "sweeps", "beacon_series", "names"}
        assert report["connections"] == {"size": 0, "cap": 200_000, "evicted_last_minute": 0}
        assert report["names"]["cap"] == 10

    def test_drops_counted_over_the_last_minute(self):
        t = FlowTracker(limits={"max_connections": 10})
        report = TableReport(Tables(t))
        for i in range(30):
            t.update(pkt(i, f"203.0.113.{i + 1}"))
        assert report.report(0.0)["connections"]["evicted_last_minute"] == 0    # first sample: the baseline
        for i in range(30, 50):
            t.update(pkt(i, f"203.0.113.{i + 1}"))
        assert report.report(30.0)["connections"]["evicted_last_minute"] == 20
        # The baseline is the newest sample at least a minute old: still the 0 s one at 61 s...
        assert report.report(61.0)["connections"]["evicted_last_minute"] == 20
        # ...and the 30 s one at 95 s, since when nothing was dropped.
        assert report.report(95.0)["connections"]["evicted_last_minute"] == 0

    def test_name_cache_drops_are_not_pressure(self):
        names = NameCache(max_entries=2)
        tables = Tables(FlowTracker(), names=names)
        monitor = PressureMonitor(tables)
        for i in range(10):
            names.observe({"name_bindings": json.dumps([[f"1.2.3.{i}", f"h{i}.example"]])}, now=float(i))
        assert names.evicted == 8
        assert monitor.check(60.0) is None


class TestStreamLoss:

    @staticmethod
    def redis_with(entries_read):
        return FakeRedis([{"name": "analyzers", "entries-read": entries_read, "lag": 0, "pending": 0}])

    def test_nothing_lost_when_everything_was_processed(self):
        loss = StreamLoss(self.redis_with(1000))
        assert loss.since_start(self.redis_with(1500), processed=500) == 0

    def test_entries_trimmed_before_reading_count_as_lost(self):
        # Redis counts trimmed, never-read entries as read; only 300 were processed.
        loss = StreamLoss(self.redis_with(1000))
        assert loss.since_start(self.redis_with(1500), processed=300) == 200

    def test_never_negative(self):
        loss = StreamLoss(self.redis_with(1000))
        assert loss.since_start(self.redis_with(10), processed=0) == 0           # Redis restarted from an old save

    def test_group_missing(self):
        assert StreamLoss(FakeRedis([])).start == 0


class TestHealth:

    def health(self, r):
        with patch.object(api, "get_redis", return_value=r), \
             patch.object(api, "_check_database", return_value={"ok": True}):
            return api.health()

    def test_metrics_from_heartbeat_redis_and_capture(self):
        r = FakeRedis([{"name": "analyzers", "entries-read": 900, "lag": 42, "pending": 3}])
        tables = {"flows": {"size": 12, "cap": 50_000, "evicted_last_minute": 0}}
        send_heartbeat(r, started_at=0.0, processed=900, model_loaded=True, tables=tables, lost_unread=7)
        names = NameExtractor()
        names.drops.record("bad name", "1.2.3.4")
        write_stats(r, names)

        services = self.health(r)["services"]
        assert services["analyzer"]["lag"] == 42 and services["analyzer"]["pending"] == 3
        assert services["analyzer"]["packets_lost_unread"] == 7
        assert services["analyzer"]["tables"] == tables
        assert services["capture"]["names_dropped_total"] == 1

    def test_analyzer_down(self):
        services = self.health(FakeRedis())["services"]
        assert services["analyzer"] == {"running": False}
        assert "names_dropped_total" not in services["capture"]    # names off: capture writes no stats

    def test_redis_down(self):
        r = MagicMock()
        r.ping.side_effect = api.redis.exceptions.ConnectionError("down")
        services = self.health(r)["services"]
        assert services["redis"]["ok"] is False and services["analyzer"] == {"running": False}


def test_capture_counts_dropped_names_in_total():
    names = NameExtractor()
    for _ in range(3):
        names.drops.record("bad name", "1.2.3.4")
    names.drops.maybe_log(0.0)
    names.drops.maybe_log(61.0)                                    # logs and resets the per-minute count
    assert names.drops.count == 0 and names.drops.total == 3
    r = FakeRedis()
    write_stats(r, names)
    assert json.loads(r.store[STATS_KEY])["names_dropped_total"] == 3
