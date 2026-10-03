"""Hard caps on the analyzer's in-memory tables, and cleanup that only looks at what expires."""

import os
import random
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from alert_service.alert_manager import AlertManager
from analysis_service.beacons import WINDOW, BeaconTracker
from analysis_service.connections import (
    CONN_CLOSED_TIMEOUT,
    CONN_IDLE_TIMEOUT,
    ConnectionTable,
    WindowCounter,
    is_local,
)
from analysis_service.feature_extractor import FlowTracker


def pkt(t, src, sport, dst, dport, flags="S", transport="TCP"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6" if transport == "TCP" else "17", "packet_size": "60", "flags": flags,
            "transport": transport}


def spoofed(i):
    return f"203.0.{i // 250 % 250}.{i % 250 + 1}"


class TestCleanupMatchesFullScan:
    """
    Cleanup now pops stale entries from the quiet end instead of scanning
    every entry. On in-order traffic it must remove exactly what the old full
    scan removed, so detection can't change.
    """

    @staticmethod
    def kept_by_full_scan(t: FlowTracker, now: float) -> dict[str, set]:
        return {
            "flows": {k for k, v in t.flows.items() if not now - v["last_seen"] > t.flow_timeout},
            "connections": {
                k for k, c in t.connections.connections.items()
                if not now - c.last_seen > (CONN_CLOSED_TIMEOUT if c.closed else CONN_IDLE_TIMEOUT)
            },
            "hosts": {ip for ip, h in t.hosts.hosts.items() if h.out_60s.total(now) or h.in_60s.total(now)},
            "services": {k for k, c in t.hosts.services.items() if c.total(now)},
            "sweeps": {k for k, c in t.hosts.sweeps.items() if c.total(now)},
            "beacons": {k for k, times in t.beacons.checkins.items() if times and times[-1] > now - WINDOW},
        }

    @staticmethod
    def kept(t: FlowTracker) -> dict[str, set]:
        return {
            "flows": set(t.flows),
            "connections": set(t.connections.connections),
            "hosts": set(t.hosts.hosts),
            "services": set(t.hosts.services),
            "sweeps": set(t.hosts.sweeps),
            "beacons": set(t.beacons.checkins),
        }

    @pytest.mark.parametrize("seed", range(5))
    def test_random_traffic(self, seed):
        rng = random.Random(seed)
        local = [f"192.168.1.{i}" for i in range(1, 30)]
        remote = [f"198.51.100.{i}" for i in range(1, 60)]
        t = FlowTracker()
        now = 1000.0
        last_cleanup = now
        removed_any = False
        for _ in range(20_000):
            # Bursts and quiet spells, so every timeout gets crossed.
            now += rng.choice([0.001, 0.01, 0.1, 1.0, 7.0, 40.0]) if rng.random() < 0.05 else 0.002
            a, b = rng.choice(local), rng.choice(local + remote + remote)
            if rng.random() < 0.5:
                a, b = b, a
            t.update(pkt(now, a, rng.randint(40000, 40100), b, rng.choice([22, 80, 443, 445, 8080]),
                         flags=rng.choice(["S", "SA", "A", "PA", "FA", "R", ""]),
                         transport=rng.choice(["TCP", "TCP", "TCP", "UDP"])))
            if now - last_cleanup > 60:
                expected = self.kept_by_full_scan(t, now)
                before = sum(map(len, self.kept(t).values()))
                t.cleanup_stale(now)
                assert self.kept(t) == expected
                removed_any |= before > sum(map(len, expected.values()))
                last_cleanup = now
        assert removed_any


class TestCaps:

    def test_flows_seen_twice_survive_a_flood_of_one_offs(self):
        t = FlowTracker(limits={"max_flows": 100})
        t.update(pkt(0.0, "198.51.100.23", 40000, "192.168.1.10", 1))
        t.update(pkt(0.1, "198.51.100.23", 40000, "192.168.1.10", 2))   # seen twice: protected
        t.update(pkt(0.2, "198.51.100.99", 40000, "192.168.1.10", 1))   # seen once
        for i in range(10_000):
            t.update(pkt(1 + i * 0.001, spoofed(i), 1000, "192.168.1.10", 80))
        assert ("198.51.100.23", "192.168.1.10") in t.flows
        assert ("198.51.100.99", "192.168.1.10") not in t.flows
        assert len(t.flows) <= 100 and t.evicted > 9_000
        assert len(t.ip_connection_counts) == len({k[0] for k in t.flows})   # counts follow evictions

    def test_connections_capped_and_closed_index_follows(self):
        t = ConnectionTable(max_connections=50)
        for i in range(500):
            t.update(pkt(i * 0.01, spoofed(i), 1000, "192.168.1.10", 80, flags="R" if i % 2 else "S"))
        assert len(t.connections) == 50
        assert t.evicted == 450
        assert set(t._closed) <= set(t.connections)

    def test_window_counts_top_out_at_the_cap(self):
        w = WindowCounter(60, cap=100)
        for i in range(1000):
            w.add(1.0, spoofed(i))
        assert w.total(1.0) == 100 and w.distinct(1.0) == 100
        assert w.total(62.0) == 0                              # still expires normally

    def test_beacon_series_capped(self):
        b = BeaconTracker(max_series=5)
        t = ConnectionTable()
        for i in range(20):
            conn, _, _ = t.update(pkt(i, "192.168.1.5", 50000 + i, f"198.51.100.{i + 1}", 443))
            b.record(conn)
        assert len(b.checkins) == 5 and b.evicted == 15

    def test_spoofed_flood_stays_within_every_cap(self):
        limits = {"max_flows": 100, "max_connections": 200, "max_hosts": 100, "max_services": 100,
                  "max_sweeps": 100, "max_window_events": 500}
        t = FlowTracker(limits=limits)
        for i in range(10_000):
            f = t.update(pkt(i * 0.001, spoofed(i), 1000 + i % 50000, "192.168.1.10", 80))
        assert len(t.flows) <= 100 and len(t.ip_connection_counts) <= 100
        assert len(t.connections.connections) <= 200
        assert len(t.hosts.hosts) <= 100 and len(t.hosts.services) <= 100
        victim = t.hosts.hosts["192.168.1.10"]                 # the busiest host stays
        assert victim.in_60s.total(10.0) == 500
        assert f["responder_external_sources_60s"] == 500     # far above the rule's 50
        assert t.evicted > 0 and t.hosts.evicted["hosts"] > 0


def test_judged_flows_capped():
    with patch("detection_engine.detector.RuleEngine", return_value=MagicMock()), \
         patch("detection_engine.detector.AnomalyDetector", return_value=MagicMock()):
        from detection_engine.detector import DetectionEngine
        engine = DetectionEngine()
    engine.max_judged = 3
    for i in range(10):
        engine._due({"src_ip": spoofed(i), "dst_ip": "192.168.1.10", "timestamp": str(i * 10.0)})
    assert len(engine._last_judged) == 3 and engine.evicted == 7
    engine.forget_idle(now=90.0 + 301)
    assert len(engine._last_judged) == 0


def test_alert_cooldowns_capped():
    with patch.object(AlertManager, "_connect"):
        m = AlertManager()
    m.max_recent = 3
    with patch.object(m, "_store"), patch.object(m, "_log"):
        for i in range(10):
            m.handle([{"type": "PORT_SCAN", "source": "rules", "confidence": 0.9}],
                     {"timestamp": str(i), "src_ip": spoofed(i), "dst_ip": "192.168.1.10"}, {})
    assert len(m._recent) == 3 and m.evicted == 7


def test_spoofed_sources_are_internet_hosts():
    """The helper above must produce internet addresses, or the flood test proves nothing."""
    assert not any(is_local(spoofed(i)) for i in range(0, 10_000, 997))


def test_gc_tuning_skips_automatic_full_collections():
    import gc
    from analysis_service.gc_tuning import FullCollector, tune_gc

    before = gc.get_threshold()
    try:
        tune_gc()
        young, middle, oldest = gc.get_threshold()
        assert (young, middle) == (700, 10)
        if sys.version_info < (3, 14):  # 3.14's incremental collector has no oldest-generation threshold
            assert oldest >= 1_000_000
        collector = FullCollector(interval=3600)
        assert collector.maybe_collect() is None          # not time yet
        collector.last -= 3601
        assert collector.maybe_collect() is not None      # the hourly safety net runs
    finally:
        gc.unfreeze()
        gc.set_threshold(*before)


class TestPressureAlert:

    @staticmethod
    def flood(t, start, n, step=0.001):
        for i in range(n):
            t.update(pkt(start + i * step, spoofed(i), 1000 + i % 50000, "192.168.1.10", 80))

    def test_quiet_while_nothing_is_dropped(self):
        from analysis_service.pressure import PressureMonitor
        from analysis_service.tables import Tables
        t = FlowTracker()
        monitor = PressureMonitor(Tables(t))
        self.flood(t, 0.0, 2000)                      # far below every cap
        assert monitor.check(60.0) is None

    def test_one_alert_when_a_table_fills_then_rate_limited(self):
        from analysis_service.pressure import PressureMonitor
        from analysis_service.tables import Tables
        t = FlowTracker(limits={"max_flows": 100, "max_connections": 100, "max_hosts": 100,
                                "max_services": 100, "max_sweeps": 100})
        monitor = PressureMonitor(Tables(t), repeat=600)
        self.flood(t, 0.0, 1000)
        threat, packet, features = monitor.check(1.0)
        assert threat["type"] == "RESOURCE_PRESSURE" and threat["group"] == "all"
        assert threat["destination_ip"] == "192.168.1.10"        # the device under the flood
        assert features["evicted_connections"] == 900   # plain table: 1,000 into 100
        assert features["evicted_flows"] == 975         # one-off flows share probation, 25 places
        assert features["tables_dropping"] == 5                    # flows, connections, hosts, services, sweeps
        assert features["busiest_peers_60s"] >= 100
        assert "evicted_judged_flows" not in features              # only tables that dropped something
        self.flood(t, 2.0, 1000)
        assert monitor.check(61.0) is None                         # still dropping, but rate-limited
        self.flood(t, 700.0, 1000)
        assert monitor.check(701.0) is not None                    # and again after the repeat window

    def test_alert_manager_keeps_one_alert_for_all_hosts(self):
        with patch.object(AlertManager, "_connect"):
            m = AlertManager()
        threat = {"type": "RESOURCE_PRESSURE", "source": "system", "confidence": 1.0, "group": "all",
                  "source_ip": "203.0.0.1", "destination_ip": "192.168.1.10"}
        other = {**threat, "source_ip": "203.0.0.2", "destination_ip": "192.168.1.11"}
        assert m._key(threat, {}) == m._key(other, {}) == ("RESOURCE_PRESSURE", "*", "*")
