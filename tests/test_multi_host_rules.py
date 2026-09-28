"""Rules built on connections and per-host windows: request floods, distributed floods, sweeps."""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.config import DEFAULTS
from detection_engine.rules import RuleEngine


def pkt(t, src, sport, dst, dport, flags="", size=60, transport="TCP"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6" if transport == "TCP" else "17", "packet_size": str(size), "flags": flags,
            "transport": transport}


@pytest.fixture
def rules():
    return RuleEngine(config=DEFAULTS)


def open_connections(tracker, count, src, dst, port, spacing, complete=True, start=0.0):
    """Open `count` TCP connections from src to dst:port; returns the features after the last packet."""
    f = None
    for i in range(count):
        t, sport = start + i * spacing, 20000 + i
        f = tracker.update(pkt(t, src, sport, dst, port, "S"))
        if complete:
            tracker.update(pkt(t + 0.001, dst, port, src, sport, "SA"))
            f = tracker.update(pkt(t + 0.002, src, sport, dst, port, "A"))
    return f


class TestRequestFlood:
    """One source opening completed connections to one service very fast: an HTTP flood."""

    def test_http_flood_detected(self, rules):
        f = open_connections(FlowTracker(), 500, "172.16.0.1", "192.168.10.50", 80, spacing=0.01)
        assert "REQUEST_FLOOD" in rules.evaluate(f)

    def test_busy_but_normal_client_is_not(self, rules):
        """CIC-IDS2017's busiest normal client peaked at 251 connections in 10s."""
        f = open_connections(FlowTracker(), 250, "192.168.10.9", "192.168.10.3", 88, spacing=0.04)
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_dns_queries_are_not_connections(self, rules):
        """Hundreds of DNS lookups a second are normal for a resolver, and they're UDP."""
        tracker = FlowTracker()
        for i in range(1000):
            f = tracker.update(pkt(i * 0.005, "192.168.10.3", 30000 + i, "8.8.8.8", 53, transport="UDP"))
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_half_open_connections_are_a_syn_flood_not_this(self, rules):
        f = open_connections(FlowTracker(), 500, "203.0.113.66", "192.168.1.10", 80, spacing=0.01, complete=False)
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_boundary(self, rules):
        base = {"conn_established": 1.0}
        assert "REQUEST_FLOOD" not in rules.evaluate({**base, **_quiet(), "service_new_conns_10s": 400})
        assert "REQUEST_FLOOD" in rules.evaluate({**base, **_quiet(), "service_new_conns_10s": 401})


class TestDistributedFlood:
    """Many internet sources converging on one host: the attack no single-source rule sees."""

    def test_many_internet_sources_detected(self, rules):
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 0.1, f"203.0.113.{i + 1}", 40000, "192.168.1.10", 443, "S"))
        assert f["responder_external_sources_60s"] == 60
        assert "DISTRIBUTED_FLOOD" in rules.evaluate(f)

    def test_many_local_sources_are_not(self, rules):
        """Every device on a big office network using the same local server is normal."""
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 0.1, f"192.168.1.{i + 20}", 40000, "192.168.1.3", 53, transport="UDP"))
        assert f["responder_external_sources_60s"] == 0
        assert "DISTRIBUTED_FLOOD" not in rules.evaluate(f)

    def test_sources_spread_over_more_than_a_minute_are_not(self, rules):
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 2.0, f"203.0.113.{i + 1}", 40000, "192.168.1.10", 443, "S"))
        assert f["responder_external_sources_60s"] <= 31
        assert "DISTRIBUTED_FLOOD" not in rules.evaluate(f)


class TestNetworkSweep:
    """One source contacting many local hosts on the same port: a worm or scanner looking for targets."""

    def test_sweep_detected(self, rules):
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(i * 0.05, "192.168.1.66", 40000 + i, f"192.168.1.{100 + i}", 445, "S"))
        assert f["initiator_same_port_local_hosts_60s"] == 29
        assert "NETWORK_SWEEP" in rules.evaluate(f)

    def test_many_internet_hosts_are_not(self, rules):
        """A DNS resolver or a browser talks to many internet hosts on one port."""
        tracker = FlowTracker()
        for i in range(1, 100):
            f = tracker.update(pkt(i * 0.05, "192.168.1.3", 40000 + i, f"198.51.100.{i}", 53, transport="UDP"))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)

    def test_different_ports_to_many_hosts_are_not(self, rules):
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(i * 0.05, "192.168.1.66", 40000 + i, f"192.168.1.{100 + i}", 1000 + i, "S"))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)

    def test_joining_connections_mid_stream_is_not(self, rules):
        """After a restart, existing connections all appear at once; they aren't new attempts."""
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(0.0, "192.168.1.5", 50000 + i, f"192.168.1.{100 + i}", 445, "PA", size=500))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)


def _quiet():
    """Features for an unremarkable packet, so only the rule under test can fire."""
    return {"syn_ratio": 0.0, "packet_rate": 1, "unanswered_syn_ports": 0, "packet_size": 60,
            "packet_has_ack": 1, "avg_packet_size": 60, "ack_ratio": 1, "total_packets": 1, "flow_duration": 1}
