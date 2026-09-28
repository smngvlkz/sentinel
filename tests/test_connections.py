"""Tests for analysis_service.connections: two-way connections and host windows."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.connections import ConnectionTable, WindowCounter
from analysis_service.feature_extractor import FlowTracker


def pkt(t, src, sport, dst, dport, flags="", size=60, transport="TCP"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6" if transport == "TCP" else "17", "packet_size": str(size), "flags": flags,
            "transport": transport}


CLIENT, SERVER = "192.168.1.20", "93.184.216.34"


class TestConnectionTable:

    def test_handshake_both_directions(self):
        table = ConnectionTable()
        conn, new, out = table.update(pkt(0.0, CLIENT, 50000, SERVER, 443, "S"))
        assert new and out and not conn.established
        conn2, new, out = table.update(pkt(0.01, SERVER, 443, CLIENT, 50000, "SA"))
        assert conn2 is conn and not new and not out
        table.update(pkt(0.02, CLIENT, 50000, SERVER, 443, "A"))
        table.update(pkt(0.03, SERVER, 443, CLIENT, 50000, "PA", size=1400))
        assert conn.established
        assert conn.initiator == (CLIENT, "50000") and conn.responder == (SERVER, "443")
        assert (conn.packets_out, conn.packets_in) == (2, 2)
        assert conn.bytes_in == 60 + 1400

    def test_unanswered_syn_never_establishes(self):
        table = ConnectionTable()
        conn, _, _ = table.update(pkt(0.0, "198.51.100.23", 40000, SERVER, 22, "S"))
        table.update(pkt(0.01, SERVER, 22, "198.51.100.23", 40000, "RA"))
        assert not conn.established and conn.closed

    def test_joining_mid_stream_counts_as_established(self):
        table = ConnectionTable()
        conn, new, _ = table.update(pkt(0.0, SERVER, 443, CLIENT, 50000, "A", size=1400))
        assert new and conn.established

    def test_missed_syn_uses_syn_ack_to_find_the_initiator(self):
        table = ConnectionTable()
        conn, _, out = table.update(pkt(0.0, SERVER, 443, CLIENT, 50000, "SA"))
        assert conn.initiator == (CLIENT, "50000") and not out

    def test_udp(self):
        table = ConnectionTable()
        conn, new, out = table.update(pkt(0.0, CLIENT, 5353, "192.168.1.1", 53, transport="UDP"))
        table.update(pkt(0.01, "192.168.1.1", 53, CLIENT, 5353, transport="UDP"))
        assert new and out and (conn.packets_out, conn.packets_in) == (1, 1)

    def test_new_syn_after_close_is_a_new_connection(self):
        table = ConnectionTable()
        first, _, _ = table.update(pkt(0.0, CLIENT, 50000, SERVER, 80, "S"))
        table.update(pkt(1.0, CLIENT, 50000, SERVER, 80, "FA"))
        second, new, _ = table.update(pkt(2.0, CLIENT, 50000, SERVER, 80, "S"))
        assert new and second is not first

    def test_cleanup(self):
        table = ConnectionTable()
        table.update(pkt(0.0, CLIENT, 50000, SERVER, 443, "A"))
        table.update(pkt(0.0, CLIENT, 50001, SERVER, 443, "FA"))
        assert table.cleanup(10.0) == 1  # the closed one goes first
        assert table.cleanup(100.0) == 1


class TestWindowCounter:

    def test_counts_and_expiry(self):
        w = WindowCounter(10)
        for t, v in [(0, "a"), (1, "a"), (2, "b"), (9, "c")]:
            w.add(t, v)
        assert (w.total(9), w.distinct(9)) == (4, 3)
        assert (w.total(11.5), w.distinct(11.5)) == (2, 2)  # events at 0 and 1 expired
        assert (w.total(30), w.distinct(30)) == (0, 0)


class TestHostActivity:

    def test_distributed_flood_counts_distinct_sources(self):
        """Many sources converging on one host: the 'not a single machine' case."""
        tracker = FlowTracker()
        for i in range(200):
            f = tracker.update(pkt(i * 0.01, f"203.0.113.{i % 100}", 30000 + i, "192.168.1.10", 80, "S"))
        assert f["responder_distinct_sources_60s"] == 100
        assert f["responder_new_conns_10s"] == 200

    def test_one_source_hammering_one_service(self):
        """HTTP flood shape: one source opening many connections to one web server."""
        tracker = FlowTracker()
        for i in range(300):
            f = tracker.update(pkt(i * 0.02, "172.16.0.1", 20000 + i, "192.168.10.50", 80, "S"))
        assert f["service_new_conns_10s"] == 300
        assert f["initiator_distinct_hosts_60s"] == 1

    def test_sweep_counts_distinct_hosts(self):
        """One source touching many hosts: a network sweep."""
        tracker = FlowTracker()
        for i in range(1, 51):
            f = tracker.update(pkt(i * 0.1, "198.51.100.9", 40000, f"192.168.1.{i}", 445, "S"))
        assert f["initiator_distinct_hosts_60s"] == 50

    def test_windows_expire_and_cleanup_forgets_quiet_hosts(self):
        tracker = FlowTracker()
        tracker.update(pkt(0.0, CLIENT, 50000, SERVER, 443, "S"))
        late = tracker.update(pkt(70.0, CLIENT, 50000, SERVER, 443, "A"))
        assert late["initiator_new_conns_60s"] == 0
        assert tracker.hosts.cleanup(70.0) == 2  # both hosts' windows are empty
        assert tracker.hosts.hosts == {}

    def test_packets_within_a_connection_are_not_new_connections(self):
        tracker = FlowTracker()
        for i in range(100):
            f = tracker.update(pkt(i * 0.01, CLIENT, 50000, SERVER, 443, "PA" if i else "S"))
        assert f["initiator_new_conns_10s"] == 1
        assert f["conn_packets_out"] == 100 and f["from_initiator"] == 1.0


def test_flow_features_are_unchanged():
    """The rules and the trained model depend on the original features."""
    f = FlowTracker().update(pkt(0.0, CLIENT, 50000, SERVER, 443, "S"))
    for key in ("packet_rate", "byte_rate", "avg_packet_size", "packet_size", "unique_dst_ports",
                "unanswered_syn_ports", "flow_duration", "total_packets", "total_bytes", "syn_ratio"):
        assert key in f


def test_is_local():
    from analysis_service.connections import is_local
    for ip in ("192.168.1.10", "10.0.0.5", "172.16.3.4", "127.0.0.1", "169.254.1.1", "fe80::1", "fd00::1"):
        assert is_local(ip), ip
    # Documentation ranges stand in for the internet in the demo and tests.
    for ip in ("203.0.113.66", "198.51.100.23", "192.0.2.1", "8.8.8.8", "172.32.0.1", "2001:db8::1", "not-an-ip"):
        assert not is_local(ip), ip
