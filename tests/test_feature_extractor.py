"""Unit tests for analysis_service.feature_extractor.FlowTracker."""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker


@pytest.fixture
def tracker():
    return FlowTracker(flow_timeout=30.0)


class TestSinglePacket:

    def test_returns_expected_keys(self, tracker, sample_tcp_packet):
        features = tracker.update(sample_tcp_packet)
        expected_keys = [
            "packet_rate", "byte_rate", "avg_packet_size", "packet_size",
            "unique_dst_ports", "flow_duration", "total_packets",
            "total_bytes", "src_connection_count", "syn_count", "syn_ratio",
        ]
        for key in expected_keys:
            assert key in features

    def test_first_packet_counts(self, tracker, sample_tcp_packet):
        features = tracker.update(sample_tcp_packet)
        assert features["total_packets"] == 1
        assert features["total_bytes"] == 512
        assert features["unique_dst_ports"] == 1

    def test_packet_size_matches_input(self, tracker, sample_tcp_packet):
        features = tracker.update(sample_tcp_packet)
        assert features["packet_size"] == 512

    def test_syn_ratio_with_syn_flag(self, tracker, sample_tcp_packet):
        """A single SYN packet should have syn_ratio == 1.0."""
        features = tracker.update(sample_tcp_packet)
        assert features["syn_ratio"] == 1.0
        assert features["syn_count"] == 1

    def test_syn_ratio_without_flags(self, tracker, sample_udp_packet):
        """UDP packet with empty flags should have syn_ratio == 0."""
        features = tracker.update(sample_udp_packet)
        assert features["syn_ratio"] == 0.0
        assert features["syn_count"] == 0

    def test_src_connection_count_first_flow(self, tracker, sample_tcp_packet):
        features = tracker.update(sample_tcp_packet)
        assert features["src_connection_count"] == 1


class TestFlowAccumulation:

    def test_multiple_packets_same_flow(self, tracker):
        base_time = time.time()
        for i in range(5):
            pkt = {
                "timestamp": str(base_time + i),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "6",
                "packet_size": "100",
                "src_port": "1234",
                "dst_port": "80",
                "flags": "S" if i == 0 else "A",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        assert features["total_packets"] == 5
        assert features["total_bytes"] == 500
        assert features["unique_dst_ports"] == 1

    def test_multiple_destination_ports(self, tracker):
        base_time = time.time()
        for i in range(10):
            pkt = {
                "timestamp": str(base_time + i * 0.1),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "6",
                "packet_size": "64",
                "src_port": "1234",
                "dst_port": str(80 + i),
                "flags": "S",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        assert features["unique_dst_ports"] == 10

    def test_packet_rate_calculation(self, tracker):
        base_time = 1000.0
        for i in range(10):
            pkt = {
                "timestamp": str(base_time + i),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "6",
                "packet_size": "100",
                "src_port": "1234",
                "dst_port": "80",
                "flags": "",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        # 10 packets over 9 seconds
        assert abs(features["packet_rate"] - 10.0 / 9.0) < 0.01

    def test_syn_ratio_partial_syns(self, tracker):
        base_time = 1000.0
        for i in range(10):
            pkt = {
                "timestamp": str(base_time + i),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "6",
                "packet_size": "64",
                "src_port": "1234",
                "dst_port": "80",
                "flags": "S" if i < 3 else "A",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        assert features["syn_ratio"] == pytest.approx(0.3)

    def test_separate_flows_tracked_independently(self, tracker):
        base_time = 1000.0
        pkt_a = {
            "timestamp": str(base_time),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6",
            "packet_size": "100",
            "src_port": "1234",
            "dst_port": "80",
            "flags": "",
            "transport": "TCP",
        }
        pkt_b = {
            "timestamp": str(base_time),
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "protocol": "6",
            "packet_size": "200",
            "src_port": "5678",
            "dst_port": "443",
            "flags": "",
            "transport": "TCP",
        }
        features_a = tracker.update(pkt_a)
        features_b = tracker.update(pkt_b)

        assert features_a["total_bytes"] == 100
        assert features_b["total_bytes"] == 200
        assert len(tracker.flows) == 2


class TestStaleFlowCleanup:

    def test_stale_flows_removed(self, tracker):
        old_time = 1000.0
        pkt = {
            "timestamp": str(old_time),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6",
            "packet_size": "100",
            "src_port": "1234",
            "dst_port": "80",
            "flags": "",
            "transport": "TCP",
        }
        tracker.update(pkt)
        assert len(tracker.flows) == 1

        removed = tracker.cleanup_stale(now=old_time + 60.0)
        assert removed == 1
        assert len(tracker.flows) == 0

    def test_active_flows_not_removed(self, tracker):
        now = 1000.0
        pkt = {
            "timestamp": str(now),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6",
            "packet_size": "100",
            "src_port": "1234",
            "dst_port": "80",
            "flags": "",
            "transport": "TCP",
        }
        tracker.update(pkt)

        removed = tracker.cleanup_stale(now=now + 10.0)
        assert removed == 0
        assert len(tracker.flows) == 1

    def test_cleanup_decrements_connection_count(self, tracker):
        old_time = 1000.0
        pkt = {
            "timestamp": str(old_time),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6",
            "packet_size": "100",
            "src_port": "1234",
            "dst_port": "80",
            "flags": "",
            "transport": "TCP",
        }
        tracker.update(pkt)
        assert tracker.ip_connection_counts["10.0.0.1"] == 1

        tracker.cleanup_stale(now=old_time + 60.0)
        assert tracker.ip_connection_counts["10.0.0.1"] == 0
