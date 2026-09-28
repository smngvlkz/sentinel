"""Integration tests for the full SentinelAI detection pipeline.

Tests the path: packet -> FlowTracker -> RuleEngine -> threats
without requiring Redis, Postgres, or a trained ML model.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.rules import RuleEngine


class TestFullPipeline:

    @pytest.fixture
    def tracker(self):
        return FlowTracker()

    @pytest.fixture
    def rules(self):
        return RuleEngine()

    def test_normal_traffic_no_threats(self, tracker, rules):
        """A few normal packets should produce zero rule matches."""
        base_time = 1000.0
        for i in range(5):
            pkt = {
                "timestamp": str(base_time + i),
                "src_ip": "192.168.1.10",
                "dst_ip": "93.184.216.34",
                "protocol": "6",
                "packet_size": "512",
                "src_port": "45000",
                "dst_port": "443",
                "flags": "A",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        threats = rules.evaluate(features)
        assert threats == []

    def test_syn_flood_detected(self, tracker, rules):
        """Many rapid SYN packets should trigger SYN_FLOOD."""
        base_time = 1000.0
        for i in range(100):
            pkt = {
                "timestamp": str(base_time + i * 0.01),
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.1.1",
                "protocol": "6",
                "packet_size": "64",
                "src_port": str(30000 + i),
                "dst_port": "80",
                "flags": "S",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        threats = rules.evaluate(features)
        assert "SYN_FLOOD" in threats

    def test_new_connection_handshake_no_threats(self, tracker, rules):
        """The opening SYN of an ordinary connection must not be flagged."""
        pkt = {
            "timestamp": "1000.0",
            "src_ip": "192.168.1.10",
            "dst_ip": "93.184.216.34",
            "protocol": "6",
            "packet_size": "60",
            "src_port": "45000",
            "dst_port": "443",
            "flags": "S",
            "transport": "TCP",
        }
        features = tracker.update(pkt)
        assert rules.evaluate(features) == []

    def test_port_scan_detected(self, tracker, rules):
        """Packets to many distinct ports should trigger PORT_SCAN."""
        base_time = 1000.0
        for i in range(25):
            pkt = {
                "timestamp": str(base_time + i * 0.5),
                "src_ip": "10.0.0.50",
                "dst_ip": "192.168.1.1",
                "protocol": "6",
                "packet_size": "64",
                "src_port": "40000",
                "dst_port": str(1 + i),
                "flags": "S",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        threats = rules.evaluate(features)
        assert "PORT_SCAN" in threats

    def test_large_payload_detected(self, tracker, rules):
        """A single oversized packet should trigger LARGE_PAYLOAD."""
        pkt = {
            "timestamp": str(1000.0),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6",
            "packet_size": "15000",
            "src_port": "1234",
            "dst_port": "80",
            "flags": "",
            "transport": "TCP",
        }
        features = tracker.update(pkt)
        threats = rules.evaluate(features)
        assert "LARGE_PAYLOAD" in threats

    def test_high_frequency_detected(self, tracker, rules):
        """Extremely rapid packets should trigger HIGH_FREQUENCY."""
        base_time = 1000.0
        for i in range(300):
            pkt = {
                "timestamp": str(base_time + i * 0.0005),
                "src_ip": "10.0.0.77",
                "dst_ip": "192.168.1.1",
                "protocol": "17",
                "packet_size": "128",
                "src_port": "5555",
                "dst_port": "53",
                "flags": "",
                "transport": "UDP",
            }
            features = tracker.update(pkt)

        threats = rules.evaluate(features)
        assert "HIGH_FREQUENCY" in threats

    def test_flow_cleanup_resets_state(self, tracker, rules):
        """After cleanup, a fresh flow should start from scratch."""
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
        tracker.cleanup_stale(now=old_time + 60.0)
        assert len(tracker.flows) == 0

        # New packet creates a fresh flow
        pkt["timestamp"] = str(old_time + 61.0)
        features = tracker.update(pkt)
        assert features["total_packets"] == 1

    def test_server_replies_are_not_a_port_scan(self, tracker, rules):
        """A busy website replies to many ephemeral client ports; that's not a scan."""
        for i in range(60):
            pkt = {
                "timestamp": str(1000.0 + i * 0.05),
                "src_ip": "104.16.7.34",
                "dst_ip": "192.168.18.134",
                "protocol": "6",
                "packet_size": "1200",
                "src_port": "443",
                "dst_port": str(51000 + i),
                "flags": "PA",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        assert "PORT_SCAN" not in rules.evaluate(features)

    def test_download_ack_stream_is_not_a_burst(self, tracker, rules):
        """The client side of a fast download: thousands of small ACKs per second."""
        for i in range(3000):
            pkt = {
                "timestamp": str(1000.0 + i * 0.0003),
                "src_ip": "192.168.18.134",
                "dst_ip": "17.248.151.130",
                "protocol": "6",
                "packet_size": "66",
                "src_port": "52000",
                "dst_port": "443",
                "flags": "A",
                "transport": "TCP",
            }
            features = tracker.update(pkt)

        assert features["packet_rate"] > 1000
        assert "HIGH_FREQUENCY" not in rules.evaluate(features)

    def test_ftp_passive_mode_is_not_a_port_scan(self, tracker, rules):
        """FTP opens a data connection on a new port per file; the server answers each."""
        client, server = "192.168.10.51", "185.170.48.239"
        t = 1000.0
        for i in range(30):
            port = str(20000 + i * 137)
            tracker.update({"timestamp": str(t), "src_ip": client, "dst_ip": server, "protocol": "6",
                            "packet_size": "66", "src_port": str(40000 + i), "dst_port": port,
                            "flags": "S", "transport": "TCP"})
            tracker.update({"timestamp": str(t + 0.01), "src_ip": server, "dst_ip": client, "protocol": "6",
                            "packet_size": "66", "src_port": port, "dst_port": str(40000 + i),
                            "flags": "SA", "transport": "TCP"})
            t += 0.2
        features = tracker.update({"timestamp": str(t), "src_ip": client, "dst_ip": server, "protocol": "6",
                                   "packet_size": "66", "src_port": "40100", "dst_port": "31000",
                                   "flags": "S", "transport": "TCP"})
        assert features["unique_syn_dst_ports"] == 31
        assert features["unanswered_syn_ports"] == 1
        assert "PORT_SCAN" not in rules.evaluate(features)

    def test_merged_download_frames_are_not_oversized(self, tracker, rules):
        """Receive offload records a download as 10-21 KB frames; they carry ACK."""
        features = tracker.update({"timestamp": "1000.0", "src_ip": "8.253.104.126", "dst_ip": "192.168.10.15",
                                   "protocol": "6", "packet_size": "15008", "src_port": "80", "dst_port": "50273",
                                   "flags": "A", "transport": "TCP"})
        assert "LARGE_PAYLOAD" not in rules.evaluate(features)
