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
                "timestamp": str(base_time + i * 0.001),
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
