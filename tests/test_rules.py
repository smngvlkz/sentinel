"""Unit tests for detection_engine.rules.RuleEngine."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection_engine.config import DEFAULTS
from detection_engine.rules import RuleEngine

MIN_RATE_PACKETS = DEFAULTS["rate_evidence"]["min_packets"]
MIN_RATE_DURATION = DEFAULTS["rate_evidence"]["min_duration_seconds"]


@pytest.fixture
def engine():
    return RuleEngine(config=DEFAULTS)


class TestSynFloodRule:

    def test_triggers_on_high_syn_ratio_and_rate(self, engine, syn_flood_features):
        result = engine.evaluate(syn_flood_features)
        assert "SYN_FLOOD" in result

    def test_no_trigger_low_syn_ratio(self, engine):
        features = {
            "syn_ratio": 0.5,
            "packet_rate": 100,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_no_trigger_low_packet_rate(self, engine):
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 10,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_boundary_syn_ratio_exactly_0_8(self, engine):
        """syn_ratio must be strictly greater than 0.8."""
        features = {
            "syn_ratio": 0.8,
            "packet_rate": 100,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_boundary_packet_rate_exactly_50(self, engine):
        """packet_rate must be strictly greater than 50."""
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 50,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result


class TestPortScanRule:

    def test_triggers_on_many_ports(self, engine, port_scan_features):
        result = engine.evaluate(port_scan_features)
        assert "PORT_SCAN" in result

    def test_no_trigger_few_ports(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert "PORT_SCAN" not in result

    def test_boundary_exactly_20_ports(self, engine):
        """unanswered_syn_ports must be strictly greater than 20."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 5,
            "unanswered_syn_ports": 20,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "PORT_SCAN" not in result

    def test_21_ports_triggers(self, engine):
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 5,
            "unanswered_syn_ports": 21,
            "packet_size": 64,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "PORT_SCAN" in result


class TestLargePayloadRule:

    def test_triggers_on_large_packet(self, engine, large_payload_features):
        result = engine.evaluate(large_payload_features)
        assert "LARGE_PAYLOAD" in result

    def test_no_trigger_normal_size(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert "LARGE_PAYLOAD" not in result

    def test_boundary_exactly_10000(self, engine):
        """packet_size must be strictly greater than 10000."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 1,
            "unanswered_syn_ports": 1,
            "packet_size": 10000,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "LARGE_PAYLOAD" not in result

    def test_10001_triggers(self, engine):
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 1,
            "unanswered_syn_ports": 1,
            "packet_size": 10001,
            "packet_has_ack": 0,
        }
        result = engine.evaluate(features)
        assert "LARGE_PAYLOAD" in result


class TestHighFrequencyRule:

    @staticmethod
    def flood(**overrides):
        """A UDP-style flood: fast, small packets, no TCP ACKs."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 1500,
            "avg_packet_size": 64,
            "ack_ratio": 0.0,
            "unanswered_syn_ports": 0,
            "packet_size": 64,
            "packet_has_ack": 0,
            "total_packets": 1500,
            "flow_duration": 1.0,
        }
        features.update(overrides)
        return features

    def test_triggers_on_high_rate(self, engine, high_frequency_features):
        result = engine.evaluate(high_frequency_features)
        assert "HIGH_FREQUENCY" in result

    def test_no_trigger_normal_rate(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert "HIGH_FREQUENCY" not in result

    def test_boundary_exactly_1000(self, engine):
        """packet_rate must be strictly greater than 1000."""
        assert "HIGH_FREQUENCY" not in engine.evaluate(self.flood(packet_rate=1000))

    def test_1001_triggers(self, engine):
        assert "HIGH_FREQUENCY" in engine.evaluate(self.flood(packet_rate=1001))

    def test_download_with_large_packets_ignored(self, engine):
        """A fast download: full-size packets, so not a flood."""
        features = self.flood(avg_packet_size=1400, packet_size=1500, ack_ratio=1.0)
        assert "HIGH_FREQUENCY" not in engine.evaluate(features)

    def test_download_ack_stream_ignored(self, engine):
        """The client side of a download: small but almost all TCP ACKs."""
        assert "HIGH_FREQUENCY" not in engine.evaluate(self.flood(ack_ratio=0.98))

    def test_boundary_avg_packet_size_300(self, engine):
        """avg_packet_size must be strictly under 300 bytes."""
        assert "HIGH_FREQUENCY" not in engine.evaluate(self.flood(avg_packet_size=300))


class TestNormalTraffic:

    def test_no_rules_triggered(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert result == []

    def test_multiple_rules_can_trigger(self, engine):
        """SYN_FLOOD + HIGH_FREQUENCY can fire together."""
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 1500,
            "avg_packet_size": 60,
            "ack_ratio": 0.0,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
            "total_packets": 1500,
            "flow_duration": 1.0,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" in result
        assert "HIGH_FREQUENCY" in result


class TestRateEvidence:
    """Rate-based rules must not fire on flows too young to have a real rate."""

    def test_first_syn_of_new_connection_is_clean(self, engine):
        """One SYN reads as 1000 pps over the 1ms duration floor."""
        features = {
            "syn_ratio": 1.0,
            "packet_rate": 1000.0,
            "unanswered_syn_ports": 1,
            "packet_size": 60,
            "packet_has_ack": 0,
            "total_packets": 1,
            "flow_duration": 0.001,
        }
        assert engine.evaluate(features) == []

    def test_too_few_packets(self, engine):
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 300,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
            "total_packets": MIN_RATE_PACKETS - 1,
            "flow_duration": 1.0,
        }
        assert engine.evaluate(features) == []

    def test_too_short_duration(self, engine):
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 300,
            "unanswered_syn_ports": 1,
            "packet_size": 64,
            "packet_has_ack": 0,
            "total_packets": 50,
            "flow_duration": MIN_RATE_DURATION / 2,
        }
        assert engine.evaluate(features) == []

    def test_non_rate_rules_fire_immediately(self, engine):
        """LARGE_PAYLOAD is per-packet and needs no flow history."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 1000.0,
            "unanswered_syn_ports": 1,
            "packet_size": 15000,
            "packet_has_ack": 0,
            "total_packets": 1,
            "flow_duration": 0.001,
        }
        assert engine.evaluate(features) == ["LARGE_PAYLOAD"]
