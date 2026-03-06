"""Unit tests for detection_engine.rules.RuleEngine."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection_engine.rules import RuleEngine


@pytest.fixture
def engine():
    return RuleEngine()


class TestSynFloodRule:

    def test_triggers_on_high_syn_ratio_and_rate(self, engine, syn_flood_features):
        result = engine.evaluate(syn_flood_features)
        assert "SYN_FLOOD" in result

    def test_no_trigger_low_syn_ratio(self, engine):
        features = {
            "syn_ratio": 0.5,
            "packet_rate": 100,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_no_trigger_low_packet_rate(self, engine):
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 10,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_boundary_syn_ratio_exactly_0_8(self, engine):
        """syn_ratio must be strictly greater than 0.8."""
        features = {
            "syn_ratio": 0.8,
            "packet_rate": 100,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" not in result

    def test_boundary_packet_rate_exactly_50(self, engine):
        """packet_rate must be strictly greater than 50."""
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 50,
            "unique_dst_ports": 1,
            "packet_size": 64,
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
        """unique_dst_ports must be strictly greater than 20."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 5,
            "unique_dst_ports": 20,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "PORT_SCAN" not in result

    def test_21_ports_triggers(self, engine):
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 5,
            "unique_dst_ports": 21,
            "packet_size": 64,
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
            "unique_dst_ports": 1,
            "packet_size": 10000,
        }
        result = engine.evaluate(features)
        assert "LARGE_PAYLOAD" not in result

    def test_10001_triggers(self, engine):
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 1,
            "unique_dst_ports": 1,
            "packet_size": 10001,
        }
        result = engine.evaluate(features)
        assert "LARGE_PAYLOAD" in result


class TestHighFrequencyRule:

    def test_triggers_on_high_rate(self, engine, high_frequency_features):
        result = engine.evaluate(high_frequency_features)
        assert "HIGH_FREQUENCY" in result

    def test_no_trigger_normal_rate(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert "HIGH_FREQUENCY" not in result

    def test_boundary_exactly_200(self, engine):
        """packet_rate must be strictly greater than 200."""
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 200,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "HIGH_FREQUENCY" not in result

    def test_201_triggers(self, engine):
        features = {
            "syn_ratio": 0.0,
            "packet_rate": 201,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "HIGH_FREQUENCY" in result


class TestNormalTraffic:

    def test_no_rules_triggered(self, engine, normal_features):
        result = engine.evaluate(normal_features)
        assert result == []

    def test_multiple_rules_can_trigger(self, engine):
        """SYN_FLOOD + HIGH_FREQUENCY can fire together."""
        features = {
            "syn_ratio": 0.95,
            "packet_rate": 300,
            "unique_dst_ports": 1,
            "packet_size": 64,
        }
        result = engine.evaluate(features)
        assert "SYN_FLOOD" in result
        assert "HIGH_FREQUENCY" in result
