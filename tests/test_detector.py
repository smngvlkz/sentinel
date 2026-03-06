"""Unit tests for detection_engine.detector.DetectionEngine."""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def packet():
    return {
        "timestamp": "1000.0",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": "54321",
        "dst_port": "80",
    }


class TestDetectionEngine:

    def _build_engine(self, rule_results=None, anomaly_detect=False, anomaly_score=-0.5):
        """Build a DetectionEngine with mocked sub-components."""
        mock_rules = MagicMock()
        mock_rules.evaluate.return_value = rule_results or []

        mock_anomaly = MagicMock()
        mock_anomaly.detect.return_value = anomaly_detect
        mock_anomaly.score.return_value = anomaly_score

        with patch("detection_engine.detector.RuleEngine", return_value=mock_rules), \
             patch("detection_engine.detector.AnomalyDetector", return_value=mock_anomaly):
            from detection_engine.detector import DetectionEngine
            engine = DetectionEngine()

        return engine

    def test_no_threats_on_clean_traffic(self, packet, normal_features):
        engine = self._build_engine(rule_results=[], anomaly_detect=False)
        threats = engine.detect(normal_features, packet)
        assert threats == []

    def test_rule_threats_included(self, packet, normal_features):
        engine = self._build_engine(rule_results=["SYN_FLOOD", "PORT_SCAN"])
        threats = engine.detect(normal_features, packet)
        rule_types = [t["type"] for t in threats]
        assert "SYN_FLOOD" in rule_types
        assert "PORT_SCAN" in rule_types
        for t in threats:
            assert t["source"] == "rules"
            assert t["confidence"] == 0.9

    def test_anomaly_threat_included(self, packet, normal_features):
        engine = self._build_engine(anomaly_detect=True, anomaly_score=-0.8)
        threats = engine.detect(normal_features, packet)
        anomaly_threats = [t for t in threats if t["type"] == "ANOMALY"]
        assert len(anomaly_threats) == 1
        assert anomaly_threats[0]["source"] == "ml"
        assert anomaly_threats[0]["confidence"] == pytest.approx(0.8)

    def test_combined_rules_and_anomaly(self, packet, normal_features):
        engine = self._build_engine(
            rule_results=["HIGH_FREQUENCY"],
            anomaly_detect=True,
            anomaly_score=-0.6,
        )
        threats = engine.detect(normal_features, packet)
        types = [t["type"] for t in threats]
        assert "HIGH_FREQUENCY" in types
        assert "ANOMALY" in types
        assert len(threats) == 2

    def test_anomaly_disabled_no_model(self, packet, normal_features):
        engine = self._build_engine(anomaly_detect=False)
        threats = engine.detect(normal_features, packet)
        anomaly_threats = [t for t in threats if t["type"] == "ANOMALY"]
        assert len(anomaly_threats) == 0

    def test_anomaly_confidence_capped_at_1(self, packet, normal_features):
        engine = self._build_engine(anomaly_detect=True, anomaly_score=-1.5)
        threats = engine.detect(normal_features, packet)
        anomaly_threats = [t for t in threats if t["type"] == "ANOMALY"]
        assert anomaly_threats[0]["confidence"] == 1.0
