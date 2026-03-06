"""Unit tests for detection_engine.anomaly_model.AnomalyDetector."""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection_engine.anomaly_model import AnomalyDetector, FEATURE_KEYS


@pytest.fixture
def features():
    return {
        "packet_rate": 10.0,
        "byte_rate": 5120.0,
        "avg_packet_size": 512.0,
        "packet_size": 512,
        "unique_dst_ports": 2,
        "flow_duration": 5.0,
        "total_packets": 50,
        "total_bytes": 25600,
        "syn_ratio": 0.02,
    }


class TestNoModelFile:

    @patch("detection_engine.anomaly_model.os.path.exists", return_value=False)
    def test_model_is_none_when_file_missing(self, mock_exists):
        detector = AnomalyDetector()
        assert detector.model is None

    @patch("detection_engine.anomaly_model.os.path.exists", return_value=False)
    def test_detect_returns_false_without_model(self, mock_exists, features):
        detector = AnomalyDetector()
        assert detector.detect(features) is False

    @patch("detection_engine.anomaly_model.os.path.exists", return_value=False)
    def test_score_returns_zero_without_model(self, mock_exists, features):
        detector = AnomalyDetector()
        assert detector.score(features) == 0.0


class TestWithMockModel:

    def _make_detector_with_mock(self, predict_value, score_value=-0.5):
        mock_model = MagicMock()
        mock_model.predict.return_value = [predict_value]
        mock_model.score_samples.return_value = [score_value]

        with patch("detection_engine.anomaly_model.os.path.exists", return_value=True), \
             patch("detection_engine.anomaly_model.joblib.load", return_value=mock_model):
            detector = AnomalyDetector()

        return detector

    def test_detect_returns_true_for_anomaly(self, features):
        detector = self._make_detector_with_mock(predict_value=-1)
        assert detector.detect(features) is True

    def test_detect_returns_false_for_normal(self, features):
        detector = self._make_detector_with_mock(predict_value=1)
        assert detector.detect(features) is False

    def test_score_returns_model_score(self, features):
        detector = self._make_detector_with_mock(predict_value=-1, score_value=-0.75)
        score = detector.score(features)
        assert score == pytest.approx(-0.75)

    def test_to_vector_uses_correct_keys(self, features):
        detector = self._make_detector_with_mock(predict_value=1)
        vec = detector._to_vector(features)
        expected = [features[k] for k in FEATURE_KEYS]
        assert vec == expected
