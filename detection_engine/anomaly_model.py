"""
Anomaly detection using Isolation Forest.

The model is optional. If no trained model exists the detector
is silently disabled and only rule-based detection runs.
"""

from __future__ import annotations

import os
import logging

import joblib

log = logging.getLogger(__name__)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "ml-models", "saved", "anomaly_model.pkl"
)

FEATURE_KEYS: list[str] = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "packet_size",
    "unique_dst_ports",
    "flow_duration",
    "total_packets",
    "total_bytes",
    "syn_ratio",
]


class AnomalyDetector:

    def __init__(self) -> None:
        self.model = None
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            log.info("loaded anomaly model from %s", MODEL_PATH)
        else:
            log.info("no trained model found, anomaly detection disabled")

    def _to_vector(self, features: dict[str, float]) -> list[float]:
        return [features[k] for k in FEATURE_KEYS]

    def detect(self, features: dict[str, float]) -> bool:
        if self.model is None:
            return False
        return bool(self.model.predict([self._to_vector(features)])[0] == -1)

    def score(self, features: dict[str, float]) -> float:
        if self.model is None:
            return 0.0
        return float(self.model.score_samples([self._to_vector(features)])[0])
