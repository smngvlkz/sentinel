"""AI anomaly detection using Isolation Forest."""

import os
import logging

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml-models", "saved", "anomaly_model.pkl")
FEATURE_KEYS = [
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
    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            logger.info("Loaded anomaly model from %s", MODEL_PATH)
        else:
            logger.warning("No trained model found at %s. Anomaly detection disabled.", MODEL_PATH)

    def features_to_vector(self, features):
        return [features[k] for k in FEATURE_KEYS]

    def detect(self, features):
        """Returns True if the features look anomalous."""
        if self.model is None:
            return False
        vector = self.features_to_vector(features)
        prediction = self.model.predict([vector])
        return prediction[0] == -1

    def score(self, features):
        """Returns anomaly score (lower = more anomalous)."""
        if self.model is None:
            return 0.0
        vector = self.features_to_vector(features)
        return float(self.model.score_samples([vector])[0])
