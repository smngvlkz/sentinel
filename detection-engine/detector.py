"""Detection Engine - combines rule-based and AI anomaly detection."""

import logging

from .rules import RuleEngine
from .anomaly_model import AnomalyDetector

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self):
        self.rules = RuleEngine()
        self.anomaly = AnomalyDetector()

    def detect(self, features, packet):
        """Run all detection methods and return list of threat dicts."""
        threats = []

        # Rule-based detection
        triggered_rules = self.rules.evaluate(features)
        for rule_name in triggered_rules:
            threats.append({
                "type": rule_name,
                "source": "rules",
                "confidence": 0.9,
            })

        # AI anomaly detection
        if self.anomaly.detect(features):
            score = self.anomaly.score(features)
            threats.append({
                "type": "ANOMALY",
                "source": "ml",
                "confidence": min(1.0, abs(score)),
                "anomaly_score": score,
            })

        return threats
