"""
Detection engine.

Combines rule-based signature matching with ML anomaly detection.
Returns a list of threat dictionaries for each packet analyzed.
"""

from __future__ import annotations

import logging

from .rules import RuleEngine
from .anomaly_model import AnomalyDetector

log = logging.getLogger(__name__)


class DetectionEngine:

    def __init__(self) -> None:
        self.rules = RuleEngine()
        self.anomaly = AnomalyDetector()

    def detect(
        self,
        features: dict[str, float],
        packet: dict[str, str],
    ) -> list[dict[str, object]]:
        threats: list[dict[str, object]] = []

        for rule_name in self.rules.evaluate(features):
            threats.append({
                "type": rule_name,
                "source": "rules",
                "confidence": 0.9,
            })

        if self.anomaly.detect(features):
            threats.append({
                "type": "ANOMALY",
                "source": "ml",
                "confidence": min(1.0, abs(self.anomaly.score(features))),
            })

        return threats
