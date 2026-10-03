"""
Detection engine.

Combines rule-based signature matching with ML anomaly detection.
Returns a list of threat dictionaries for each packet analyzed.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from .config import has_rate_evidence, load_config
from .rules import RuleEngine
from .anomaly_model import AnomalyDetector

log = logging.getLogger(__name__)

# Rules judged on a whole connection rather than a one-way flow. Their alerts
# name the connection's initiator as the source, whichever direction the
# triggering packet went.
CONNECTION_RULES = {"REQUEST_FLOOD", "DISTRIBUTED_FLOOD", "NETWORK_SWEEP", "BEACONING"}

# How repeat alerts are grouped: one distributed-flood alert per victim, not
# one per attacking host; one sweep alert per scanner, not one per target.
ALERT_GROUP = {"DISTRIBUTED_FLOOD": "destination", "NETWORK_SWEEP": "source"}


class DetectionEngine:

    def __init__(self) -> None:
        self.config = load_config()
        self.rules = RuleEngine(self.config)
        self.anomaly = AnomalyDetector()
        self.judge_interval = float(self.config["anomaly"]["judge_interval_seconds"])
        # When the model last judged each (src, dst) flow, in packet time.
        # In order of last judgement, oldest first, at most max_judged_flows.
        self._last_judged: OrderedDict[tuple[str, str], float] = OrderedDict()
        self.max_judged = max(1, int(self.config["limits"]["max_judged_flows"]))
        self.evicted = 0

    def detect(
        self,
        features: dict[str, float],
        packet: dict[str, str],
    ) -> list[dict[str, object]]:
        threats: list[dict[str, object]] = []

        for rule_name in self.rules.evaluate(features):
            threat: dict[str, object] = {
                "type": rule_name,
                "source": "rules",
                "confidence": 0.9,
            }
            if rule_name in CONNECTION_RULES:
                threat.update(_oriented(packet, features))
            if rule_name in ALERT_GROUP:
                threat["group"] = ALERT_GROUP[rule_name]
            if rule_name == "BEACONING":
                # An ongoing condition: repeat the alert hourly, not every minute.
                threat["cooldown"] = float(self.config["beaconing"]["repeat_alert_seconds"])
            threats.append(threat)

        # The model judges a flow by its rates, which are meaningless for a
        # flow only a few packets or milliseconds old, and at most once per
        # judge interval so a busy flow doesn't get a chance to trip it on
        # every packet. Training samples flows the same way
        # (see ml-models/train_model.py).
        if has_rate_evidence(features, self.config) and self._due(packet) and self.anomaly.detect(features):
            threats.append({
                "type": "ANOMALY",
                "source": "ml",
                "confidence": min(1.0, abs(self.anomaly.score(features))),
            })

        return threats

    @property
    def judged_flows(self) -> int:
        return len(self._last_judged)

    def _due(self, packet: dict[str, str]) -> bool:
        if self.judge_interval <= 0:
            return True
        flow = (packet.get("src_ip", ""), packet.get("dst_ip", ""))
        now = float(packet.get("timestamp", 0))
        last = self._last_judged.get(flow)
        if last is not None and now - last < self.judge_interval:
            return False
        self._last_judged[flow] = now
        self._last_judged.move_to_end(flow)
        while len(self._last_judged) > self.max_judged:
            self._last_judged.popitem(last=False)
            self.evicted += 1
        return True

    def forget_idle(self, now: float, idle_seconds: float = 300) -> None:
        """Drop judging state for flows not judged recently, so it stays small."""
        while self._last_judged and now - next(iter(self._last_judged.values())) > idle_seconds:
            self._last_judged.popitem(last=False)


def _oriented(packet: dict[str, str], features: dict[str, float]) -> dict[str, object]:
    """Source and destination as initiator and responder of the packet's connection."""
    src = (packet.get("src_ip"), packet.get("src_port"))
    dst = (packet.get("dst_ip"), packet.get("dst_port"))
    if not features.get("from_initiator", 1.0):
        src, dst = dst, src
    return {"source_ip": src[0], "source_port": src[1], "destination_ip": dst[0], "destination_port": dst[1]}
