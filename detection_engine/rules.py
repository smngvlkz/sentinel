"""
Rule-based threat detection.

Each rule evaluates extracted flow features against a known attack
signature. Thresholds are intentionally conservative to reduce false
positives on residential networks.
"""

from __future__ import annotations

from typing import Callable


class RuleEngine:

    def __init__(self) -> None:
        self.rules: list[tuple[str, Callable[[dict[str, float]], bool]]] = [
            ("SYN_FLOOD", self._syn_flood),
            ("PORT_SCAN", self._port_scan),
            ("LARGE_PAYLOAD", self._large_payload),
            ("HIGH_FREQUENCY", self._high_frequency),
        ]

    def evaluate(self, features: dict[str, float]) -> list[str]:
        return [name for name, check in self.rules if check(features)]

    def _syn_flood(self, f: dict[str, float]) -> bool:
        return f["syn_ratio"] > 0.8 and f["packet_rate"] > 50

    def _port_scan(self, f: dict[str, float]) -> bool:
        return f["unique_dst_ports"] > 20

    def _large_payload(self, f: dict[str, float]) -> bool:
        return f["packet_size"] > 10_000

    def _high_frequency(self, f: dict[str, float]) -> bool:
        return f["packet_rate"] > 200
