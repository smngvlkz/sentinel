"""
Rule-based threat detection.

Each rule evaluates extracted flow features against a known attack
signature. Thresholds come from config/detection.toml and default to
conservative values that suit a residential network.
"""

from __future__ import annotations

from typing import Callable

from .config import has_rate_evidence, load_config


class RuleEngine:

    def __init__(self, config: dict[str, dict[str, float]] | None = None) -> None:
        self.config = config if config is not None else load_config()
        self.rules: list[tuple[str, Callable[[dict[str, float]], bool]]] = [
            ("SYN_FLOOD", self._syn_flood),
            ("PORT_SCAN", self._port_scan),
            ("LARGE_PAYLOAD", self._large_payload),
            ("HIGH_FREQUENCY", self._high_frequency),
        ]

    def evaluate(self, features: dict[str, float]) -> list[str]:
        return [name for name, check in self.rules if check(features)]

    def _has_rate_evidence(self, f: dict[str, float]) -> bool:
        return has_rate_evidence(f, self.config)

    def _syn_flood(self, f: dict[str, float]) -> bool:
        c = self.config["syn_flood"]
        return (
            f["syn_ratio"] > c["min_syn_ratio"]
            and f["packet_rate"] > c["min_packet_rate"]
            and self._has_rate_evidence(f)
        )

    def _port_scan(self, f: dict[str, float]) -> bool:
        # Counts ports that got a new connection attempt (so server replies
        # to ephemeral client ports don't count) and never answered it (so
        # clients legitimately opening many connections, like FTP passive
        # mode, don't count either).
        return f["unanswered_syn_ports"] > self.config["port_scan"]["min_unique_ports"]

    def _large_payload(self, f: dict[str, float]) -> bool:
        # Established TCP traffic is skipped: the capturing machine merges
        # its segments into oversized frames that never existed on the wire.
        return f["packet_size"] > self.config["large_payload"]["min_packet_size"] and not f["packet_has_ack"]

    def _high_frequency(self, f: dict[str, float]) -> bool:
        # Rate alone can't tell a flood from a download. Floods are many small
        # packets outside an established connection; downloads are large
        # packets, and their return traffic is mostly TCP ACKs.
        c = self.config["high_frequency"]
        return (
            f["packet_rate"] > c["min_packet_rate"]
            and f["avg_packet_size"] < c["max_avg_packet_size"]
            and f["ack_ratio"] < c["max_ack_ratio"]
            and self._has_rate_evidence(f)
        )
