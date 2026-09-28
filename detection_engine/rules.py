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
            ("REQUEST_FLOOD", self._request_flood),
            ("DISTRIBUTED_FLOOD", self._distributed_flood),
            ("NETWORK_SWEEP", self._network_sweep),
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

    # The rules below use connection and per-host window features. .get()
    # keeps them from failing on feature sets built without those.

    def _request_flood(self, f: dict[str, float]) -> bool:
        # Completed TCP connections only: a SYN flood never completes them
        # (SYN_FLOOD covers that), and busy UDP services like DNS aren't
        # connections in this sense.
        return bool(f.get("conn_established")) and (
            f.get("service_new_conns_10s", 0) > self.config["request_flood"]["min_new_connections_10s"]
        )

    def _distributed_flood(self, f: dict[str, float]) -> bool:
        return f.get("responder_external_sources_60s", 0) > self.config["distributed_flood"]["min_external_sources_60s"]

    def _network_sweep(self, f: dict[str, float]) -> bool:
        return f.get("initiator_same_port_local_hosts_60s", 0) > self.config["network_sweep"]["min_local_hosts_60s"]
