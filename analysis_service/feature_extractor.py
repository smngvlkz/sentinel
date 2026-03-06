"""
Flow-based feature extraction.

Tracks bidirectional network flows and computes statistical features
used by both the rule engine and the anomaly detection model.
"""

from __future__ import annotations

import time
from collections import defaultdict


class FlowTracker:

    def __init__(self, flow_timeout: float = 30.0) -> None:
        self.flows: dict[tuple[str, str], dict] = defaultdict(lambda: {
            "start_time": 0.0,
            "last_seen": 0.0,
            "packet_count": 0,
            "total_bytes": 0,
            "ports_seen": set(),
            "flag_counts": defaultdict(int),
        })
        self.flow_timeout = flow_timeout
        self.ip_connection_counts: dict[str, int] = defaultdict(int)

    def _flow_key(self, packet: dict[str, str]) -> tuple[str, str]:
        return (packet["src_ip"], packet["dst_ip"])

    def update(self, packet: dict[str, str]) -> dict[str, float]:
        key = self._flow_key(packet)
        now = float(packet["timestamp"])

        flow = self.flows[key]
        if flow["start_time"] == 0.0:
            flow["start_time"] = now
            self.ip_connection_counts[packet["src_ip"]] += 1

        flow["last_seen"] = now
        flow["packet_count"] += 1
        flow["total_bytes"] += int(packet["packet_size"])
        flow["ports_seen"].add(packet["dst_port"])

        if packet.get("flags"):
            flow["flag_counts"][packet["flags"]] += 1

        duration = max(now - flow["start_time"], 0.001)

        return {
            "packet_rate": flow["packet_count"] / duration,
            "byte_rate": flow["total_bytes"] / duration,
            "avg_packet_size": flow["total_bytes"] / flow["packet_count"],
            "packet_size": int(packet["packet_size"]),
            "unique_dst_ports": len(flow["ports_seen"]),
            "flow_duration": duration,
            "total_packets": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "src_connection_count": self.ip_connection_counts[packet["src_ip"]],
            "syn_count": flow["flag_counts"].get("S", 0),
            "syn_ratio": flow["flag_counts"].get("S", 0) / flow["packet_count"],
        }

    def cleanup_stale(self, now: float | None = None) -> int:
        now = now or time.time()
        stale = [k for k, v in self.flows.items() if now - v["last_seen"] > self.flow_timeout]
        for k in stale:
            self.ip_connection_counts[k[0]] = max(0, self.ip_connection_counts[k[0]] - 1)
            del self.flows[k]
        return len(stale)
