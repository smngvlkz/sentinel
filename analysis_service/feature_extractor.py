"""
Flow-based feature extraction.

Tracks one-way flows (source -> destination) and computes statistical
features used by both the rule engine and the anomaly detection model.
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
            # Ports that received a bare SYN, i.e. a new connection attempt.
            # Replies from a server land on many ephemeral client ports but
            # are never bare SYNs, so this is what port-scan detection uses.
            "syn_ports_seen": set(),
            # Of those, ports that answered with a SYN-ACK. Scanners mostly
            # hit closed ports that never answer; legitimate clients opening
            # many connections (FTP passive mode, for one) get answers.
            "answered_ports": set(),
            "ack_count": 0,
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

        flags = packet.get("flags", "")
        if flags:
            flow["flag_counts"][flags] += 1
        if flags == "S":
            flow["syn_ports_seen"].add(packet["dst_port"])
        elif "S" in flags and "A" in flags:
            # A SYN-ACK answers the connection attempt in the reverse flow.
            # .get(), not [], so a stray SYN-ACK doesn't create a flow.
            asker = self.flows.get((packet["dst_ip"], packet["src_ip"]))
            if asker is not None:
                asker["answered_ports"].add(packet["src_port"])
        if "A" in flags:
            flow["ack_count"] += 1

        duration = max(now - flow["start_time"], 0.001)

        return {
            "packet_rate": flow["packet_count"] / duration,
            "byte_rate": flow["total_bytes"] / duration,
            "avg_packet_size": flow["total_bytes"] / flow["packet_count"],
            "packet_size": int(packet["packet_size"]),
            "unique_dst_ports": len(flow["ports_seen"]),
            "unique_syn_dst_ports": len(flow["syn_ports_seen"]),
            "unanswered_syn_ports": len(flow["syn_ports_seen"] - flow["answered_ports"]),
            # Part of an established TCP connection. Capture hosts merge
            # these into oversized "packets" (receive offload), so size
            # checks skip them.
            "packet_has_ack": 1.0 if "A" in flags else 0.0,
            "ack_ratio": flow["ack_count"] / flow["packet_count"],
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
