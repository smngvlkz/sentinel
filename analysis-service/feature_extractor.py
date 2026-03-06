"""Feature extraction from raw packet data into ML-ready features."""

import time
from collections import defaultdict


class FlowTracker:
    """Tracks network flows and extracts statistical features."""

    def __init__(self, flow_timeout=30.0):
        self.flows = defaultdict(lambda: {
            "start_time": 0.0,
            "last_seen": 0.0,
            "packet_count": 0,
            "total_bytes": 0,
            "ports_seen": set(),
            "flag_counts": defaultdict(int),
        })
        self.flow_timeout = flow_timeout
        self.ip_connection_counts = defaultdict(int)

    def _flow_key(self, packet):
        return (packet["src_ip"], packet["dst_ip"])

    def update(self, packet):
        """Update flow state with a new packet and return extracted features."""
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

        features = {
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

        return features

    def cleanup_stale(self, now=None):
        """Remove flows that have been idle beyond the timeout."""
        now = now or time.time()
        stale = [k for k, v in self.flows.items() if now - v["last_seen"] > self.flow_timeout]
        for k in stale:
            src_ip = k[0]
            self.ip_connection_counts[src_ip] = max(0, self.ip_connection_counts[src_ip] - 1)
            del self.flows[k]
        return len(stale)
