"""
Flow-based feature extraction.

Tracks one-way flows (source -> destination) and computes statistical
features used by both the rule engine and the anomaly detection model.
Connection-level (both directions) and per-host windowed features come
from connections.py and are added alongside.
"""

from __future__ import annotations

import time
from collections import defaultdict

from detection_engine.config import DEFAULTS

from .beacons import BeaconTracker
from .connections import ConnectionTable, HostActivity, connection_features
from .seen_twice import SeenTwiceTable

# Connection requests followed per flow while their handshake completes.
# Beyond this, new ones aren't followed until some finish or expire: a flood
# still shows up a grace period later (more than min_unfinished of these
# expire), and the flow table stays small.
MAX_PENDING_SYNS = 32


def _new_flow() -> dict:
    return {
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
        # Connection requests (by source port) not yet completed, oldest
        # first, and how many were still unfinished after the grace period.
        "pending_syns": {},
        "unfinished_syns": 0,
    }


class FlowTracker:

    def __init__(
        self,
        flow_timeout: float = 30.0,
        limits: dict[str, int] | None = None,
        handshake_seconds: float = DEFAULTS["syn_flood"]["handshake_seconds"],
    ) -> None:
        limits = {**DEFAULTS["limits"], **(limits or {})}
        self.handshake_seconds = handshake_seconds
        # A flood of one-packet flows can't push out flows seen twice (seen_twice.py).
        self.flows: SeenTwiceTable[tuple[str, str], dict] = SeenTwiceTable(
            limits["max_flows"], on_evict=lambda key, _: self._release(key[0])
        )
        self.flow_timeout = flow_timeout
        # Live flows per source; a source with none is removed.
        self.ip_connection_counts: dict[str, int] = {}
        self.connections = ConnectionTable(limits["max_connections"])
        self.hosts = HostActivity(
            limits["max_hosts"], limits["max_services"], limits["max_sweeps"], limits["max_window_events"]
        )
        self.beacons = BeaconTracker(limits["max_beacon_series"])

    def _flow_key(self, packet: dict[str, str]) -> tuple[str, str]:
        return (packet["src_ip"], packet["dst_ip"])

    def update(self, packet: dict[str, str]) -> dict[str, float]:
        key = self._flow_key(packet)
        now = float(packet["timestamp"])

        flow = self.flows.touch(key, _new_flow)
        if flow["start_time"] and now - flow["last_seen"] > self.flow_timeout:
            # Idle past the timeout, so this flow is over; cleanup just hasn't
            # run yet (it checks once a minute). Start afresh, as if it had:
            # otherwise the rates average in the quiet gap, and a flood that
            # repeats every minute is only caught when cleanup happens to fall
            # between two bursts.
            self._release(key[0])
            flow.clear()
            flow.update(_new_flow())
        if flow["start_time"] == 0.0:
            flow["start_time"] = now
            src = packet["src_ip"]
            self.ip_connection_counts[src] = self.ip_connection_counts.get(src, 0) + 1

        flow["last_seen"] = now
        flow["packet_count"] += 1
        flow["total_bytes"] += int(packet["packet_size"])
        flow["ports_seen"].add(packet["dst_port"])

        flags = packet.get("flags", "")
        if flags:
            flow["flag_counts"][flags] += 1
        if flags == "S":
            flow["syn_ports_seen"].add(packet["dst_port"])
            self._syn_sent(flow, packet["src_port"], now)
        elif "S" in flags and "A" in flags:
            # A SYN-ACK answers the connection attempt in the reverse flow.
            # .get(), not [], so a stray SYN-ACK doesn't create a flow.
            asker = self.flows.get((packet["dst_ip"], packet["src_ip"]))
            if asker is not None:
                asker["answered_ports"].add(packet["src_port"])
        if "A" in flags:
            flow["ack_count"] += 1
            if "S" not in flags:
                # The client's ACK completes its handshake (and every later
                # packet carries one): that request wasn't a flood.
                flow["pending_syns"].pop(packet["src_port"], None)
        self._expire_syns(flow, now)

        duration = max(now - flow["start_time"], 0.001)

        conn, is_new, outbound = self.connections.update(packet)
        if is_new:
            self.hosts.record(conn)
            self.beacons.record(conn)

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
            "src_connection_count": self.ip_connection_counts.get(packet["src_ip"], 0),
            "syn_count": flow["flag_counts"].get("S", 0),
            "syn_ratio": flow["flag_counts"].get("S", 0) / flow["packet_count"],
            "unfinished_syns": flow["unfinished_syns"],
            **connection_features(conn, outbound, now),
            **self.hosts.features(conn, now),
            **self.beacons.features(conn, now),
        }

    def _syn_sent(self, flow: dict, src_port: str, now: float) -> None:
        pending = flow["pending_syns"]
        if src_port in pending or len(pending) >= MAX_PENDING_SYNS:
            return  # a retransmission of a request already waiting, or too many to follow
        pending[src_port] = now

    def _expire_syns(self, flow: dict, now: float) -> None:
        """
        Requests not completed within the grace period count as unfinished.
        A browser opening a dozen connections at once completes them all
        within a round trip; a flood never completes its requests (no answer,
        or the sender resets instead of finishing the handshake).
        """
        pending = flow["pending_syns"]
        while pending:
            port, sent = next(iter(pending.items()))
            if now - sent <= self.handshake_seconds:
                break
            del pending[port]
            flow["unfinished_syns"] += 1

    @property
    def evicted(self) -> int:
        return self.flows.evicted

    def _release(self, src: str) -> None:
        """One fewer live flow from `src`."""
        count = self.ip_connection_counts.get(src, 0) - 1
        if count > 0:
            self.ip_connection_counts[src] = count
        else:
            self.ip_connection_counts.pop(src, None)

    def cleanup_stale(self, now: float | None = None) -> int:
        now = now or time.time()
        stale = self.flows.expire(
            lambda flow: now - flow["last_seen"] > self.flow_timeout,
            on_remove=lambda key, _: self._release(key[0]),
        )
        self.connections.cleanup(now)
        self.hosts.cleanup(now)
        self.beacons.cleanup(now)
        return stale
