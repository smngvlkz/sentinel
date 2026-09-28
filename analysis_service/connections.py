"""
Connection tracking and per-host activity windows.

FlowTracker (feature_extractor.py) sees traffic as one-way source ->
destination streams averaged over their whole life. This module adds the
two views it lacks:

- ConnectionTable follows each connection (protocol, both endpoints and
  ports) in both directions: who started it, traffic each way, whether the
  TCP handshake completed, and whether it closed.
- HostActivity counts new connections per host over sliding windows: how
  many a host opened, to how many different hosts, how many different
  sources connected to it, and how often one source hit one service.

Host activity only changes when a connection starts, which is far rarer
than packets, so the per-packet cost stays small.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

Endpoint = tuple[str, str]  # (ip, port)
ConnKey = tuple[str, Endpoint, Endpoint]  # (protocol, lower endpoint, higher endpoint)

# Connections idle this long are forgotten; closed ones sooner.
CONN_IDLE_TIMEOUT = 60.0
CONN_CLOSED_TIMEOUT = 5.0


@dataclass(slots=True)
class Connection:
    initiator: Endpoint
    responder: Endpoint
    start: float
    last_seen: float
    packets_out: int = 0  # initiator -> responder
    packets_in: int = 0  # responder -> initiator
    bytes_out: int = 0
    bytes_in: int = 0
    syn_ack_seen: bool = False
    established: bool = False
    closed: bool = False


def conn_key(protocol: str, a: Endpoint, b: Endpoint) -> ConnKey:
    return (protocol, a, b) if a <= b else (protocol, b, a)


class ConnectionTable:

    def __init__(self) -> None:
        self.connections: dict[ConnKey, Connection] = {}

    def update(self, packet: dict[str, str]) -> tuple[Connection, bool, bool]:
        """Record a packet. Returns (connection, is_new_connection, sent_by_initiator)."""
        now = float(packet["timestamp"])
        src = (packet["src_ip"], packet.get("src_port", "0"))
        dst = (packet["dst_ip"], packet.get("dst_port", "0"))
        flags = packet.get("flags", "")
        key = conn_key(packet.get("protocol", ""), src, dst)
        size = int(packet["packet_size"])

        conn = self.connections.get(key)
        is_syn = flags == "S"
        # A bare SYN on a closed connection's ports starts a fresh connection.
        if conn is not None and conn.closed and is_syn:
            conn = None
        is_new = conn is None
        if is_new:
            # The first packet usually comes from the initiator. A SYN-ACK
            # first means the SYN was missed and the receiver started it.
            if "S" in flags and "A" in flags:
                conn = Connection(initiator=dst, responder=src, start=now, last_seen=now)
            else:
                conn = Connection(initiator=src, responder=dst, start=now, last_seen=now)
            # Joining a TCP connection mid-stream: treat it as established.
            if packet.get("transport") == "TCP" and not is_syn and "S" not in flags:
                conn.established = True
            self.connections[key] = conn

        outbound = src == conn.initiator
        conn.last_seen = now
        if outbound:
            conn.packets_out += 1
            conn.bytes_out += size
        else:
            conn.packets_in += 1
            conn.bytes_in += size

        if "S" in flags and "A" in flags and not outbound:
            conn.syn_ack_seen = True
        elif outbound and conn.syn_ack_seen and "A" in flags and "S" not in flags:
            conn.established = True
        if "F" in flags or "R" in flags:
            conn.closed = True

        return conn, is_new, outbound

    def cleanup(self, now: float) -> int:
        stale = [
            k for k, c in self.connections.items()
            if now - c.last_seen > (CONN_CLOSED_TIMEOUT if c.closed else CONN_IDLE_TIMEOUT)
        ]
        for k in stale:
            del self.connections[k]
        return len(stale)


class WindowCounter:
    """Events in the last `window` seconds: how many, and how many distinct values."""

    __slots__ = ("window", "events", "counts")

    def __init__(self, window: float) -> None:
        self.window = window
        self.events: deque[tuple[float, object]] = deque()
        self.counts: Counter[object] = Counter()

    def add(self, now: float, value: object) -> None:
        self.events.append((now, value))
        self.counts[value] += 1
        self.expire(now)

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        while self.events and self.events[0][0] <= cutoff:
            _, value = self.events.popleft()
            self.counts[value] -= 1
            if not self.counts[value]:
                del self.counts[value]

    def total(self, now: float) -> int:
        self.expire(now)
        return len(self.events)

    def distinct(self, now: float) -> int:
        self.expire(now)
        return len(self.counts)


class _Host:
    __slots__ = ("out_10s", "out_60s", "in_10s", "in_60s")

    def __init__(self) -> None:
        self.out_10s = WindowCounter(10)  # connections this host opened; value = responder host
        self.out_60s = WindowCounter(60)
        self.in_10s = WindowCounter(10)  # connections opened to this host; value = initiator host
        self.in_60s = WindowCounter(60)


class HostActivity:

    def __init__(self) -> None:
        self.hosts: dict[str, _Host] = {}
        # (initiator host, responder host, responder port) -> new connections
        self.services: dict[tuple[str, str, str], WindowCounter] = {}

    def _host(self, ip: str) -> _Host:
        host = self.hosts.get(ip)
        if host is None:
            host = self.hosts[ip] = _Host()
        return host

    def record(self, conn: Connection) -> None:
        """Record that `conn` just started."""
        now = conn.start
        init_ip, resp_ip = conn.initiator[0], conn.responder[0]
        out = self._host(init_ip)
        out.out_10s.add(now, resp_ip)
        out.out_60s.add(now, resp_ip)
        inbound = self._host(resp_ip)
        inbound.in_10s.add(now, init_ip)
        inbound.in_60s.add(now, init_ip)
        service = (init_ip, resp_ip, conn.responder[1])
        counter = self.services.get(service)
        if counter is None:
            counter = self.services[service] = WindowCounter(10)
        counter.add(now, None)

    def features(self, conn: Connection, now: float) -> dict[str, float]:
        init = self.hosts.get(conn.initiator[0])
        resp = self.hosts.get(conn.responder[0])
        service = self.services.get((conn.initiator[0], conn.responder[0], conn.responder[1]))
        return {
            "initiator_new_conns_10s": init.out_10s.total(now) if init else 0,
            "initiator_new_conns_60s": init.out_60s.total(now) if init else 0,
            "initiator_distinct_hosts_60s": init.out_60s.distinct(now) if init else 0,
            "responder_new_conns_10s": resp.in_10s.total(now) if resp else 0,
            "responder_distinct_sources_60s": resp.in_60s.distinct(now) if resp else 0,
            "service_new_conns_10s": service.total(now) if service else 0,
        }

    def cleanup(self, now: float) -> int:
        """Forget hosts and services with nothing in their windows."""
        idle = [ip for ip, h in self.hosts.items() if not (h.out_60s.total(now) or h.in_60s.total(now))]
        for ip in idle:
            del self.hosts[ip]
        quiet = [k for k, c in self.services.items() if not c.total(now)]
        for k in quiet:
            del self.services[k]
        return len(idle)


def connection_features(conn: Connection, outbound: bool, now: float) -> dict[str, float]:
    return {
        "conn_packets_out": conn.packets_out,
        "conn_packets_in": conn.packets_in,
        "conn_bytes_out": conn.bytes_out,
        "conn_bytes_in": conn.bytes_in,
        "conn_established": 1.0 if conn.established else 0.0,
        "conn_duration": max(now - conn.start, 0.0),
        "from_initiator": 1.0 if outbound else 0.0,
    }
