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

Every table has a hard size cap (`[limits]` in config/detection.toml) and is
kept in order of last activity, so a full table drops whatever was quiet
longest, and cleanup removes stale entries from the quiet end without
looking at the rest.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from functools import lru_cache

from detection_engine.config import DEFAULTS

from .seen_twice import SeenTwiceTable

_LIMITS = DEFAULTS["limits"]

Endpoint = tuple[str, str]  # (ip, port)
ConnKey = tuple[str, Endpoint, Endpoint]  # (protocol, lower endpoint, higher endpoint)

# Connections idle this long are forgotten; closed ones sooner.
CONN_IDLE_TIMEOUT = 60.0
CONN_CLOSED_TIMEOUT = 5.0
# For this long after the first packet, a connection seen without its
# opening handshake (TCP without a SYN, or any UDP flow) is assumed to have
# been open before capture started. After that it counts as new, so floods
# that never send a SYN (ACK and RST floods) are still counted.
STARTUP_WINDOW = 60.0


@dataclass(slots=True)
class Connection:
    initiator: Endpoint
    responder: Endpoint
    start: float
    last_seen: float
    protocol: str = ""
    # TCP seen without its SYN: joined partway through, either because
    # capture started after it opened or because it was forgotten while idle.
    mid_stream: bool = False
    # Seen without its opening handshake in capture's first minute, so most
    # likely open before capture started rather than a new connection.
    before_capture: bool = False
    packets_out: int = 0  # initiator -> responder
    packets_in: int = 0  # responder -> initiator
    bytes_out: int = 0
    bytes_in: int = 0
    syn_ack_seen: bool = False
    established: bool = False
    closed: bool = False


# Addresses on your own network: the private LAN ranges, loopback, link-local
# and IPv6 unique-local. Listed explicitly because ipaddress's is_private also
# covers the documentation ranges (e.g. 203.0.113.0/24), which the demo and
# tests use to stand in for internet hosts.
_LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]


@lru_cache(maxsize=65536)
def is_local(ip: str) -> bool:
    """Whether an address is on this network rather than the internet."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _LOCAL_NETWORKS if net.version == addr.version)


def conn_key(protocol: str, a: Endpoint, b: Endpoint) -> ConnKey:
    return (protocol, a, b) if a <= b else (protocol, b, a)


class ConnectionTable:

    def __init__(self, max_connections: int = _LIMITS["max_connections"]) -> None:
        # In order of last packet, oldest first.
        self.connections: OrderedDict[ConnKey, Connection] = OrderedDict()
        # Closed connections expire sooner, so they get their own order too.
        self._closed: OrderedDict[ConnKey, None] = OrderedDict()
        self.max_connections = max(1, int(max_connections))
        self.evicted = 0
        self.first_seen: float | None = None

    def update(self, packet: dict[str, str]) -> tuple[Connection, bool, bool]:
        """Record a packet. Returns (connection, is_new_connection, sent_by_initiator)."""
        now = float(packet["timestamp"])
        if self.first_seen is None:
            self.first_seen = now
        src = (packet["src_ip"], packet.get("src_port", "0"))
        dst = (packet["dst_ip"], packet.get("dst_port", "0"))
        flags = packet.get("flags", "")
        protocol = packet.get("protocol", "")
        key = conn_key(protocol, src, dst)
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
                conn = Connection(initiator=dst, responder=src, start=now, last_seen=now, protocol=protocol)
            else:
                conn = Connection(initiator=src, responder=dst, start=now, last_seen=now, protocol=protocol)
            # Joining a TCP connection mid-stream: treat it as established.
            transport = packet.get("transport")
            starting_up = now - self.first_seen < STARTUP_WINDOW
            if transport == "TCP" and not is_syn and "S" not in flags:
                conn.established = True
                conn.mid_stream = True
                conn.before_capture = starting_up
            elif transport == "UDP":
                conn.before_capture = starting_up
            self._closed.pop(key, None)  # it may replace a closed one
            self.connections[key] = conn
            self.connections.move_to_end(key)
            while len(self.connections) > self.max_connections:
                old, _ = self.connections.popitem(last=False)
                self._closed.pop(old, None)
                self.evicted += 1
        else:
            self.connections.move_to_end(key)

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
        if conn.closed:
            self._closed[key] = None
            self._closed.move_to_end(key)

        return conn, is_new, outbound

    def cleanup(self, now: float) -> int:
        """Forget closed connections quiet for 5 s and any connection quiet for 60 s."""
        removed = 0
        while self._closed:
            key = next(iter(self._closed))
            if now - self.connections[key].last_seen <= CONN_CLOSED_TIMEOUT:
                break
            del self._closed[key]
            del self.connections[key]
            removed += 1
        while self.connections:
            key, conn = next(iter(self.connections.items()))
            if now - conn.last_seen <= CONN_IDLE_TIMEOUT:
                break
            del self.connections[key]
            self._closed.pop(key, None)
            removed += 1
        return removed


class WindowCounter:
    """
    Events in the last `window` seconds: how many, and how many distinct
    values. Holds at most `cap` events (the newest), so under a flood the
    counts top out at the cap, far above any rule threshold.
    """

    __slots__ = ("window", "events", "counts", "cap")

    def __init__(self, window: float, cap: int = _LIMITS["max_window_events"]) -> None:
        self.window = window
        self.cap = max(1, int(cap))
        self.events: deque[tuple[float, object]] = deque()
        self.counts: Counter[object] = Counter()

    def add(self, now: float, value: object) -> None:
        self.events.append((now, value))
        self.counts[value] += 1
        if len(self.events) > self.cap:
            self._drop_oldest()
        self.expire(now)

    def _drop_oldest(self) -> None:
        _, value = self.events.popleft()
        self.counts[value] -= 1
        if not self.counts[value]:
            del self.counts[value]

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        while self.events and self.events[0][0] <= cutoff:
            self._drop_oldest()

    def total(self, now: float) -> int:
        self.expire(now)
        return len(self.events)

    def distinct(self, now: float) -> int:
        self.expire(now)
        return len(self.counts)


class _Host:
    __slots__ = ("out_10s", "out_60s", "in_10s", "in_60s", "in_external_60s")

    def __init__(self, cap: int) -> None:
        self.out_10s = WindowCounter(10, cap)  # connections this host opened; value = responder host
        self.out_60s = WindowCounter(60, cap)
        self.in_10s = WindowCounter(10, cap)  # connections opened to this host; value = initiator host
        self.in_60s = WindowCounter(60, cap)
        self.in_external_60s = WindowCounter(60, cap)  # the same, from internet hosts only


class HostActivity:

    def __init__(
        self,
        max_hosts: int = _LIMITS["max_hosts"],
        max_services: int = _LIMITS["max_services"],
        max_sweeps: int = _LIMITS["max_sweeps"],
        max_window_events: int = _LIMITS["max_window_events"],
    ) -> None:
        # A flood of one-off hosts can't push out hosts seen twice (seen_twice.py).
        self.hosts: SeenTwiceTable[str, _Host] = SeenTwiceTable(max_hosts)
        # (initiator host, responder host, protocol, responder port) -> new connections.
        # Protocol matters: browsers' QUIC is UDP on 443, next to HTTPS on TCP 443.
        self.services: SeenTwiceTable[tuple[str, str, str, str], WindowCounter] = SeenTwiceTable(max_services)
        # (initiator host, protocol, port) -> local hosts it opened connections to
        self.sweeps: SeenTwiceTable[tuple[str, str, str], WindowCounter] = SeenTwiceTable(max_sweeps)
        self.window_cap = max(1, int(max_window_events))

    @property
    def evicted(self) -> dict[str, int]:
        return {"hosts": self.hosts.evicted, "services": self.services.evicted, "sweeps": self.sweeps.evicted}

    def _host(self, ip: str) -> _Host:
        return self.hosts.touch(ip, lambda: _Host(self.window_cap))

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
        # Connections already open when capture started aren't new attempts,
        # so they don't count towards a sweep or a distributed flood (they'd
        # all appear at once, with the server mistaken for the initiator).
        if not is_local(init_ip) and not conn.before_capture:
            inbound.in_external_60s.add(now, init_ip)
        service = (init_ip, resp_ip, conn.protocol, conn.responder[1])
        self.services.touch(service, lambda: WindowCounter(10, self.window_cap)).add(now, None)
        if is_local(resp_ip) and not conn.before_capture:
            sweep = (init_ip, conn.protocol, conn.responder[1])
            self.sweeps.touch(sweep, lambda: WindowCounter(60, self.window_cap)).add(now, resp_ip)

    def busiest(self, now: float) -> tuple[str | None, int, str | None]:
        """
        The host with the most new connections in the last minute, either
        way: (host, how many different hosts it dealt with, the latest of
        them). Looks at every host, so it's only for the pressure alert.
        """
        best, best_total = None, 0
        for ip, host in self.hosts.items():
            total = host.in_60s.total(now) + host.out_60s.total(now)
            if total > best_total:
                best, best_total = ip, total
        if best is None:
            return None, 0, None
        host = self.hosts[best]
        windows = [w for w in (host.in_60s, host.out_60s) if w.events]
        latest = max(windows, key=lambda w: w.events[-1][0]).events[-1][1] if windows else None
        return best, host.in_60s.distinct(now) + host.out_60s.distinct(now), latest

    def features(self, conn: Connection, now: float) -> dict[str, float]:
        init = self.hosts.get(conn.initiator[0])
        resp = self.hosts.get(conn.responder[0])
        service = self.services.get((conn.initiator[0], conn.responder[0], conn.protocol, conn.responder[1]))
        sweep = self.sweeps.get((conn.initiator[0], conn.protocol, conn.responder[1]))
        return {
            "initiator_new_conns_10s": init.out_10s.total(now) if init else 0,
            "initiator_new_conns_60s": init.out_60s.total(now) if init else 0,
            "initiator_distinct_hosts_60s": init.out_60s.distinct(now) if init else 0,
            "responder_new_conns_10s": resp.in_10s.total(now) if resp else 0,
            "responder_distinct_sources_60s": resp.in_60s.distinct(now) if resp else 0,
            "responder_external_sources_60s": resp.in_external_60s.distinct(now) if resp else 0,
            "service_new_conns_10s": service.total(now) if service else 0,
            "initiator_same_port_local_hosts_60s": sweep.distinct(now) if sweep else 0,
        }

    def cleanup(self, now: float) -> int:
        """Forget hosts and services with nothing in their windows."""
        idle = self.hosts.expire(lambda h: not (h.out_60s.total(now) or h.in_60s.total(now)))
        for table in (self.services, self.sweeps):
            table.expire(lambda c: not c.total(now))
        return idle


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
