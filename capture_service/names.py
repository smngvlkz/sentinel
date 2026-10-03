"""
Hostnames from packets, for alert context (optional payload inspection).

DNS answers, cleartext HTTP Host headers and the TLS server name (SNI) are
read just enough to learn [ip, name, client] bindings; payloads are never
kept. `NameExtractor` holds the only state: the count of dropped names and
the TLS handshakes waiting for their next segment.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict

from scapy.all import IP, TCP, DNS, DNSRR, Raw, Packet

from common.hostnames import valid_hostname

log = logging.getLogger(__name__)

# Don't scan huge TCP payloads looking for a Host header or SNI.
_HTTP_PEEK = 2048
_TLS_PEEK = 4096
_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
)
# Longest bad name shown in the drop log, so a huge junk name can't flood it.
_LOG_NAME_CHARS = 40


class NameDrops:
    """
    Counts names dropped as invalid and logs one summary a minute at most.

    A hostile hostname is itself worth noticing, so drops aren't silent; but
    a flood of junk names must not flood the log either. The bad name is
    shown escaped (ascii()) and truncated, so it can't forge log lines or
    send terminal control codes.
    """

    def __init__(self, interval: float = 60.0) -> None:
        self.interval = interval
        self.count = 0
        self.latest: tuple[str, str] | None = None
        self.since: float | None = None

    def record(self, raw: str, ip: str) -> None:
        self.count += 1
        self.latest = (raw, ip)

    def maybe_log(self, now: float) -> bool:
        if self.since is None:
            self.since = now
        if not self.count or now - self.since < self.interval:
            return False
        raw, ip = self.latest or ("", "")
        log.warning(
            "dropped %d invalid name(s) in the last %ds (latest: %s%s for %s)",
            self.count,
            round(now - self.since),
            ascii(raw[:_LOG_NAME_CHARS]),
            "..." if len(raw) > _LOG_NAME_CHARS else "",
            ascii(ip),
        )
        self.count, self.latest, self.since = 0, None, now
        return True


def _dns_answer_rrs(dns: DNS) -> list[DNSRR]:
    """Walk the answer section; works for wire packets and hand-built ones."""
    section = dns.an
    if section is None:
        return []
    rrs: list[DNSRR] = []
    # Scapy sometimes wraps answers in a one-element list.
    if isinstance(section, list):
        section = section[0] if section else None
    while isinstance(section, DNSRR):
        rrs.append(section)
        nxt = section.payload
        section = nxt if isinstance(nxt, DNSRR) else None
    return rrs


def _parse_sni(data: bytes) -> str | None:
    """
    Server name from a TLS ClientHello, or None.

    Walks only the bytes present. A large ClientHello (post-quantum key
    shares) often spans two TCP segments; `HelloReassembler` joins them when
    the name isn't in the first.
    """
    # TLS record: handshake (22), version 3.x, then ClientHello (1).
    if len(data) < 9 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    end = len(data)
    # Skip record header (5), handshake header (4), client version (2), random (32).
    pos = 5 + 4 + 2 + 32
    try:
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression methods
        ext_end = min(end, pos + 2 + int.from_bytes(data[pos : pos + 2], "big"))
        pos += 2
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0:  # server_name
                # list length (2), name type (1, 0 = host_name), name length (2)
                if pos + 5 > end or data[pos + 2] != 0:
                    return None
                name_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
                raw = data[pos + 5 : pos + 5 + name_len]
                if len(raw) != name_len:
                    return None
                return raw.decode("latin-1")
            pos += ext_len
    except IndexError:
        return None
    return None


def _client_hello_length(data: bytes) -> int | None:
    """Full length of the TLS record if `data` starts a ClientHello, else None."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    return 5 + int.from_bytes(data[3:5], "big")


class HelloReassembler:
    """
    Joins a ClientHello split across TCP segments, to read a server name
    that landed in a later segment.

    Chrome and Safari send post-quantum key shares, which roughly doubles the
    ClientHello to about 1.8-2.5 KB, more than one segment, and they shuffle
    extension order. Measured on a Mac (2026-10-03): about half of all
    handshakes were split, and 18-23% of server names were only in a later
    segment. Replaying 502 real connections, this raised names read from 81%
    to 99.8%.

    Bounded so a flood of fake partial handshakes can't use much memory: at
    most `max_flows` held, `max_bytes` each, for `ttl` seconds. Segments must
    arrive in order; anything else is dropped. The worst an attacker can do
    is make some names go missing.
    """

    def __init__(self, max_flows: int = 256, max_bytes: int = 8192, ttl: float = 2.0) -> None:
        self.max_flows = max_flows
        self.max_bytes = max_bytes
        self.ttl = ttl
        # (src, sport, dst, dport) -> (bytes so far, next expected seq, record length, deadline)
        self._pending: OrderedDict[tuple, tuple[bytes, int, int, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._pending)

    def feed(self, key: tuple, seq: int, payload: bytes, now: float) -> str | None:
        """Process one TCP payload; returns the SNI once it can be read."""
        held = self._pending.pop(key, None)
        if held is not None:
            data, expected, rec_len, deadline = held
            if seq != expected or now > deadline:
                return None  # out of order or stale: give up on this one
            data += payload
        else:
            rec_len = _client_hello_length(payload)
            if rec_len is None:
                return None
            data = payload
        sni = _parse_sni(data)
        if sni or len(data) >= rec_len or len(data) >= self.max_bytes:
            return sni  # found it, or the whole hello is here without one
        # Still incomplete: hold it for the next segment.
        if held is None:
            deadline = now + self.ttl
        self._pending[key] = (data, (seq + len(payload)) & 0xFFFFFFFF, rec_len, deadline)
        while len(self._pending) > self.max_flows:
            self._pending.popitem(last=False)
        return None


class NameExtractor:
    """
    Learns [ip, name, client] triples from packets without storing the
    payload. `client` is the device that looked the name up or connected,
    so a shared CDN address can carry a different name per device.
    """

    def __init__(self, drops: NameDrops | None = None, hellos: HelloReassembler | None = None) -> None:
        self.drops = drops if drops is not None else NameDrops()
        self.hellos = hellos if hellos is not None else HelloReassembler()

    def bindings(self, packet: Packet) -> list[list[str]]:
        """
        DNS answers come first; otherwise the HTTP Host header or the TLS
        server name of a connection names its destination.
        """
        return self.dns(packet) or self.http_host(packet) or self.tls_sni(packet)

    def _valid(self, raw: str, ip: str) -> str | None:
        """`raw` as a hostname, or None (and the drop is counted)."""
        name = valid_hostname(raw)
        if name is None:
            self.drops.record(raw, ip)
        return name

    def dns(self, packet: Packet) -> list[list[str]]:
        """[ip, name, client] from DNS A/AAAA answers; the client asked."""
        if DNS not in packet:
            return []
        dns = packet[DNS]
        if int(getattr(dns, "qr", 0) or 0) != 1:
            return []

        client = packet[IP].dst if IP in packet else ""
        out: list[list[str]] = []
        for answer in _dns_answer_rrs(dns):
            if int(answer.type) not in (1, 28):  # A, AAAA
                continue
            rdata = answer.rdata
            if isinstance(rdata, bytes):
                continue
            ip = str(rdata)
            if not ip or ip in ("0.0.0.0", "::"):
                continue
            rrname = answer.rrname
            if isinstance(rrname, bytes):
                # latin-1 maps every byte to one character, so nothing is
                # silently removed before validation.
                rrname = rrname.decode("latin-1")
            name = self._valid(str(rrname), ip)
            if name:
                out.append([ip, name, client])
        return out

    def http_host(self, packet: Packet) -> list[list[str]]:
        """[server, Host header, client] from a cleartext HTTP request."""
        if TCP not in packet or Raw not in packet or IP not in packet:
            return []
        raw = bytes(packet[Raw].load[:_HTTP_PEEK])
        if not raw.startswith(_HTTP_METHODS):
            return []
        for line in raw.split(b"\r\n"):
            if not line.lower().startswith(b"host:"):
                continue
            host = line.split(b":", 1)[1].strip().decode("latin-1")
            # Host: example.com:8080 → example.com
            host = host.split(":", 1)[0].strip()
            name = self._valid(host, packet[IP].dst)
            if name:
                return [[packet[IP].dst, name, packet[IP].src]]
            return []
        return []

    def tls_sni(self, packet: Packet, now: float | None = None) -> list[list[str]]:
        """[server, SNI, client] from a TLS ClientHello, even one split across segments."""
        if TCP not in packet or Raw not in packet or IP not in packet:
            return []
        ip, tcp = packet[IP], packet[TCP]
        key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
        sni = self.hellos.feed(
            key,
            int(tcp.seq),
            bytes(packet[Raw].load[:_TLS_PEEK]),
            now if now is not None else time.monotonic(),
        )
        if not sni:
            return []
        name = self._valid(sni, packet[IP].dst)
        if not name:
            return []
        return [[packet[IP].dst, name, packet[IP].src]]
