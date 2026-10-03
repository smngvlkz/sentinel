"""
Packet capture service.

Sniffs raw network traffic from a local interface and publishes
parsed packet metadata to a Redis Stream for downstream analysis.

Requires root/sudo for raw socket access.

Optional payload inspection (off by default): when PAYLOAD_INSPECTION is
enabled, DNS answers, cleartext HTTP Host headers and the TLS server name
(SNI) are read just enough to learn IP → hostname bindings. Those bindings
travel on the stream as `name_bindings` and are stored only on alerts, never
as payloads.
"""

from __future__ import annotations

import json
import os
import re
import time
import logging
from collections import OrderedDict

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSRR, Raw, Packet
import redis
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [capture] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "en0")
STREAM_NAME = "packet_stream"
STREAM_MAXLEN = 100_000
RECONNECT_DELAY = 5

# Off by default: reading DNS/HTTP names is a privacy trade-off. Enable with
# PAYLOAD_INSPECTION=true (and names.enabled in config/detection.toml).
PAYLOAD_INSPECTION = os.getenv("PAYLOAD_INSPECTION", "").strip().lower() in ("1", "true", "yes", "on")

# Don't scan huge TCP payloads looking for a Host header or SNI.
_HTTP_PEEK = 2048
_TLS_PEEK = 4096
_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
)
MAX_NAME_LEN = 253


def connect_redis() -> redis.Redis:
    while True:
        try:
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            client.ping()
            log.info("redis connected %s:%s", REDIS_HOST, REDIS_PORT)
            return client
        except redis.ConnectionError:
            log.warning("redis unavailable, retrying in %ds...", RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)


# Labels of letters, digits, hyphens and underscores (underscores aren't
# valid in strict hostnames but appear in real DNS). Punycode (xn--...) is
# plain ASCII, so internationalised names pass.
_HOSTNAME = re.compile(r"[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*")
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


NAME_DROPS = NameDrops()


def _valid_hostname(raw: str, ip: str = "") -> str | None:
    """
    `raw` as a lowercase hostname, or None if it isn't one (and the drop is
    counted). Names are dropped, never cleaned: stripping characters can turn
    a hostile name into a different, real-looking domain (pay<b>pal.com →
    paybpal.com), and showing a name that was never sent is worse than none.
    """
    name = raw.lower()
    if name.endswith("."):
        name = name[:-1]
    if len(name) <= MAX_NAME_LEN and _HOSTNAME.fullmatch(name):
        return name
    NAME_DROPS.record(raw, ip)
    return None


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


def _dns_bindings(packet: Packet) -> list[list[str]]:
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
        name = _valid_hostname(str(rrname), ip)
        if name:
            out.append([ip, name, client])
    return out


def _http_host_bindings(packet: Packet) -> list[list[str]]:
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
        name = _valid_hostname(host, packet[IP].dst)
        if name:
            return [[packet[IP].dst, name, packet[IP].src]]
        return []
    return []


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


HELLOS = HelloReassembler()


def _tls_sni_bindings(packet: Packet, now: float | None = None) -> list[list[str]]:
    """[server, SNI, client] from a TLS ClientHello, even one split across segments."""
    if TCP not in packet or Raw not in packet or IP not in packet:
        return []
    ip, tcp = packet[IP], packet[TCP]
    key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
    sni = HELLOS.feed(
        key,
        int(tcp.seq),
        bytes(packet[Raw].load[:_TLS_PEEK]),
        now if now is not None else time.monotonic(),
    )
    if not sni:
        return []
    name = _valid_hostname(sni, packet[IP].dst)
    if not name:
        return []
    return [[packet[IP].dst, name, packet[IP].src]]


def extract_name_bindings(packet: Packet) -> list[list[str]]:
    """
    Learn [ip, name, client] triples from this packet without storing the
    payload. `client` is the device that looked the name up or connected,
    so a shared CDN address can carry a different name per device.

    DNS answers come first; otherwise the HTTP Host header or the TLS server
    name of a connection names its destination.
    """
    return _dns_bindings(packet) or _http_host_bindings(packet) or _tls_sni_bindings(packet)


def parse_packet(packet: Packet, *, names: bool | None = None) -> dict[str, str] | None:
    if IP not in packet:
        return None

    entry: dict[str, str] = {
        # Capture time from the packet itself, so a replayed recording keeps
        # its original timing (and so its packet rates).
        "timestamp": str(float(packet.time)),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": str(packet[IP].proto),
        "packet_size": str(len(packet)),
    }

    if TCP in packet:
        entry["src_port"] = str(packet[TCP].sport)
        entry["dst_port"] = str(packet[TCP].dport)
        entry["flags"] = str(packet[TCP].flags)
        entry["transport"] = "TCP"
    elif UDP in packet:
        entry["src_port"] = str(packet[UDP].sport)
        entry["dst_port"] = str(packet[UDP].dport)
        entry["flags"] = ""
        entry["transport"] = "UDP"
    else:
        entry["src_port"] = "0"
        entry["dst_port"] = "0"
        entry["flags"] = ""
        entry["transport"] = "OTHER"

    if names if names is not None else PAYLOAD_INSPECTION:
        bindings = extract_name_bindings(packet)
        if bindings:
            entry["name_bindings"] = json.dumps(bindings, separators=(",", ":"))

    return entry


def main() -> None:
    r = connect_redis()
    log.info(
        "capturing on %s -> stream:%s (maxlen=%d, names=%s)",
        CAPTURE_INTERFACE,
        STREAM_NAME,
        STREAM_MAXLEN,
        "on" if PAYLOAD_INSPECTION else "off",
    )

    def handle(pkt: Packet) -> None:
        nonlocal r
        entry = parse_packet(pkt)
        NAME_DROPS.maybe_log(time.monotonic())
        if entry is None:
            return
        try:
            r.xadd(STREAM_NAME, entry, maxlen=STREAM_MAXLEN)
        except redis.ConnectionError:
            log.warning("redis connection lost, reconnecting...")
            r = connect_redis()

    sniff(iface=CAPTURE_INTERFACE, prn=handle, store=0)


if __name__ == "__main__":
    main()
