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
import time
import logging

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


def _sanitize_name(name: str) -> str | None:
    cleaned = "".join(c for c in name.rstrip(".").lower() if 32 <= ord(c) < 127)
    if not cleaned:
        return None
    return cleaned[:MAX_NAME_LEN]


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
        rrname = answer.rrname
        if isinstance(rrname, bytes):
            rrname = rrname.decode("ascii", "ignore")
        name = _sanitize_name(str(rrname))
        rdata = answer.rdata
        if isinstance(rdata, bytes):
            continue
        ip = str(rdata)
        if name and ip and ip not in ("0.0.0.0", "::"):
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
        host = line.split(b":", 1)[1].strip().decode("ascii", "ignore")
        # Host: example.com:8080 → example.com
        host = host.split(":", 1)[0].strip()
        name = _sanitize_name(host)
        if name:
            return [[packet[IP].dst, name, packet[IP].src]]
        return []
    return []


def _parse_sni(data: bytes) -> str | None:
    """
    Server name from a TLS ClientHello, or None.

    Walks only the bytes present: a large ClientHello (post-quantum key
    shares) can span two TCP segments, and if the SNI extension falls in the
    second one it's simply missed.
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
                return raw.decode("ascii", "ignore")
            pos += ext_len
    except IndexError:
        return None
    return None


_SNI_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")


def _tls_sni_bindings(packet: Packet) -> list[list[str]]:
    """[server, SNI, client] from a TLS ClientHello."""
    if TCP not in packet or Raw not in packet or IP not in packet:
        return []
    sni = _parse_sni(bytes(packet[Raw].load[:_TLS_PEEK]))
    if not sni:
        return []
    name = _sanitize_name(sni)
    # SNI must be a DNS hostname; drop anything else rather than show junk.
    if not name or not set(name) <= _SNI_CHARS:
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
