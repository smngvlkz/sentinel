"""
Packet capture service.

Reads packets from a local interface with libpcap and publishes their
header fields to a Redis Stream for downstream analysis, in batches.

Requires root/sudo for raw socket access.

Optional payload inspection (off by default): when PAYLOAD_INSPECTION is
enabled, DNS answers, cleartext HTTP Host headers and the TLS server name
(SNI) are read just enough to learn IP → hostname bindings (see names.py).
Those bindings travel on the stream as `name_bindings` and are stored only on
alerts, never as payloads.
"""

from __future__ import annotations

import json
import os
import sys
import time
import logging

import pcapy
from scapy.all import Ether, IP, TCP, UDP, Packet
import redis
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capture_service.frames import parse_frame, tcp_payload
from capture_service.names import _HTTP_METHODS, NameExtractor
from common.flags import env_flag

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
# Capture's own numbers for /health, written once a minute.
STATS_KEY = "sentinel:capture:stats"
STATS_INTERVAL = 60.0
# Enough of each packet for its headers, with VLAN tags and IP and TCP
# options; the whole packet when names are read from payloads.
SNAPLEN_HEADERS = 128
SNAPLEN_NAMES = 65535
# Packets go to Redis in batches: when this many are waiting, or after
# FLUSH_SECONDS, whichever is first. libpcap returns at least every
# TIMEOUT_MS, so a quiet network still flushes on time.
BATCH_SIZE = 500
FLUSH_SECONDS = 0.1
TIMEOUT_MS = 100
# The kernel's buffer for packets waiting to be read. A bigger one rides out
# bursts that would otherwise be dropped.
BUFFER_BYTES = 16 * 1024 * 1024
# Ports scapy decodes as DNS (and LLMNR, which it decodes as DNS too).
DNS_PORTS = {"53", "5353", "5355"}

# Off by default: reading DNS/HTTP names is a privacy trade-off. Enable with
# PAYLOAD_INSPECTION=true (and names.enabled in config/detection.toml).
PAYLOAD_INSPECTION = env_flag(os.getenv("PAYLOAD_INSPECTION")) is True


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


class DropCounter:
    """
    Packets the kernel dropped before capture read them, from libpcap's
    counters. Those are 32-bit and can wrap, so this adds up the change
    between readings.
    """

    def __init__(self) -> None:
        self.total = 0
        self._last: int | None = None

    def update(self, dropped: int) -> int:
        if self._last is not None:
            self.total += (dropped - self._last) % 2**32
        self._last = dropped
        return self.total


def write_stats(r: redis.Redis, names: NameExtractor | None, kernel_dropped: int | None) -> None:
    stats: dict = {"at": time.time(), "kernel_dropped_total": kernel_dropped}
    if names is not None:
        stats["names_dropped_total"] = names.drops.total
    try:
        r.set(STATS_KEY, json.dumps(stats), ex=int(STATS_INTERVAL * 3))
    except redis.ConnectionError:
        pass


def parse_packet(packet: Packet, *, names: NameExtractor | None = None) -> dict[str, str] | None:
    """Packet metadata for the stream, plus any hostnames `names` learns from it."""
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

    if names is not None:
        bindings = names.bindings(packet)
        if bindings:
            entry["name_bindings"] = json.dumps(bindings, separators=(",", ":"))

    return entry


def may_carry_name(entry: dict[str, str], data: bytes, names: NameExtractor) -> bool:
    """
    Whether names.bindings() could learn anything from this packet: DNS, or
    a TCP payload that starts an HTTP request or a TLS ClientHello, or
    continues a split one. Only these are decoded with scapy, which is slow.
    """
    if entry["src_port"] in DNS_PORTS or entry["dst_port"] in DNS_PORTS:
        return True
    if entry["transport"] != "TCP":
        return False
    payload = tcp_payload(data)
    if not payload:
        return False
    key = (entry["src_ip"], int(entry["src_port"]), entry["dst_ip"], int(entry["dst_port"]))
    return payload.startswith(_HTTP_METHODS) or payload[:1] == b"\x16" or names.hellos.holds(key)


def main() -> None:
    r = connect_redis()
    names = NameExtractor() if PAYLOAD_INSPECTION else None
    reader = pcapy.create(CAPTURE_INTERFACE)
    reader.set_snaplen(SNAPLEN_NAMES if names else SNAPLEN_HEADERS)
    reader.set_promisc(1)
    reader.set_timeout(TIMEOUT_MS)
    reader.set_buffer_size(BUFFER_BYTES)
    reader.activate()
    if reader.datalink() != pcapy.DLT_EN10MB:
        log.error("%s isn't an Ethernet or Wi-Fi interface (link type %d); set CAPTURE_INTERFACE",
                  CAPTURE_INTERFACE, reader.datalink())
        sys.exit(1)
    log.info(
        "capturing on %s -> stream:%s (maxlen=%d, names=%s)",
        CAPTURE_INTERFACE,
        STREAM_NAME,
        STREAM_MAXLEN,
        "on" if names is not None else "off",
    )

    drops = DropCounter()
    pipe = r.pipeline(transaction=False)
    waiting = 0
    last_flush = last_stats = time.monotonic()

    while True:
        header, data = reader.next()
        if header is not None:
            sec, usec = header.getts()
            entry = parse_frame(data, sec + usec / 1e6, header.getlen())
            if entry is not None:
                if names is not None and may_carry_name(entry, data, names):
                    pkt = Ether(data)
                    pkt.time = sec + usec / 1e6
                    bindings = names.bindings(pkt)
                    if bindings:
                        entry["name_bindings"] = json.dumps(bindings, separators=(",", ":"))
                pipe.xadd(STREAM_NAME, entry, maxlen=STREAM_MAXLEN)
                waiting += 1

        now = time.monotonic()
        if names is not None:
            names.drops.maybe_log(now)
        if waiting and (waiting >= BATCH_SIZE or now - last_flush >= FLUSH_SECONDS):
            try:
                pipe.execute()
            except redis.ConnectionError:
                log.warning("redis connection lost, reconnecting...")
                r = connect_redis()
                pipe = r.pipeline(transaction=False)
            waiting = 0
            last_flush = now
        if now - last_stats >= STATS_INTERVAL:
            write_stats(r, names, drops.update(reader.stats()[1]))
            last_stats = now


if __name__ == "__main__":
    main()
