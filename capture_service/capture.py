"""
Packet capture service.

Sniffs raw network traffic from a local interface and publishes
parsed packet metadata to a Redis Stream for downstream analysis.

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

from scapy.all import sniff, IP, TCP, UDP, Packet
import redis
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capture_service.names import NameExtractor
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


def main() -> None:
    r = connect_redis()
    names = NameExtractor() if PAYLOAD_INSPECTION else None
    log.info(
        "capturing on %s -> stream:%s (maxlen=%d, names=%s)",
        CAPTURE_INTERFACE,
        STREAM_NAME,
        STREAM_MAXLEN,
        "on" if names is not None else "off",
    )

    def handle(pkt: Packet) -> None:
        nonlocal r
        entry = parse_packet(pkt, names=names)
        if names is not None:
            names.drops.maybe_log(time.monotonic())
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
