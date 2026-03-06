"""
Packet capture service.

Sniffs raw network traffic from a local interface and publishes
parsed packet metadata to a Redis Stream for downstream analysis.

Requires root/sudo for raw socket access.
"""

from __future__ import annotations

import os
import time
import logging

from scapy.all import sniff, IP, TCP, UDP, Packet
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


def parse_packet(packet: Packet) -> dict[str, str] | None:
    if IP not in packet:
        return None

    entry: dict[str, str] = {
        "timestamp": str(time.time()),
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

    return entry


def main() -> None:
    r = connect_redis()
    log.info("capturing on %s -> stream:%s (maxlen=%d)", CAPTURE_INTERFACE, STREAM_NAME, STREAM_MAXLEN)

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
