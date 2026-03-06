"""Packet Capture Service - sniffs network traffic and pushes to Redis Streams."""

import json
import time
import os
import logging

from scapy.all import sniff, IP, TCP, UDP
import redis
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CAPTURE] %(message)s")
logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "en0")
STREAM_NAME = "packet_stream"
STREAM_MAXLEN = 100_000


def create_redis_client():
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    client.ping()
    logger.info("Connected to Redis at %s:%s", REDIS_HOST, REDIS_PORT)
    return client


def process_packet(packet, redis_client):
    if IP not in packet:
        return

    data = {
        "timestamp": str(time.time()),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": str(packet[IP].proto),
        "packet_size": str(len(packet)),
    }

    if TCP in packet:
        data["src_port"] = str(packet[TCP].sport)
        data["dst_port"] = str(packet[TCP].dport)
        data["flags"] = str(packet[TCP].flags)
        data["transport"] = "TCP"
    elif UDP in packet:
        data["src_port"] = str(packet[UDP].sport)
        data["dst_port"] = str(packet[UDP].dport)
        data["flags"] = ""
        data["transport"] = "UDP"
    else:
        data["src_port"] = "0"
        data["dst_port"] = "0"
        data["flags"] = ""
        data["transport"] = "OTHER"

    redis_client.xadd(STREAM_NAME, data, maxlen=STREAM_MAXLEN)


def start_capture():
    redis_client = create_redis_client()
    logger.info("Starting packet capture on interface: %s", CAPTURE_INTERFACE)
    logger.info("Streaming to Redis stream: %s (maxlen=%d)", STREAM_NAME, STREAM_MAXLEN)

    sniff(
        iface=CAPTURE_INTERFACE,
        prn=lambda pkt: process_packet(pkt, redis_client),
        store=0,
    )


if __name__ == "__main__":
    start_capture()
