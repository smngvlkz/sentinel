"""
Attack traffic simulator for testing.

Generates synthetic network packets and pushes them into the Redis
stream. Use this to verify the detection pipeline without needing
root access for real packet capture.

Usage:
    python scripts/simulate_attack.py
"""

import os
import time
import random

import redis
from dotenv import load_dotenv

load_dotenv()

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)

STREAM = "packet_stream"
MAXLEN = 100_000


def normal_packet():
    return {
        "timestamp": str(time.time()),
        "src_ip": f"192.168.1.{random.randint(2, 50)}",
        "dst_ip": f"10.0.0.{random.randint(1, 10)}",
        "src_port": str(random.randint(49152, 65535)),
        "dst_port": str(random.choice([80, 443, 8080, 3000])),
        "packet_size": str(random.randint(64, 1500)),
        "flags": random.choice(["S", "SA", "A", "PA", "FA"]),
        "protocol": "6",
        "transport": "TCP",
    }


def syn_flood_packet():
    return {
        "timestamp": str(time.time()),
        "src_ip": "10.99.99.99",
        "dst_ip": "192.168.1.1",
        "src_port": str(random.randint(1024, 65535)),
        "dst_port": "80",
        "packet_size": str(random.randint(40, 60)),
        "flags": "S",
        "protocol": "6",
        "transport": "TCP",
    }


def port_scan_packet():
    return {
        "timestamp": str(time.time()),
        "src_ip": "10.88.88.88",
        "dst_ip": "192.168.1.1",
        "src_port": str(random.randint(49152, 65535)),
        "dst_port": str(random.randint(1, 1024)),
        "packet_size": str(random.randint(40, 80)),
        "flags": "S",
        "protocol": "6",
        "transport": "TCP",
    }


def main():
    print("Injecting simulated traffic (Ctrl+C to stop)")
    count = 0

    while True:
        for _ in range(10):
            r.xadd(STREAM, normal_packet(), maxlen=MAXLEN)
            count += 1

        if count % 100 < 30:
            for _ in range(50):
                r.xadd(STREAM, syn_flood_packet(), maxlen=MAXLEN)
                count += 1

        if count % 200 < 10:
            for _ in range(25):
                r.xadd(STREAM, port_scan_packet(), maxlen=MAXLEN)
                count += 1

        time.sleep(0.1)


if __name__ == "__main__":
    main()
