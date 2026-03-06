"""Simulate network attacks for testing the detection engine.

Run this INSTEAD of real packet capture to test the pipeline without sudo.
Pushes synthetic attack patterns directly into the Redis stream.
"""

import time
import random
import redis
import os
from dotenv import load_dotenv

load_dotenv()

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)

STREAM = "packet_stream"


def normal_traffic():
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


def syn_flood():
    """Lots of SYN packets from one IP, high rate."""
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


def port_scan():
    """Sequential port scanning from one IP."""
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


def run_simulation():
    print("Starting attack simulation...")
    print("Sending normal traffic with periodic attacks")
    print("Press Ctrl+C to stop\n")

    count = 0
    while True:
        # Normal traffic baseline
        for _ in range(10):
            r.xadd(STREAM, normal_traffic(), maxlen=100_000)
            count += 1

        # Every ~5 seconds, inject an attack pattern
        if count % 100 < 30:
            # SYN flood burst
            for _ in range(50):
                r.xadd(STREAM, syn_flood(), maxlen=100_000)
                count += 1
            print(f"[{count}] Injected SYN flood burst")

        if count % 200 < 10:
            # Port scan
            for _ in range(25):
                r.xadd(STREAM, port_scan(), maxlen=100_000)
                count += 1
            print(f"[{count}] Injected port scan")

        time.sleep(0.1)


if __name__ == "__main__":
    run_simulation()
