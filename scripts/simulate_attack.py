"""
Attack traffic simulator.

Pushes synthetic packets into the Redis stream so you can see SentinelAI
detect threats without root access or real packet capture. `make demo`
runs this in Docker; you can also run it directly:

    python scripts/simulate_attack.py

Background traffic flows constantly. Every minute the simulator replays
one of each attack against a pretend machine on your network. Attackers
use the documentation-only ranges 203.0.113.0/24 and 198.51.100.0/24
(RFC 5737), so demo alerts can never be mistaken for real hosts.
"""

import os
import random
import time

import redis
from dotenv import load_dotenv

load_dotenv()

STREAM = "packet_stream"
MAXLEN = 100_000
TICK = 0.1
CYCLE = 60
VICTIM = "192.168.1.10"

SYN_FLOOD_SRC = "203.0.113.66"
PORT_SCAN_SRC = "198.51.100.23"
LARGE_PAYLOAD_SRC = "203.0.113.140"
HIGH_FREQ_SRC = "198.51.100.77"
REQUEST_FLOOD_SRC = "198.51.100.44"
# A compromised device on your network, for the sweep.
SWEEP_SRC = "192.168.1.66"


def packet(src, dst, dst_port, size, flags="", transport="TCP", src_port=None):
    return {
        "timestamp": str(time.time()),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": str(src_port if src_port is not None else random.randint(49152, 65535)),
        "dst_port": str(dst_port),
        "packet_size": str(size),
        "flags": flags,
        "protocol": "6" if transport == "TCP" else "17",
        "transport": transport,
    }


def handshake(src, dst, dst_port):
    """A completed TCP connection: SYN, SYN-ACK, ACK on matching ports."""
    sport = random.randint(49152, 65535)
    return [
        packet(src, dst, dst_port, 60, "S", src_port=sport),
        packet(dst, src, sport, 60, "SA", src_port=dst_port),
        packet(src, dst, dst_port, 52, "A", src_port=sport),
    ]


def background():
    return packet(
        f"192.168.1.{random.randint(20, 40)}",
        random.choice(["93.184.216.34", "142.250.72.14", "151.101.1.69"]),
        random.choice([443, 443, 443, 80, 53]),
        random.randint(64, 1500),
        random.choice(["A", "A", "PA", "PA", "S", "FA"]),
    )


def attacks_for(second, scan_port):
    """Packets to add this tick, based on where we are in the one-minute cycle."""
    if 0 <= second < 5:
        return [packet(SYN_FLOOD_SRC, VICTIM, 80, random.randint(40, 60), "S") for _ in range(40)]
    if 15 <= second < 18:
        return [packet(PORT_SCAN_SRC, VICTIM, scan_port + i, 60, "S") for i in range(8)]
    if 30 <= second < 30 + TICK:
        return [packet(LARGE_PAYLOAD_SRC, VICTIM, 9999, 15_000, transport="UDP")]
    if 40 <= second < 43:
        return [packet(HIGH_FREQ_SRC, VICTIM, 53, 128, transport="UDP") for _ in range(150)]
    if 20 <= second < 24:
        # Request flood: 200 completed connections a second to the web server.
        return [p for _ in range(20) for p in handshake(REQUEST_FLOOD_SRC, VICTIM, 80)]
    if 46 <= second < 47:
        # Distributed flood: 80 different internet hosts in one second.
        return [packet(f"198.51.100.{150 + i}", VICTIM, 443, 60, "S") for i in range(8 * int((second - 46) * 10), 8 * int((second - 46) * 10) + 8)]
    if 52 <= second < 54:
        # Network sweep: a local device trying Windows file sharing on 40 others.
        start = 2 * int((second - 52) * 10)
        return [packet(SWEEP_SRC, f"192.168.1.{100 + i}", 445, 60, "S") for i in range(start, start + 2)]
    return []


def connect():
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", 6379))
    while True:
        try:
            r = redis.Redis(host=host, port=port, decode_responses=True)
            r.ping()
            return r
        except redis.ConnectionError:
            print(f"Waiting for Redis at {host}:{port}...", flush=True)
            time.sleep(2)


def main():
    r = connect()
    print(
        f"Simulating traffic. Attacks against {VICTIM} repeat every {CYCLE}s.\n"
        "Open the dashboard to watch them get detected. Ctrl+C to stop.",
        flush=True,
    )
    start = time.time()
    scan_port = 1

    while True:
        second = (time.time() - start) % CYCLE
        batch = [background() for _ in range(10)] + attacks_for(second, scan_port)
        if 15 <= second < 18:
            scan_port = scan_port + 8 if scan_port < 1000 else 1

        pipe = r.pipeline()
        for p in batch:
            pipe.xadd(STREAM, p, maxlen=MAXLEN, approximate=True)
        try:
            pipe.execute()
        except redis.ConnectionError:
            r = connect()

        time.sleep(TICK)


if __name__ == "__main__":
    main()
