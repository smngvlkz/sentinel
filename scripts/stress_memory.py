#!/usr/bin/env python3
"""
Stress test for the analyzer's memory caps (roadmap 1.1).

1. Flood: N connections from unique spoofed internet addresses at a steady
   rate, through the analyzer's real tracker and rules. Memory should level
   off once the caps fill, and no single packet or cleanup should stall the
   analyzer for long.
2. Hidden scan: a slow port scan running underneath the same kind of flood.
   The flood churns the tables, so this measures whether it can push the
   scan out of memory before it's caught.

    make stress                                        # 10 million, in the analyzer image
    python scripts/stress_memory.py --connections 1000000

Run it in the analyzer image (`make stress`) for numbers that match the
real analyzer: pauses depend on the Python version's garbage collector.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker  # noqa: E402
from analysis_service.gc_tuning import tune_gc  # noqa: E402
from detection_engine.config import load_config  # noqa: E402
from detection_engine.rules import RuleEngine  # noqa: E402

VICTIM = "192.168.1.10"
SCANNER = "198.51.100.23"
CLEANUP_INTERVAL = 60.0  # packet time, as in the analyzer and evaluate.py


def rss_mb() -> float:
    """Current resident memory: /proc on Linux (the Docker image has no ps), ps elsewhere."""
    try:
        with open("/proc/self/status") as f:
            return next(int(line.split()[1]) for line in f if line.startswith("VmRSS:")) / 1024
    except OSError:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())], capture_output=True, text=True).stdout
        return int(out.strip()) / 1024


def spoofed(i: int) -> str:
    """A different internet address for each i, up to about 200 million."""
    return f"{11 + i // 16_581_375 % 200}.{i // 65_025 % 255}.{i // 255 % 255}.{i % 255 + 1}"


def packet(t: float, src: str, sport: int, dst: str, dport: int, flags: str = "S") -> dict[str, str]:
    return {"timestamp": f"{t:.6f}", "src_ip": src, "src_port": str(sport), "dst_ip": dst,
            "dst_port": str(dport), "protocol": "6", "packet_size": "60", "flags": flags, "transport": "TCP"}


def tables(t: FlowTracker) -> dict[str, int]:
    return {
        "flows": len(t.flows),
        "connections": len(t.connections.connections),
        "hosts": len(t.hosts.hosts),
        "services": len(t.hosts.services),
        "ip counts": len(t.ip_connection_counts),
    }


def flood(n: int, rate: float, config: dict) -> bool:
    tracker = FlowTracker(limits=config["limits"], handshake_seconds=config["syn_flood"]["handshake_seconds"])
    rules = RuleEngine(config)
    print(f"Flood: {n:,} connections from unique spoofed addresses at {rate:,.0f}/s of packet time")
    start_rss = rss_mb()
    checkpoints = []
    worst_packet = worst_cleanup = 0.0
    last_cleanup = 0.0
    started = time.perf_counter()
    step = max(n // 10, 1)
    for i in range(n):
        now = i / rate
        if now - last_cleanup > CLEANUP_INTERVAL:
            c0 = time.perf_counter()
            tracker.cleanup_stale(now)
            worst_cleanup = max(worst_cleanup, time.perf_counter() - c0)
            last_cleanup = now
        p0 = time.perf_counter()
        rules.evaluate(tracker.update(packet(now, spoofed(i), 1024 + i % 60_000, VICTIM, 80)))
        worst_packet = max(worst_packet, time.perf_counter() - p0)
        if (i + 1) % step == 0:
            checkpoints.append((i + 1, rss_mb()))
            print(f"  {i + 1:>12,}  RSS {checkpoints[-1][1]:7.0f} MB  {tables(tracker)}")
    elapsed = time.perf_counter() - started
    # Flat: the last half of the run grew by less than 5% of the peak.
    half = checkpoints[len(checkpoints) // 2][1]
    peak = max(mb for _, mb in checkpoints)
    flat = checkpoints[-1][1] - half < 0.05 * peak
    print(f"  {n / elapsed:,.0f} packets/s; memory +{peak - start_rss:,.0f} MB at peak, "
          f"{'flat' if flat else 'STILL GROWING'} over the second half")
    print(f"  slowest packet {worst_packet * 1000:.1f} ms, slowest cleanup {worst_cleanup * 1000:.1f} ms")
    print(f"  evicted: flows {tracker.evicted:,}, connections {tracker.connections.evicted:,}, "
          f"{', '.join(f'{k} {v:,}' for k, v in tracker.hosts.evicted.items())}")
    return flat


def hidden_scan(flood_rate: float, scan_interval: float, config: dict) -> float | None:
    """Seconds until the scan is caught under the flood, or None if it never is."""
    tracker = FlowTracker(limits=config["limits"], handshake_seconds=config["syn_flood"]["handshake_seconds"])
    rules = RuleEngine(config)
    needed = int(config["port_scan"]["min_unique_ports"]) + 1
    next_scan, port, i, now = 0.0, 1, 0, 0.0
    last_cleanup = 0.0
    while port <= needed * 3:
        if now - last_cleanup > CLEANUP_INTERVAL:
            tracker.cleanup_stale(now)
            last_cleanup = now
        if now >= next_scan:
            if "PORT_SCAN" in rules.evaluate(tracker.update(packet(now, SCANNER, 40000, VICTIM, port))):
                return now
            port += 1
            next_scan += scan_interval
        tracker.update(packet(now, spoofed(i), 1024 + i % 60_000, VICTIM, 80))
        i += 1
        now = i / flood_rate
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--connections", type=int, default=10_000_000)
    ap.add_argument("--rate", type=float, default=20_000, help="flood connections per second of packet time")
    args = ap.parse_args()
    config = load_config()
    tune_gc()  # the analyzer's own garbage-collector settings

    flat = flood(args.connections, args.rate, config)

    print("\nHidden scan: one port at a time under a spoofed flood "
          f"(caught at {int(config['port_scan']['min_unique_ports']) + 1} ports)")
    for rate in (1_000, 20_000, 50_000):
        for interval in (0.5, 2.0, 5.0, 10.0):
            caught = hidden_scan(rate, interval, config)
            result = f"caught after {caught:.0f} s" if caught is not None else "MISSED"
            print(f"  flood {rate:>6,}/s, a port every {interval:>3} s: {result}")

    sys.exit(0 if flat else 1)


if __name__ == "__main__":
    main()
