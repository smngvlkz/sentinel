"""
An alert for when the analyzer's own tables fill up.

Every table has a hard cap (`[limits]` in config/detection.toml), set far
above anything real traffic reaches. So a table dropping entries means
something unusual is happening, most likely a flood of made-up addresses.
That's worth an alert in itself: it means detection may be degraded, and an
attacker could be doing it on purpose to hide something else.
"""

from __future__ import annotations

from collections.abc import Callable

from .feature_extractor import FlowTracker

THREAT_TYPE = "RESOURCE_PRESSURE"
# At most one alert this often while the pressure lasts.
REPEAT_SECONDS = 600.0


class PressureMonitor:
    """Turns eviction counts from every table into at most one alert per `repeat` seconds."""

    def __init__(self, tracker: FlowTracker, extra: dict[str, Callable[[], int]] | None = None,
                 repeat: float = REPEAT_SECONDS) -> None:
        self.tracker = tracker
        # Tables outside the tracker (the detector's, the alert manager's).
        self.extra = extra or {}
        self.repeat = repeat
        self.last_counts = self.counts()
        self.last_alert: float | None = None

    def counts(self) -> dict[str, int]:
        t = self.tracker
        counts = {
            "flows": t.evicted,
            "connections": t.connections.evicted,
            **t.hosts.evicted,
            "beacon_series": t.beacons.evicted,
        }
        counts.update({name: read() for name, read in self.extra.items()})
        return counts

    def check(self, now: float) -> tuple[dict, dict[str, str], dict[str, float]] | None:
        """
        Call once a minute. Returns (threat, packet, features) for the alert
        manager if any table dropped entries since the last call and no
        alert went out in the last `repeat` seconds.
        """
        counts = self.counts()
        dropped = {name: counts[name] - self.last_counts.get(name, 0) for name in counts}
        self.last_counts = counts
        total = sum(dropped.values())
        if not total or (self.last_alert is not None and now - self.last_alert < self.repeat):
            return None
        self.last_alert = now

        busiest, peers, latest_peer = self.tracker.hosts.busiest(now)
        threat = {
            "type": THREAT_TYPE,
            "source": "system",
            "confidence": 1.0,
            "cooldown": self.repeat,
            "group": "all",
            "source_ip": latest_peer or "",
            "destination_ip": busiest or "",
        }
        packet = {"timestamp": str(now), "src_ip": latest_peer or "", "dst_ip": busiest or ""}
        features: dict[str, float] = {
            "evicted_last_minute": total,
            "tables_dropping": sum(1 for n in dropped.values() if n),
            "busiest_peers_60s": peers,
        }
        features.update({f"evicted_{name}": n for name, n in dropped.items() if n})
        return threat, packet, features
