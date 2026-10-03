"""
Every size-limited table the analyzer keeps, in one place: how full each one
is and how many entries it has dropped. Feeds the `/health` metrics (through
the heartbeat) and the RESOURCE_PRESSURE alert, so the two always agree.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from .feature_extractor import FlowTracker

if TYPE_CHECKING:
    from alert_service.alert_manager import AlertManager
    from detection_engine.detector import DetectionEngine

    from .names import NameCache

# (entries now, cap, entries dropped since start)
Row = tuple[int, int, int]


class Tables:

    def __init__(
        self,
        tracker: FlowTracker,
        detector: DetectionEngine | None = None,
        alerts: AlertManager | None = None,
        names: NameCache | None = None,
    ) -> None:
        self.tracker = tracker
        self.detector = detector
        self.alerts = alerts
        self.names = names

    def snapshot(self) -> dict[str, Row]:
        t = self.tracker
        rows = {
            "flows": (len(t.flows), t.flows.cap, t.flows.evicted),
            "connections": (len(t.connections.connections), t.connections.max_connections, t.connections.evicted),
            "hosts": (len(t.hosts.hosts), t.hosts.hosts.cap, t.hosts.hosts.evicted),
            "services": (len(t.hosts.services), t.hosts.services.cap, t.hosts.services.evicted),
            "sweeps": (len(t.hosts.sweeps), t.hosts.sweeps.cap, t.hosts.sweeps.evicted),
            "beacon_series": (len(t.beacons.checkins), t.beacons.max_series, t.beacons.evicted),
        }
        if self.detector is not None:
            d = self.detector
            rows["judged_flows"] = (d.judged_flows, d.max_judged, d.evicted)
        if self.alerts is not None:
            a = self.alerts
            rows["alert_cooldowns"] = (a.cooldowns, a.max_recent, a.evicted)
        if self.names is not None:
            n = self.names
            rows["names"] = (len(n), n.max_entries, n.evicted)
        return rows


class TableReport:
    """Per-table size, cap and entries dropped over roughly the last minute, for the heartbeat."""

    def __init__(self, tables: Tables, window: float = 60.0) -> None:
        self.tables = tables
        self.window = window
        # (time, dropped totals); the first is the newest sample at least `window` old.
        self._samples: deque[tuple[float, dict[str, int]]] = deque()

    def report(self, now: float) -> dict[str, dict[str, int]]:
        snapshot = self.tables.snapshot()
        totals = {name: row[2] for name, row in snapshot.items()}
        self._samples.append((now, totals))
        while len(self._samples) > 1 and now - self._samples[1][0] >= self.window:
            self._samples.popleft()
        base = self._samples[0][1]
        return {
            name: {"size": size, "cap": cap, "evicted_last_minute": evicted - base.get(name, evicted)}
            for name, (size, cap, evicted) in snapshot.items()
        }
