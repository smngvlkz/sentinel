"""
Check-in tracking, for spotting botnet beaconing.

Infected machines keep contacting their controller for instructions: a
new connection to the same server every minute or two, for hours. The
timing alone isn't distinctive (plenty of normal software refreshes on an
exact schedule), but persistence is: normal patterns come in short bursts
or every 10+ minutes, while a bot keeps returning without a break.

So for every (device on this network, internet server, TCP port) this
counts, over the last hour, how many check-ins there were and how many of
the hour's twelve 5-minute slots they touched. Connections opened within a
few seconds of each other count as one check-in.

TCP only: devices using an internet DNS server query it all day, which
would look the same over UDP.
"""

from __future__ import annotations

from collections import deque

from .connections import Connection, is_local

WINDOW = 3600.0
SLOT = 300.0
# Connections this close together are one check-in (a burst of requests).
BURST_GAP = 5.0

BeaconKey = tuple[str, str, str]  # (local host, internet host, port)


class BeaconTracker:

    def __init__(self) -> None:
        self.checkins: dict[BeaconKey, deque[float]] = {}

    @staticmethod
    def key(conn: Connection) -> BeaconKey | None:
        """Which check-in series a connection belongs to, if it's local -> internet over TCP."""
        if conn.protocol != "6" or not is_local(conn.initiator[0]) or is_local(conn.responder[0]):
            return None
        return (conn.initiator[0], conn.responder[0], conn.responder[1])

    def record(self, conn: Connection) -> None:
        """Record a newly opened connection (not one joined mid-stream)."""
        key = self.key(conn)
        if key is None or conn.mid_stream:
            return
        times = self.checkins.get(key)
        if times is None:
            times = self.checkins[key] = deque()
        if times and conn.start - times[-1] <= BURST_GAP:
            return
        times.append(conn.start)
        self._expire(times, conn.start)

    @staticmethod
    def _expire(times: deque[float], now: float) -> None:
        while times and times[0] <= now - WINDOW:
            times.popleft()

    def features(self, conn: Connection, now: float) -> dict[str, float]:
        key = self.key(conn)
        times = self.checkins.get(key) if key else None
        if not times:
            return {"checkins_last_hour": 0, "checkin_slots_last_hour": 0}
        self._expire(times, now)
        start = now - WINDOW
        # Twelve slots; a check-in at exactly `now` belongs to the last one.
        slots = {min(int((t - start) // SLOT), int(WINDOW // SLOT) - 1) for t in times}
        return {"checkins_last_hour": len(times), "checkin_slots_last_hour": len(slots)}

    def cleanup(self, now: float) -> int:
        quiet = [k for k, times in self.checkins.items() if not times or times[-1] <= now - WINDOW]
        for k in quiet:
            del self.checkins[k]
        return len(quiet)
