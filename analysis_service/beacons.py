"""
Check-in tracking, for spotting botnet beaconing.

Infected machines keep contacting their controller for instructions: a
new connection to the same server every minute or two, for hours. The
timing has two marks. Persistence: normal patterns come in short bursts or
every 10+ minutes, while a bot keeps returning without a break. And
regularity: a bot sleeps a fixed time between check-ins, while an app
talking to its server all day (an editor, a chat app, a busy web page)
reconnects whenever the person does something.

So for every (device on this network, internet server, TCP port) this
counts, over the last hour, how many check-ins there were, how many of the
hour's twelve 5-minute slots they touched, and what share of the gaps
between them were close to the usual gap. Connections opened within a few
seconds of each other count as one check-in.

Some normal software (an update checker) is just as regular, and a bot that
randomises its timing isn't, so regularity narrows the alerts down rather
than proving anything.

TCP only: devices using an internet DNS server query it all day, which
would look the same over UDP.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable

from .connections import _LIMITS, Connection, is_local

WINDOW = 3600.0
SLOT = 300.0
# Connections this close together are one check-in (a burst of requests).
BURST_GAP = 5.0
# A gap counts as regular when it's within this share of the usual (median)
# gap, or within REGULAR_SECONDS for short gaps where timer jitter dominates.
REGULAR_SHARE = 0.1
REGULAR_SECONDS = 2.0

BeaconKey = tuple[str, str, str]  # (local host, internet host, port)


class BeaconTracker:

    def __init__(self, max_series: int = _LIMITS["max_beacon_series"]) -> None:
        # In order of last check-in, oldest first.
        self.checkins: OrderedDict[BeaconKey, deque[float]] = OrderedDict()
        self.max_series = max(1, int(max_series))
        self.evicted = 0

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
            while len(self.checkins) > self.max_series:
                self.checkins.popitem(last=False)
                self.evicted += 1
        if times and conn.start - times[-1] <= BURST_GAP:
            return
        times.append(conn.start)
        self.checkins.move_to_end(key)
        self._expire(times, conn.start)

    @staticmethod
    def _expire(times: deque[float], now: float) -> None:
        while times and times[0] <= now - WINDOW:
            times.popleft()

    def features(self, conn: Connection, now: float) -> dict[str, float]:
        key = self.key(conn)
        times = self.checkins.get(key) if key else None
        if not times:
            return {"checkins_last_hour": 0, "checkin_slots_last_hour": 0, "checkin_regularity": 0.0}
        self._expire(times, now)
        start = now - WINDOW
        # Twelve slots; a check-in at exactly `now` belongs to the last one.
        slots = {min(int((t - start) // SLOT), int(WINDOW // SLOT) - 1) for t in times}
        return {
            "checkins_last_hour": len(times),
            "checkin_slots_last_hour": len(slots),
            "checkin_regularity": regularity(times),
        }

    def cleanup(self, now: float) -> int:
        quiet = 0
        while self.checkins:
            times = next(iter(self.checkins.values()))
            if times and times[-1] > now - WINDOW:
                break
            self.checkins.popitem(last=False)
            quiet += 1
        return quiet


def regularity(times: Iterable[float]) -> float:
    """Share of the gaps between check-ins that are close to the median gap (0-1)."""
    t = list(times)
    gaps = sorted(b - a for a, b in zip(t, t[1:]))
    if len(gaps) < 2:
        return 0.0
    mid = len(gaps) // 2
    median = gaps[mid] if len(gaps) % 2 else (gaps[mid - 1] + gaps[mid]) / 2
    tolerance = max(REGULAR_SECONDS, REGULAR_SHARE * median)
    return sum(abs(g - median) <= tolerance for g in gaps) / len(gaps)
