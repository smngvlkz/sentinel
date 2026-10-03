"""
Garbage-collector settings for the analyzer.

The analyzer holds hundreds of thousands of long-lived objects in its
tables. Python's full collections walk all of them, and under load each one
paused the analyzer for up to 200 ms (Python 3.12, tables full). The tables
have no reference cycles, so reference counting already frees evicted
entries, and a full pass found nothing to free. So only young objects are
collected automatically (cheap, and they catch the short-lived cycles
libraries create), with a full pass once an hour as a safety net.

Measured on Python 3.12, which the analyzer image runs: the worst pause went
from 199 ms to under 10 ms. Python 3.14's incremental collector has no
oldest-generation threshold, so this doesn't change its pauses.
"""

from __future__ import annotations

import gc
import logging
import time

log = logging.getLogger(__name__)

FULL_COLLECT_INTERVAL = 3600.0
# CPython's default young-generation thresholds; the oldest generation's is
# set so high that it never triggers on its own.
_THRESHOLDS = (700, 10, 1_000_000_000)


def tune_gc() -> None:
    """Call once after startup: objects created so far are never scanned again."""
    gc.collect()
    gc.freeze()
    gc.set_threshold(*_THRESHOLDS)


class FullCollector:
    """Runs a full collection at most once an hour, from the analyzer's cleanup step."""

    def __init__(self, interval: float = FULL_COLLECT_INTERVAL) -> None:
        self.interval = interval
        self.last = time.monotonic()

    def maybe_collect(self) -> int | None:
        """Objects freed, or None if it isn't time yet."""
        now = time.monotonic()
        if now - self.last < self.interval:
            return None
        self.last = now
        started = time.perf_counter()
        freed = gc.collect()
        log.info("full garbage collection: %d objects freed in %.0f ms", freed, (time.perf_counter() - started) * 1000)
        return freed
