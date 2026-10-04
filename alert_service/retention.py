"""
Deleting old alerts, so the database can't fill the disk.

Two limits, from `[retention]` in config/detection.toml:
- alerts older than `max_age_days` are deleted (checked hourly);
- at most `max_alerts` are kept, newest first (checked every minute). That's
  the backstop for a flood of alerts, which can arrive by the thousand a
  second when an attacker sets out to cause them.

It runs in a background thread with its own database connection, deleting in
small batches, so the analyzer keeps processing packets meanwhile. After a
large delete it runs VACUUM, so Postgres reuses the freed space instead of
growing the files: the database stays about the size of `max_alerts` alerts
however long a flood lasts.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import psycopg2

log = logging.getLogger(__name__)

BATCH = 10_000
CAP_INTERVAL = 60.0
AGE_INTERVAL = 3600.0
# VACUUM after deleting at least this share of max_alerts in one pass.
VACUUM_SHARE = 0.1


def delete_old(cur, max_age_days: float) -> int:
    """Delete alerts older than `max_age_days`, oldest first, in batches."""
    deleted = 0
    while True:
        cur.execute(
            """DELETE FROM alerts WHERE id IN (
                   SELECT id FROM alerts WHERE timestamp < NOW() - make_interval(secs => %s)
                   ORDER BY id LIMIT %s)""",
            [max_age_days * 86_400, BATCH],
        )
        deleted += cur.rowcount
        if cur.rowcount < BATCH:
            return deleted


def delete_over_cap(cur, max_alerts: int) -> int:
    """
    Keep only the newest `max_alerts` alerts. Finds the cutoff by walking
    back `max_alerts` entries on the id index, so gaps in the ids (a restore,
    a skipped sequence range) can never make it delete alerts it should keep.
    """
    cur.execute("SELECT id FROM alerts ORDER BY id DESC OFFSET %s LIMIT 1", [max_alerts])
    row = cur.fetchone()
    if row is None:
        return 0
    cutoff = row[0]  # the newest alert past the limit: it and everything older goes
    deleted = 0
    while True:
        cur.execute(
            "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE id <= %s ORDER BY id LIMIT %s)",
            [cutoff, BATCH],
        )
        deleted += cur.rowcount
        if cur.rowcount < BATCH:
            return deleted


class Retention:

    def __init__(self, dsn: dict[str, Any], max_age_days: float, max_alerts: int) -> None:
        self.dsn = dsn
        self.max_age_days = float(max_age_days)
        self.max_alerts = max(1, int(max_alerts))
        self.last_age_check = 0.0
        self.deleted_total = 0

    def run_once(self, conn, check_age: bool = True) -> tuple[int, int]:
        """(deleted for age, deleted over the cap); VACUUMs after a large delete."""
        with conn.cursor() as cur:
            by_age = delete_old(cur, self.max_age_days) if check_age else 0
            over_cap = delete_over_cap(cur, self.max_alerts)
            deleted = by_age + over_cap
            if deleted:
                log.info(
                    "retention: deleted %d alerts (%d older than %g days, %d over the %d limit)",
                    deleted, by_age, self.max_age_days, over_cap, self.max_alerts,
                )
            if deleted >= self.max_alerts * VACUUM_SHARE:
                # No parallel workers: they share memory through /dev/shm,
                # which Docker limits to 64 MB, and a large VACUUM then fails
                # with "could not resize shared memory segment".
                cur.execute("VACUUM (PARALLEL 0) alerts")
        self.deleted_total += deleted
        return by_age, over_cap

    def loop(self, stop: threading.Event) -> None:
        conn = None
        while not stop.is_set():
            try:
                if conn is None or conn.closed:
                    conn = psycopg2.connect(**self.dsn)
                    conn.autocommit = True
                now = time.monotonic()
                check_age = now - self.last_age_check >= AGE_INTERVAL
                self.run_once(conn, check_age=check_age)
                if check_age:
                    self.last_age_check = now
            except psycopg2.Error as e:
                log.warning("retention: database error, retrying in a minute: %s", e)
                try:
                    if conn is not None:
                        conn.close()
                except psycopg2.Error:
                    pass
                conn = None
            stop.wait(CAP_INTERVAL)

    def start(self) -> threading.Event:
        """Run in a daemon thread; set the returned event to stop it."""
        stop = threading.Event()
        threading.Thread(target=self.loop, args=(stop,), name="retention", daemon=True).start()
        log.info("retention: keeping alerts for %g days, at most %d", self.max_age_days, self.max_alerts)
        return stop
