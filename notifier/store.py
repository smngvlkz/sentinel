"""
The notifier's database work. Everything the notifier remembers is here, so
a restart carries on where it left off: how far through the alerts it has
got, alerts waiting for a summary, and messages waiting to be sent or retried.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import psycopg2.extras

# Notifications and handled test requests older than this are deleted.
KEEP_DAYS = 30

ALERT_COLUMNS = """alerts.id, alerts.timestamp, alerts.threat_type, alerts.source_ip, alerts.destination_ip,
                   alerts.source_name, alerts.destination_name,
                   sd.name AS source_device, dd.name AS destination_device"""
ALERT_JOINS = """LEFT JOIN device_names sd ON sd.ip = alerts.source_ip
                 LEFT JOIN device_names dd ON dd.ip = alerts.destination_ip"""


class Store:

    def __init__(self, conn) -> None:
        self.conn = conn

    def _cur(self):
        return self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def position(self) -> int:
        """The last alert already dealt with. On the first start, the newest alert now."""
        with self.conn, self._cur() as cur:
            cur.execute("SELECT last_alert_id FROM notifier_state WHERE id = 1")
            row = cur.fetchone()
            if row is not None:
                return int(row["last_alert_id"])
            cur.execute("SELECT COALESCE(MAX(id), 0) AS id FROM alerts")
            newest = int(cur.fetchone()["id"])
            cur.execute(
                "INSERT INTO notifier_state (id, last_alert_id) VALUES (1, %s) ON CONFLICT (id) DO NOTHING",
                [newest],
            )
        return newest

    def new_alerts(self, after_id: int, limit: int = 500) -> list[dict[str, Any]]:
        with self.conn, self._cur() as cur:
            cur.execute(
                f"SELECT {ALERT_COLUMNS} FROM alerts {ALERT_JOINS} WHERE alerts.id > %s ORDER BY alerts.id LIMIT %s",
                [after_id, limit],
            )
            return [dict(r) for r in cur.fetchall()]

    def messages_in_last_hour(self, now: dt.datetime) -> int:
        """Alert and summary messages queued in the hour before `now` (tests don't count)."""
        with self.conn, self._cur() as cur:
            cur.execute(
                """SELECT COUNT(DISTINCT message_id) AS n FROM notifications
                   WHERE kind IN ('alert', 'digest') AND created_at > %s""",
                [now - dt.timedelta(hours=1)],
            )
            return int(cur.fetchone()["n"])

    def notified_since(self, keys: list[str], since: dt.datetime) -> set[str]:
        """Which of these repeat keys had an alert notification queued after `since`."""
        if not keys:
            return set()
        with self.conn, self._cur() as cur:
            cur.execute(
                """SELECT DISTINCT message->>'repeat_key' AS key FROM notifications
                   WHERE kind = 'alert' AND created_at > %s AND message->>'repeat_key' = ANY(%s)""",
                [since, keys],
            )
            return {r["key"] for r in cur.fetchall()}

    def commit_batch(
        self,
        last_alert_id: int,
        messages: list[tuple[str, list[int], dict[str, str]]],
        held: list[int],
        channels: list[str],
        now: dt.datetime,
    ) -> None:
        """
        In one transaction: queue `messages` (kind, alert ids, message) for
        every channel, hold `held` alerts for the next summary, and move the
        position on. A crash part-way leaves none of it, so the batch is
        redone rather than half-sent.
        """
        with self.conn, self._cur() as cur:
            for kind, alert_ids, message in messages:
                self._queue(cur, kind, alert_ids, message, channels, now)
            if held:
                cur.execute(
                    "INSERT INTO notification_digest (alert_id) SELECT unnest(%s::bigint[]) ON CONFLICT DO NOTHING",
                    [held],
                )
            cur.execute(
                "UPDATE notifier_state SET last_alert_id = %s, updated_at = NOW() WHERE id = 1",
                [last_alert_id],
            )

    @staticmethod
    def _queue(cur, kind: str, alert_ids: list[int], message: dict[str, str], channels: list[str], now) -> None:
        cur.execute("SELECT nextval('notification_message_seq') AS id")
        message_id = cur.fetchone()["id"]
        for channel in channels:
            cur.execute(
                """INSERT INTO notifications (message_id, kind, channel, alert_ids, message, created_at, next_attempt_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                [message_id, kind, channel, alert_ids, json.dumps(message), now, now],
            )

    def held_alerts(self) -> list[dict[str, Any]]:
        with self.conn, self._cur() as cur:
            cur.execute(
                f"""SELECT {ALERT_COLUMNS} FROM notification_digest d
                    JOIN alerts ON alerts.id = d.alert_id {ALERT_JOINS} ORDER BY alerts.id"""
            )
            rows = [dict(r) for r in cur.fetchall()]
            # Alerts deleted by retention while held are just dropped.
            cur.execute("DELETE FROM notification_digest WHERE alert_id NOT IN (SELECT id FROM alerts)")
            return rows

    def queue_digest(self, alert_ids: list[int], message: dict[str, str], channels: list[str], now) -> None:
        with self.conn, self._cur() as cur:
            self._queue(cur, "digest", alert_ids, message, channels, now)
            cur.execute("DELETE FROM notification_digest WHERE alert_id = ANY(%s)", [alert_ids])

    def queue_tests(self, message: dict[str, str], channels: list[str], now) -> int:
        """Queue a test message for every unhandled test request; returns how many there were."""
        with self.conn, self._cur() as cur:
            cur.execute("UPDATE notification_tests SET handled_at = NOW() WHERE handled_at IS NULL RETURNING id")
            n = len(cur.fetchall())
            if n and channels:
                self._queue(cur, "test", [], message, channels, now)
            return n

    def due(self, now: dt.datetime, limit: int = 50) -> list[dict[str, Any]]:
        with self.conn, self._cur() as cur:
            cur.execute(
                """SELECT id, kind, channel, message, attempts FROM notifications
                   WHERE status = 'pending' AND next_attempt_at <= %s ORDER BY id LIMIT %s""",
                [now, limit],
            )
            return [dict(r) for r in cur.fetchall()]

    def mark_sent(self, row_id: int, now: dt.datetime) -> None:
        with self.conn, self._cur() as cur:
            cur.execute(
                "UPDATE notifications SET status = 'sent', attempts = attempts + 1, sent_at = %s WHERE id = %s",
                [now, row_id],
            )

    def mark_failed_attempt(self, row_id: int, error: str, retry_at: dt.datetime | None) -> None:
        """Record a failed send: retry at `retry_at`, or give up when it's None."""
        with self.conn, self._cur() as cur:
            cur.execute(
                """UPDATE notifications SET attempts = attempts + 1, last_error = %s,
                       status = CASE WHEN %s::timestamptz IS NULL THEN 'failed' ELSE 'pending' END,
                       next_attempt_at = COALESCE(%s::timestamptz, next_attempt_at)
                   WHERE id = %s""",
                [error[:500], retry_at, retry_at, row_id],
            )

    def prune(self, now: dt.datetime) -> None:
        cutoff = now - dt.timedelta(days=KEEP_DAYS)
        with self.conn, self._cur() as cur:
            cur.execute("DELETE FROM notifications WHERE created_at < %s AND status <> 'pending'", [cutoff])
            cur.execute("DELETE FROM notification_tests WHERE handled_at < %s", [cutoff])
