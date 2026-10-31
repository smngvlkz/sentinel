"""
Triage's database work. Everything triage remembers is here, so a restart
carries on where it left off: how far through the alerts it has got, the
groups still collecting alerts, and those waiting for the model.

Triage reads alerts and writes only its own tables (triage, triage_state).
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import psycopg2.extras

from .groups import GAP, Group, Key

# Triage only reads the columns the model is shown, plus what groups them.
ALERT_COLUMNS = """id, timestamp, threat_type, source_ip, destination_ip, source_port, destination_port,
                   confidence, detection_source, features, source_name, destination_name"""
GROUP_COLUMNS = """id, threat_type, source_ip, destination_ip, first_alert_id, last_alert_id, first_at, last_at,
                   alert_count"""


class Store:

    def __init__(self, conn) -> None:
        self.conn = conn

    def _cur(self):
        return self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def position(self) -> int:
        """The last alert already grouped. On the first start, the newest alert now."""
        with self.conn, self._cur() as cur:
            cur.execute("SELECT last_alert_id FROM triage_state WHERE id = 1")
            row = cur.fetchone()
            if row is not None:
                return int(row["last_alert_id"])
            cur.execute("SELECT COALESCE(MAX(id), 0) AS id FROM alerts")
            newest = int(cur.fetchone()["id"])
            cur.execute(
                "INSERT INTO triage_state (id, last_alert_id) VALUES (1, %s) ON CONFLICT (id) DO NOTHING", [newest]
            )
        return newest

    def newest_alert(self) -> int:
        with self.conn, self._cur() as cur:
            cur.execute("SELECT COALESCE(MAX(id), 0) AS id FROM alerts")
            return int(cur.fetchone()["id"])

    def new_alerts(self, after_id: int, limit: int = 500) -> list[dict[str, Any]]:
        with self.conn, self._cur() as cur:
            cur.execute(
                "SELECT id, timestamp, threat_type, source_ip, destination_ip FROM alerts"
                " WHERE id > %s ORDER BY id LIMIT %s",
                [after_id, limit],
            )
            return [dict(r) for r in cur.fetchall()]

    def open_groups(self) -> dict[Key, Group]:
        with self.conn, self._cur() as cur:
            cur.execute(f"SELECT {GROUP_COLUMNS} FROM triage WHERE status = 'open'")
            groups = [Group(**{k: r[k] for k in r if k != "id"}, id=int(r["id"])) for r in cur.fetchall()]
        return {g.key: g for g in groups}

    def save_batch(self, last_alert_id: int, closed: list[Group], changed: list[Group]) -> None:
        """Store the groups a batch of alerts changed, and move past it, in one transaction."""
        with self.conn, self._cur() as cur:
            for group, status in [(g, "waiting") for g in closed] + [(g, "open") for g in changed]:
                values = [group.last_alert_id, group.last_at, group.alert_count, status]
                if group.id is None:
                    cur.execute(
                        """INSERT INTO triage (threat_type, source_ip, destination_ip, first_alert_id, first_at,
                                               last_alert_id, last_at, alert_count, status, next_attempt_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()) RETURNING id""",
                        [group.threat_type, group.source_ip, group.destination_ip, group.first_alert_id,
                         group.first_at, *values],
                    )
                    group.id = int(cur.fetchone()["id"])
                else:
                    cur.execute(
                        """UPDATE triage SET last_alert_id = %s, last_at = %s, alert_count = %s, status = %s,
                                  next_attempt_at = NOW() WHERE id = %s""",
                        [*values, group.id],
                    )
            cur.execute(
                """INSERT INTO triage_state (id, last_alert_id, updated_at) VALUES (1, %s, NOW())
                   ON CONFLICT (id) DO UPDATE SET last_alert_id = EXCLUDED.last_alert_id, updated_at = NOW()""",
                [last_alert_id],
            )

    def skip_to(self, alert_id: int) -> None:
        """Triage is off: move past these alerts, and drop groups it was collecting."""
        with self.conn, self._cur() as cur:
            cur.execute("UPDATE triage SET status = 'skipped', last_error = 'triage was turned off'"
                        " WHERE status IN ('open', 'waiting')")
            cur.execute(
                """INSERT INTO triage_state (id, last_alert_id, updated_at) VALUES (1, %s, NOW())
                   ON CONFLICT (id) DO UPDATE SET last_alert_id = EXCLUDED.last_alert_id, updated_at = NOW()""",
                [alert_id],
            )

    def close_quiet(self, now: dt.datetime) -> int:
        """Groups with no alert for GAP are done collecting: they wait for the model."""
        with self.conn, self._cur() as cur:
            cur.execute(
                "UPDATE triage SET status = 'waiting', next_attempt_at = %s WHERE status = 'open' AND last_at < %s",
                [now, now - GAP],
            )
            return cur.rowcount

    def skip_stale(self, now: dt.datetime, older_than: dt.timedelta) -> int:
        """Groups that have waited too long are skipped, so a backlog can't build up forever."""
        with self.conn, self._cur() as cur:
            cur.execute(
                """UPDATE triage SET status = 'skipped', last_error = 'waited too long for the model'
                   WHERE status = 'waiting' AND last_at < %s""",
                [now - older_than],
            )
            return cur.rowcount

    def next_waiting(self, now: dt.datetime) -> Group | None:
        """The newest group due for the model, so a flood of groups is triaged newest first."""
        with self.conn, self._cur() as cur:
            cur.execute(
                f"""SELECT {GROUP_COLUMNS} FROM triage WHERE status = 'waiting' AND next_attempt_at <= %s
                    ORDER BY last_at DESC LIMIT 1""",
                [now],
            )
            r = cur.fetchone()
        return None if r is None else Group(**{k: r[k] for k in r if k != "id"}, id=int(r["id"]))

    def group_alerts(self, group: Group) -> list[dict[str, Any]]:
        with self.conn, self._cur() as cur:
            cur.execute(
                f"""SELECT {ALERT_COLUMNS} FROM alerts
                    WHERE threat_type = %s AND (%s = '*' OR source_ip = %s) AND (%s = '*' OR destination_ip = %s)
                      AND id BETWEEN %s AND %s
                    ORDER BY timestamp, id""",
                [group.threat_type, group.source_ip, group.source_ip, group.destination_ip, group.destination_ip,
                 group.first_alert_id, group.last_alert_id],
            )
            return [dict(r) for r in cur.fetchall()]

    def finish(self, group_id: int, status: str, now: dt.datetime, verdict: str | None = None,
               reason: str | None = None, model: str | None = None, digest: str | None = None,
               error: str | None = None) -> None:
        with self.conn, self._cur() as cur:
            cur.execute(
                """UPDATE triage SET status = %s, verdict = %s, reason = %s, model = %s, digest = %s,
                          last_error = %s, attempts = attempts + 1, triaged_at = %s
                   WHERE id = %s""",
                [status, verdict, reason, model, digest, error, now, group_id],
            )

    def retry_later(self, group_id: int, error: str, at: dt.datetime) -> None:
        with self.conn, self._cur() as cur:
            cur.execute(
                "UPDATE triage SET attempts = attempts + 1, last_error = %s, next_attempt_at = %s WHERE id = %s",
                [error, at, group_id],
            )

    def counts(self) -> dict[str, int]:
        with self.conn, self._cur() as cur:
            cur.execute("SELECT status, COUNT(*) AS n FROM triage WHERE status IN ('open', 'waiting') GROUP BY 1")
            return {r["status"]: int(r["n"]) for r in cur.fetchall()}

    def prune(self) -> int:
        """Remove opinions on groups whose alerts have all been deleted (data retention)."""
        with self.conn, self._cur() as cur:
            cur.execute(
                """DELETE FROM triage t WHERE status NOT IN ('open', 'waiting') AND NOT EXISTS
                   (SELECT 1 FROM alerts a WHERE a.id BETWEEN t.first_alert_id AND t.last_alert_id)"""
            )
            return cur.rowcount
