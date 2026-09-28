"""
Alert manager.

Persists detected threats to PostgreSQL and logs them to stdout.
If the database is unavailable alerts are still logged so no
events are silently dropped. Reconnects automatically on failure.

Repeat alerts are rate-limited: once a threat type fires for a
src -> dst pair, further matches for that pair are suppressed for
the configured cooldown, so an attack produces one alert per window
instead of one per packet.
"""

from __future__ import annotations

import os
import json
import time
import logging

import psycopg2
from dotenv import load_dotenv

from detection_engine.config import load_config

load_dotenv()

log = logging.getLogger(__name__)

AlertKey = tuple[str, str, str]


class AlertManager:

    def __init__(self) -> None:
        self._dsn = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": os.getenv("POSTGRES_PORT", "5432"),
            "dbname": os.getenv("POSTGRES_DB", "sentinel_ai"),
            "user": os.getenv("POSTGRES_USER", "sentinel"),
            "password": os.getenv("POSTGRES_PASSWORD", "changeme"),
        }
        self.conn: psycopg2.extensions.connection | None = None
        self.cooldown = float(
            os.getenv("ALERT_COOLDOWN_SECONDS") or load_config()["alerts"]["cooldown_seconds"]
        )
        # key -> (time last emitted, matches suppressed since then)
        self._recent: dict[AlertKey, tuple[float, int]] = {}
        self._connect()

    def _connect(self) -> None:
        try:
            self.conn = psycopg2.connect(**self._dsn)
            self.conn.autocommit = True
            log.info("postgresql connected")
        except psycopg2.OperationalError as e:
            log.warning("postgresql unavailable: %s — alerts will only be logged", e)
            self.conn = None

    def _reconnect(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self._connect()

    def handle(
        self,
        threats: list[dict[str, object]],
        packet: dict[str, str],
        features: dict[str, float],
    ) -> None:
        now = float(packet.get("timestamp", time.time()))
        for threat in threats:
            key = (str(threat["type"]), packet.get("src_ip", "?"), packet.get("dst_ip", "?"))
            suppressed = self._suppress(key, now)
            if suppressed is None:
                continue
            self._log(threat, packet, suppressed)
            self._store(threat, packet, features)

    def _suppress(self, key: AlertKey, now: float) -> int | None:
        """Return None to drop a repeat alert, else how many were dropped before it."""
        last = self._recent.get(key)
        if last is not None and now - last[0] < self.cooldown:
            self._recent[key] = (last[0], last[1] + 1)
            return None
        self._recent[key] = (now, 0)
        return last[1] if last else 0

    def prune(self, now: float | None = None) -> int:
        """Forget cooldowns that have expired so the table does not grow unbounded."""
        now = now or time.time()
        expired = [k for k, (t, _) in self._recent.items() if now - t >= self.cooldown]
        for k in expired:
            del self._recent[k]
        return len(expired)

    def _log(self, threat: dict[str, object], packet: dict[str, str], suppressed: int = 0) -> None:
        log.warning(
            "%s src=%s dst=%s conf=%.2f engine=%s%s",
            threat["type"],
            packet.get("src_ip", "?"),
            packet.get("dst_ip", "?"),
            threat.get("confidence", 0),
            threat.get("source", "?"),
            f" (+{suppressed} suppressed)" if suppressed else "",
        )

    def _store(
        self,
        threat: dict[str, object],
        packet: dict[str, str],
        features: dict[str, float],
    ) -> None:
        if self.conn is None:
            self._reconnect()
        if self.conn is None:
            return
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO alerts
                       (timestamp, threat_type, source_ip, destination_ip,
                        source_port, destination_port, confidence,
                        detection_source, features)
                       VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        float(packet.get("timestamp", str(time.time()))),
                        threat["type"],
                        packet.get("src_ip"),
                        packet.get("dst_ip"),
                        packet.get("src_port"),
                        packet.get("dst_port"),
                        threat.get("confidence", 0),
                        threat.get("source", "unknown"),
                        json.dumps(features),
                    ),
                )
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            log.error("db write failed: %s — reconnecting", e)
            self._reconnect()
        except Exception as e:
            log.error("failed to store alert: %s", e)
