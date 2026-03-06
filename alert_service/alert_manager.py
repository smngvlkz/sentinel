"""
Alert manager.

Persists detected threats to PostgreSQL and logs them to stdout.
If the database is unavailable alerts are still logged so no
events are silently dropped. Reconnects automatically on failure.
"""

from __future__ import annotations

import os
import json
import time
import logging

import psycopg2
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)


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
        for threat in threats:
            self._log(threat, packet)
            self._store(threat, packet, features)

    def _log(self, threat: dict[str, object], packet: dict[str, str]) -> None:
        log.warning(
            "%s src=%s dst=%s conf=%.2f engine=%s",
            threat["type"],
            packet.get("src_ip", "?"),
            packet.get("dst_ip", "?"),
            threat.get("confidence", 0),
            threat.get("source", "?"),
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
