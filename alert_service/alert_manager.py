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
from collections import OrderedDict

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
        config = load_config()
        self.cooldown = float(os.getenv("ALERT_COOLDOWN_SECONDS") or config["alerts"]["cooldown_seconds"])
        # key -> (time last emitted, repeats suppressed since, cooldown for this key),
        # in order of last emitted. When full, the oldest is dropped, which at
        # worst lets that alert repeat early.
        self._recent: OrderedDict[AlertKey, tuple[float, int, float]] = OrderedDict()
        self.max_recent = max(1, int(config["limits"]["max_alert_cooldowns"]))
        self.evicted = 0
        self._connect()

    def _connect(self) -> None:
        try:
            self.conn = psycopg2.connect(**self._dsn)
            self.conn.autocommit = True
            self._ensure_schema()
            log.info("postgresql connected")
        except psycopg2.OperationalError as e:
            log.warning("postgresql unavailable: %s — alerts will only be logged", e)
            self.conn = None

    def _ensure_schema(self) -> None:
        """Add columns introduced after the first install; no-op when already present."""
        if self.conn is None:
            return
        with self.conn.cursor() as cur:
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_name TEXT")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS destination_name TEXT")

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
        names: dict[str, str] | None = None,
    ) -> None:
        now = float(packet.get("timestamp", time.time()))
        names = names or {}
        for threat in threats:
            cooldown = float(threat.get("cooldown") or self.cooldown)
            suppressed = self._suppress(self._key(threat, packet), now, cooldown)
            if suppressed is None:
                continue
            self._log(threat, packet, suppressed, names)
            self._store(threat, packet, features, names)

    @staticmethod
    def _endpoints(threat: dict[str, object], packet: dict[str, str]) -> tuple[str, str, str, str]:
        """(src ip, dst ip, src port, dst port): the threat's own if it names them, else the packet's."""
        return (
            str(threat.get("source_ip") or packet.get("src_ip", "?")),
            str(threat.get("destination_ip") or packet.get("dst_ip", "?")),
            str(threat.get("source_port") or packet.get("src_port", "")),
            str(threat.get("destination_port") or packet.get("dst_port", "")),
        )

    def _key(self, threat: dict[str, object], packet: dict[str, str]) -> AlertKey:
        """
        Repeats of the same key are suppressed. Normally that's one threat
        between one source and destination; threats involving many hosts
        group on the side that stays the same.
        """
        src, dst, _, _ = self._endpoints(threat, packet)
        group = threat.get("group")
        if group == "destination":
            src = "*"
        elif group == "source":
            dst = "*"
        elif group == "all":
            src = dst = "*"
        return (str(threat["type"]), src, dst)

    def _suppress(self, key: AlertKey, now: float, cooldown: float | None = None) -> int | None:
        """Return None to drop a repeat alert, else how many were dropped before it."""
        cooldown = cooldown if cooldown is not None else self.cooldown
        last = self._recent.get(key)
        if last is not None and now - last[0] < last[2]:
            self._recent[key] = (last[0], last[1] + 1, last[2])
            return None
        self._recent[key] = (now, 0, cooldown)
        self._recent.move_to_end(key)
        while len(self._recent) > self.max_recent:
            self._recent.popitem(last=False)
            self.evicted += 1
        return last[1] if last else 0

    def prune(self, now: float | None = None) -> int:
        """Forget cooldowns that have expired so the table does not grow unbounded."""
        now = now or time.time()
        expired = [k for k, (t, _, cooldown) in self._recent.items() if now - t >= cooldown]
        for k in expired:
            del self._recent[k]
        return len(expired)

    def _log(
        self,
        threat: dict[str, object],
        packet: dict[str, str],
        suppressed: int = 0,
        names: dict[str, str] | None = None,
    ) -> None:
        src, dst, _, _ = self._endpoints(threat, packet)
        names = names or {}
        src_n = names.get(src)
        dst_n = names.get(dst)
        log.warning(
            "%s src=%s%s dst=%s%s conf=%.2f engine=%s%s",
            threat["type"],
            src,
            f"({src_n})" if src_n else "",
            dst,
            f"({dst_n})" if dst_n else "",
            threat.get("confidence", 0),
            threat.get("source", "?"),
            f" (+{suppressed} suppressed)" if suppressed else "",
        )

    def _store(
        self,
        threat: dict[str, object],
        packet: dict[str, str],
        features: dict[str, float],
        names: dict[str, str] | None = None,
    ) -> None:
        if self.conn is None:
            self._reconnect()
        if self.conn is None:
            return
        src, dst, sport, dport = self._endpoints(threat, packet)
        names = names or {}
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO alerts
                       (timestamp, threat_type, source_ip, destination_ip,
                        source_port, destination_port, confidence,
                        detection_source, features, source_name, destination_name)
                       VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        float(packet.get("timestamp", str(time.time()))),
                        threat["type"],
                        src,
                        dst,
                        sport,
                        dport,
                        threat.get("confidence", 0),
                        threat.get("source", "unknown"),
                        json.dumps(features),
                        names.get(src),
                        names.get(dst),
                    ),
                )
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            log.error("db write failed: %s — reconnecting", e)
            self._reconnect()
        except Exception as e:
            log.error("failed to store alert: %s", e)
