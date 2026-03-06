"""Alert Manager - stores and dispatches threat alerts."""

import os
import json
import time
import logging

import psycopg2
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentinel_ai")
POSTGRES_USER = os.getenv("POSTGRES_USER", "sentinel")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")


class AlertManager:
    def __init__(self):
        self.db_conn = None
        self._connect_db()

    def _connect_db(self):
        try:
            self.db_conn = psycopg2.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                dbname=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
            )
            self.db_conn.autocommit = True
            logger.info("Connected to PostgreSQL")
        except psycopg2.OperationalError as e:
            logger.warning("Could not connect to PostgreSQL: %s. Alerts will only be logged.", e)
            self.db_conn = None

    def handle(self, threats, packet, features):
        """Process detected threats - store in DB and log."""
        for threat in threats:
            self._log_alert(threat, packet)
            self._store_alert(threat, packet, features)

    def _log_alert(self, threat, packet):
        logger.warning(
            "THREAT DETECTED: %s | src=%s dst=%s | confidence=%.2f | source=%s",
            threat["type"],
            packet.get("src_ip", "?"),
            packet.get("dst_ip", "?"),
            threat.get("confidence", 0),
            threat.get("source", "unknown"),
        )

    def _store_alert(self, threat, packet, features):
        if self.db_conn is None:
            return
        try:
            with self.db_conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip,
                       source_port, destination_port, confidence, detection_source, features)
                       VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        float(packet.get("timestamp", time.time())),
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
        except Exception as e:
            logger.error("Failed to store alert: %s", e)
