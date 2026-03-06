"""
Traffic analyzer.

Consumes packets from the Redis stream, extracts flow features,
runs them through the detection engine, and dispatches alerts.
"""

from __future__ import annotations

import os
import sys
import time
import logging

import redis
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.detector import DetectionEngine
from alert_service.alert_manager import AlertManager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [analyzer] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
STREAM_NAME = "packet_stream"
CONSUMER_GROUP = "analyzers"
CONSUMER_NAME = f"analyzer-{os.getpid()}"
CLEANUP_INTERVAL = 60
RECONNECT_DELAY = 5


def connect_redis() -> redis.Redis:
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            r.ping()
            log.info("redis connected")
            return r
        except redis.ConnectionError:
            log.warning("redis unavailable, retrying in %ds...", RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)


def ensure_consumer_group(r: redis.Redis) -> None:
    try:
        r.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
        log.info("created consumer group %s", CONSUMER_GROUP)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def main() -> None:
    r = connect_redis()
    ensure_consumer_group(r)

    tracker = FlowTracker()
    detector = DetectionEngine()
    alerts = AlertManager()

    last_cleanup = time.time()
    processed = 0

    log.info("listening on stream:%s as %s", STREAM_NAME, CONSUMER_NAME)

    while True:
        try:
            messages = r.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME, {STREAM_NAME: ">"}, count=100, block=1000
            )
        except redis.ConnectionError:
            log.warning("redis connection lost, reconnecting...")
            r = connect_redis()
            ensure_consumer_group(r)
            continue

        for _, entries in messages:
            for msg_id, packet in entries:
                features = tracker.update(packet)
                threats = detector.detect(features, packet)

                if threats:
                    alerts.handle(threats, packet, features)

                r.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
                processed += 1

        now = time.time()
        if now - last_cleanup > CLEANUP_INTERVAL:
            cleaned = tracker.cleanup_stale(now)
            if cleaned:
                log.info("cleaned %d stale flows, total processed: %d", cleaned, processed)
            last_cleanup = now


if __name__ == "__main__":
    main()
