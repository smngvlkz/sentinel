"""Traffic Analyzer - consumes packets from Redis and runs detection pipeline."""

import os
import time
import json
import logging

import redis
from dotenv import load_dotenv

from feature_extractor import FlowTracker

# Add parent dir so we can import sibling packages
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection_engine.detector import DetectionEngine
from alert_service.alert_manager import AlertManager

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ANALYZER] %(message)s")
logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
STREAM_NAME = "packet_stream"
CONSUMER_GROUP = "analyzers"
CONSUMER_NAME = "analyzer-1"
CLEANUP_INTERVAL = 60


def ensure_consumer_group(redis_client):
    try:
        redis_client.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
        logger.info("Created consumer group: %s", CONSUMER_GROUP)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def run():
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    redis_client.ping()
    logger.info("Connected to Redis")

    ensure_consumer_group(redis_client)

    flow_tracker = FlowTracker()
    detector = DetectionEngine()
    alert_manager = AlertManager()

    last_cleanup = time.time()
    processed = 0

    logger.info("Listening for packets on stream: %s", STREAM_NAME)

    while True:
        messages = redis_client.xreadgroup(
            CONSUMER_GROUP, CONSUMER_NAME, {STREAM_NAME: ">"}, count=100, block=1000
        )

        for stream, entries in messages:
            for msg_id, packet in entries:
                features = flow_tracker.update(packet)
                threats = detector.detect(features, packet)

                if threats:
                    alert_manager.handle(threats, packet, features)

                redis_client.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
                processed += 1

        now = time.time()
        if now - last_cleanup > CLEANUP_INTERVAL:
            cleaned = flow_tracker.cleanup_stale(now)
            if cleaned:
                logger.info("Cleaned %d stale flows. Total processed: %d", cleaned, processed)
            last_cleanup = now


if __name__ == "__main__":
    run()
