"""
Traffic analyzer.

Consumes packets from the Redis stream, extracts flow features,
runs them through the detection engine, and dispatches alerts.
"""

from __future__ import annotations

import os
import sys
import json
import time
import logging

import redis
from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from analysis_service.gc_tuning import FullCollector, tune_gc
from analysis_service.pressure import PressureMonitor
from analysis_service.tables import TableReport, Tables
from analysis_service.names import NameCache
from common.flags import env_flag
from detection_engine.config import load_config
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
# The dashboard reads this key to show whether the analyzer is running.
# It expires on its own if the analyzer stops.
HEARTBEAT_KEY = "sentinel:analyzer:heartbeat"
HEARTBEAT_INTERVAL = 5
HEARTBEAT_TTL = 30


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


# Packets read but unfinished for this long belong to a run that has stopped:
# a live analyzer finishes each batch within milliseconds.
STALE_PENDING_MS = 60_000


def clear_stale_pending(r: redis.Redis) -> int:
    """
    Mark packets that an earlier run read but never finished (it was stopped
    mid-batch) as done. Redis never hands them to a reader of new packets
    again, so they'd stay in the group's pending list for good and `pending`
    on /health would never reach 0. They aren't processed now: they're from
    before the restart, and the flow state they belonged to is gone.
    """
    cleared = 0
    while True:
        stale = r.xpending_range(STREAM_NAME, CONSUMER_GROUP, "-", "+", 1000, idle=STALE_PENDING_MS)
        if not stale:
            break
        acked = r.xack(STREAM_NAME, CONSUMER_GROUP, *[entry["message_id"] for entry in stale])
        cleared += acked
        if len(stale) < 1000 or not acked:
            break
    if cleared:
        log.info("marked %d packets left unfinished by an earlier run as done", cleared)
    return cleared


def entries_read(r: redis.Redis) -> int:
    """
    Stream entries the consumer group has moved past. Redis counts entries
    trimmed away before anyone read them as read too, which is what lets
    StreamLoss tell them apart from the ones actually processed.
    """
    for group in r.xinfo_groups(STREAM_NAME):
        if group.get("name") == CONSUMER_GROUP:
            return int(group.get("entries-read") or 0)
    return 0


class StreamLoss:
    """Packets dropped from the stream (capture keeps the newest 100,000) before the analyzer read them."""

    def __init__(self, r: redis.Redis) -> None:
        self.start = entries_read(r)

    def since_start(self, r: redis.Redis, processed: int) -> int:
        return max(0, entries_read(r) - self.start - processed)


def send_heartbeat(
    r: redis.Redis,
    started_at: float,
    processed: int,
    model_loaded: bool,
    tables: dict[str, dict[str, int]] | None = None,
    lost_unread: int | None = None,
) -> None:
    try:
        r.set(
            HEARTBEAT_KEY,
            json.dumps({
                "at": time.time(),
                "started_at": started_at,
                "processed": processed,
                "model_loaded": model_loaded,
                "tables": tables or {},
                "lost_unread": lost_unread,
            }),
            ex=HEARTBEAT_TTL,
        )
    except redis.ConnectionError:
        pass


def names_enabled(config_value: object, env: str | None) -> bool:
    """
    Whether to learn hostnames. NAMES_ENABLED overrides the config file when
    set (`make demo` turns names on, since its traffic is all made up);
    otherwise `[names] enabled` decides.
    """
    flag = env_flag(env)
    return bool(config_value) if flag is None else flag


def main() -> None:
    r = connect_redis()
    ensure_consumer_group(r)
    clear_stale_pending(r)

    config = load_config()
    names_cfg = config["names"]
    learn_names = names_enabled(names_cfg.get("enabled"), os.getenv("NAMES_ENABLED"))
    name_cache = (
        NameCache(
            max_entries=int(names_cfg.get("max_entries", 10_000)),
            ttl_seconds=float(names_cfg.get("ttl_seconds", 86_400)),
        )
        if learn_names
        else None
    )

    tracker = FlowTracker(limits=config["limits"])
    detector = DetectionEngine()
    alerts = AlertManager()

    started_at = time.time()
    last_cleanup = started_at
    last_heartbeat = 0.0
    processed = 0
    model_loaded = detector.anomaly.model is not None
    # The model and config are loaded; from here on, skip full collections
    # (see gc_tuning.py) apart from the hourly safety net.
    tune_gc()
    full_collector = FullCollector()
    tables = Tables(tracker, detector, alerts, name_cache)
    pressure = PressureMonitor(tables)
    table_report = TableReport(tables)
    stream_loss = StreamLoss(r)

    log.info(
        "listening on stream:%s as %s (names=%s)",
        STREAM_NAME,
        CONSUMER_NAME,
        "on" if learn_names else "off",
    )

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
                if name_cache is not None:
                    name_cache.observe(packet)

                features = tracker.update(packet)
                threats = detector.detect(features, packet)

                if threats:
                    resolved = None
                    if name_cache is not None:
                        # Name both ends of every pair the alert might show,
                        # including multi-host rules that override the
                        # packet endpoints. Each end is looked up as seen
                        # from the other, so shared CDN IPs get the right name.
                        src, dst = packet.get("src_ip", ""), packet.get("dst_ip", "")
                        pairs = [
                            (str(t.get("source_ip") or src), str(t.get("destination_ip") or dst))
                            for t in threats
                        ]
                        pairs.append((src, dst))
                        resolved = name_cache.resolve_pairs(pairs)
                    alerts.handle(threats, packet, features, resolved)

                r.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
                processed += 1

        now = time.time()
        if now - last_heartbeat > HEARTBEAT_INTERVAL:
            try:
                lost = stream_loss.since_start(r, processed)
            except redis.RedisError:
                lost = None
            send_heartbeat(r, started_at, processed, model_loaded, table_report.report(now), lost)
            last_heartbeat = now

        if now - last_cleanup > CLEANUP_INTERVAL:
            cleaned = tracker.cleanup_stale(now)
            alerts.prune(now)
            detector.forget_idle(now)
            if name_cache is not None:
                name_cache.prune(now)
            full_collector.maybe_collect()
            alert = pressure.check(now)
            if alert is not None:
                threat, packet, features = alert
                alerts.handle([threat], packet, features)
            if cleaned:
                log.info("cleaned %d stale flows, total processed: %d", cleaned, processed)
            last_cleanup = now


if __name__ == "__main__":
    main()
