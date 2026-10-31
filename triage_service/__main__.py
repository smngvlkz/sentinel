"""
Run triage: `python -m triage_service`.

Reloads config/triage.toml whenever the file changes, so edits need no
restart. Reports its state to Redis every few seconds for /health and the
dashboard.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import time

import psycopg2
import redis
from dotenv import load_dotenv

from common.migrations import migrate

from . import config
from .service import Triage
from .store import Store

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("triage")

INTERVAL = 5.0
PRUNE_INTERVAL = 3600.0
HEARTBEAT_KEY = "sentinel:triage:heartbeat"
HEARTBEAT_TTL = 120


def connect_db() -> psycopg2.extensions.connection:
    while True:
        try:
            conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST", "localhost"),
                port=os.getenv("POSTGRES_PORT", "5432"),
                dbname=os.getenv("POSTGRES_DB", "sentinel_ai"),
                user=os.getenv("POSTGRES_USER", "sentinel"),
                password=os.getenv("POSTGRES_PASSWORD", "changeme"),
            )
            migrate(conn)
            conn.autocommit = False
            log.info("postgresql connected")
            return conn
        except psycopg2.OperationalError as e:
            log.warning("postgresql unavailable, retrying in 5 s: %s", e)
            time.sleep(5)


class ConfigWatcher:
    """Loads the settings again when the file's modification time changes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.mtime: float | None = -1.0

    def check(self, triage: Triage) -> None:
        try:
            mtime: float | None = os.stat(self.path).st_mtime
        except OSError:
            mtime = None
        if mtime == self.mtime:
            return
        self.mtime = mtime
        try:
            triage.settings = config.load(self.path)
            triage.config_error = None
            s = triage.settings
            log.info("triage %s; %s %s on %s", "on" if s.enabled else "off", s.model, s.digest, s.url)
        except config.ConfigError as e:
            triage.config_error = str(e)
            log.error("triage.toml: %s. Nothing is triaged until it's fixed.", e)
        triage.settings_changed()


def heartbeat(r: redis.Redis, triage: Triage, counts: dict[str, int], now: dt.datetime) -> None:
    s = triage.settings
    state = {
        "at": now.timestamp(),
        "enabled": s.enabled and triage.config_error is None,
        "error": triage.config_error or triage.model_error,
        "model": s.model,
        "digest": s.digest,
        "collecting": counts.get("open", 0),
        "waiting": counts.get("waiting", 0),
        "last_triaged_at": triage.last_triaged_at.timestamp() if triage.last_triaged_at else None,
    }
    try:
        r.set(HEARTBEAT_KEY, json.dumps(state), ex=HEARTBEAT_TTL)
    except redis.RedisError:
        pass


def main() -> None:
    path = os.getenv("SENTINEL_TRIAGE_CONFIG") or config.DEFAULT_PATH
    r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")))
    conn = connect_db()
    triage = Triage(Store(conn))
    watcher = ConfigWatcher(path)
    last_prune = 0.0
    while True:
        now = dt.datetime.now(dt.timezone.utc)
        watcher.check(triage)
        counts: dict[str, int] = {}
        try:
            triage.run_once(now)
            counts = triage.store.counts()
            if time.monotonic() - last_prune > PRUNE_INTERVAL:
                triage.store.prune()
                last_prune = time.monotonic()
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            log.warning("database connection lost (%s), reconnecting", e)
            try:
                conn.close()
            except Exception:
                pass
            conn = connect_db()
            triage.store = Store(conn)
        heartbeat(r, triage, counts, now)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
