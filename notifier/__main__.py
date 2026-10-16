"""
Run the notifier: `python -m notifier`.

Reloads config/notifications.toml whenever the file changes, so most edits
need no restart (secrets in .env do). Reports its state to Redis every few
seconds for the dashboard's status line.
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
from .service import Notifier
from .store import Store

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("notifier")

INTERVAL = 2.0
PRUNE_INTERVAL = 3600.0
HEARTBEAT_KEY = "sentinel:notifier:heartbeat"
HEARTBEAT_TTL = 60


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

    def check(self, notifier: Notifier) -> None:
        try:
            mtime: float | None = os.stat(self.path).st_mtime
        except OSError:
            mtime = None
        if mtime == self.mtime:
            return
        self.mtime = mtime
        try:
            notifier.settings = config.load(self.path)
            notifier.config_error = None
            s = notifier.settings
            log.info(
                "notifications %s; channels: %s; at least %s severity",
                "on" if s.enabled else "off",
                ", ".join(s.channels) or "none",
                s.min_severity,
            )
        except config.ConfigError as e:
            notifier.config_error = str(e)
            log.error("notifications.toml: %s. Nothing is sent until it's fixed.", e)


def heartbeat(r: redis.Redis, notifier: Notifier, now: dt.datetime) -> None:
    s = notifier.settings
    state = {
        "at": now.timestamp(),
        "enabled": s.enabled and notifier.config_error is None,
        "error": notifier.config_error,
        "channels": list(s.channels),
        "min_severity": s.min_severity,
        "quiet_now": notifier.quiet_now(now) if notifier.config_error is None else False,
    }
    try:
        r.set(HEARTBEAT_KEY, json.dumps(state), ex=HEARTBEAT_TTL)
    except redis.RedisError:
        pass


def main() -> None:
    path = os.getenv("SENTINEL_NOTIFICATIONS_CONFIG") or config.DEFAULT_PATH
    r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")))
    conn = connect_db()
    notifier = Notifier(Store(conn))
    watcher = ConfigWatcher(path)
    last_prune = 0.0
    while True:
        now = dt.datetime.now(dt.timezone.utc)
        watcher.check(notifier)
        try:
            notifier.run_once(now)
            if time.monotonic() - last_prune > PRUNE_INTERVAL:
                notifier.store.prune(now)
                last_prune = time.monotonic()
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            log.warning("database connection lost (%s), reconnecting", e)
            try:
                conn.close()
            except Exception:
                pass
            conn = connect_db()
            notifier.store = Store(conn)
        heartbeat(r, notifier, now)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
