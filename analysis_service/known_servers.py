"""
Known botnet servers, from abuse.ch's ThreatFox.

ThreatFox publishes the addresses and ports of botnet controllers that
researchers have confirmed. A device on this network opening a connection to
one is the clearest sign of infection SentinelAI can see from headers alone,
and it catches what the check-in rule can't: a bot checking in over HTTPS
looks exactly like an app by its timing, but not by where it goes.

The list is downloaded every few hours with a free abuse.ch Auth-Key
(THREATFOX_AUTH_KEY); nothing about this network is sent, abuse.ch only sees
the request. It's kept in Redis so a restart doesn't need
the internet. If a download fails, the last good list stays in use, and its
age is reported in the heartbeat so a stale list is visible.

It only knows controllers someone has already reported, so a new one isn't
caught until it's listed.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterable

log = logging.getLogger(__name__)

# The last 48 hours of all IOC types; only ip:port botnet controllers are kept.
THREATFOX_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{key}/recent.csv"
AUTH_KEY_ENV = "THREATFOX_AUTH_KEY"
NO_KEY = f"needs a free abuse.ch Auth-Key: set {AUTH_KEY_ENV} in .env, then make up"
CACHE_KEY = "sentinel:known_servers"
# The export is about 2 MB; refuse anything absurd.
MAX_BYTES = 20_000_000

ServerKey = tuple[str, str]  # (ip, port)


def parse_threatfox(text: str, min_confidence: int = 75) -> dict[ServerKey, str]:
    """
    (ip, port) -> malware name, from ThreatFox's ip:port CSV export.
    Only botnet controllers at or above min_confidence (0-100) count.
    """
    servers: dict[ServerKey, str] = {}
    lines = (line for line in io.StringIO(text) if not line.startswith("#"))
    for row in csv.reader(lines, skipinitialspace=True):
        if len(row) < 10:
            continue
        ioc, ioc_type, threat_type, malware = row[2], row[3], row[4], row[7]
        try:
            confidence = int(row[9])
        except ValueError:
            continue
        if ioc_type != "ip:port" or threat_type != "botnet_cc" or confidence < min_confidence:
            continue
        ip, sep, port = ioc.rpartition(":")
        ip = ip.strip("[]")
        if not sep or not ip or not port.isdigit():
            continue
        servers[(ip, port)] = malware or "unknown"
    return servers


class KnownServers:
    """The current list, swapped whole when a new one arrives."""

    def __init__(self, servers: dict[ServerKey, str] | None = None) -> None:
        self.servers = servers or {}
        self.updated_at: float | None = None
        self.error: str | None = None

    def match(self, ip: str, port: str) -> str | None:
        """The malware a listed server belongs to, or None."""
        return self.servers.get((ip, port))

    def replace(self, servers: dict[ServerKey, str], updated_at: float) -> None:
        self.servers = servers
        self.updated_at = updated_at
        self.error = None

    def status(self) -> dict[str, object]:
        return {"entries": len(self.servers), "updated_at": self.updated_at, "error": self.error}


def _download(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelAI"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("list is larger than expected")
    return data.decode("utf-8", errors="replace")


class Updater(threading.Thread):
    """Keeps a KnownServers list current in the background."""

    def __init__(
        self,
        known: KnownServers,
        redis_client,
        auth_key: str = "",
        url: str = THREATFOX_URL,
        refresh_hours: float = 6.0,
        min_confidence: int = 75,
        fetch=_download,
    ) -> None:
        super().__init__(daemon=True, name="known-servers")
        self.known = known
        self.redis = redis_client
        self.auth_key = auth_key.strip()
        self.url = url
        self.refresh = max(1.0, float(refresh_hours)) * 3600
        self.min_confidence = int(min_confidence)
        self.fetch = fetch

    def load_cached(self) -> bool:
        """Use the last list saved in Redis, if any."""
        try:
            raw = self.redis.get(CACHE_KEY)
        except Exception as e:  # noqa: BLE001 - Redis down shouldn't stop detection
            log.warning("couldn't read the cached known-server list: %s", e)
            return False
        if not raw:
            return False
        cached = json.loads(raw)
        self.known.replace(parse_threatfox(cached["text"], self.min_confidence), cached["at"])
        log.info("known-server list: %d servers from cache", len(self.known.servers))
        return True

    def update(self) -> bool:
        if not self.auth_key:
            self.known.error = NO_KEY
            log.warning("known-server list: %s", NO_KEY)
            return False
        try:
            text = self.fetch(self.url.format(key=self.auth_key))
            servers = parse_threatfox(text, self.min_confidence)
            if not servers:
                raise ValueError("the list was empty")
        except Exception as e:  # noqa: BLE001 - keep the last good list
            # The key is part of the URL; keep it out of the logs and /health.
            reason = str(e).replace(self.auth_key, "<key>")
            if isinstance(e, urllib.error.HTTPError) and e.code in (401, 403):
                reason += f" (abuse.ch didn't accept the Auth-Key; check {AUTH_KEY_ENV} in .env)"
            self.known.error = f"couldn't download the list: {reason}"
            log.warning("known-server list: %s", self.known.error)
            return False
        now = time.time()
        self.known.replace(servers, now)
        try:
            self.redis.set(CACHE_KEY, json.dumps({"at": now, "text": text}))
        except Exception as e:  # noqa: BLE001
            log.warning("couldn't cache the known-server list: %s", e)
        log.info("known-server list: %d servers", len(servers))
        return True

    def due(self, now: float) -> bool:
        return self.known.updated_at is None or now - self.known.updated_at >= self.refresh

    def run(self) -> None:
        self.load_cached()
        if not self.auth_key:
            # The key only comes from the environment, so retrying can't help.
            self.update()
            return
        while True:
            if self.due(time.time()):
                self.update()
            # After a failure, try again in 10 minutes rather than waiting a full refresh.
            time.sleep(600 if self.known.error else 60)


def from_file(path: str, min_confidence: int = 75) -> KnownServers:
    """A fixed list read from a saved export, for offline replays."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        known = KnownServers(parse_threatfox(fh.read(), min_confidence))
    return known


def listed(servers: Iterable[ServerKey]) -> KnownServers:
    """A list of the given servers, for tests."""
    return KnownServers({key: "test" for key in servers})
