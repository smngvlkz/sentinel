"""
IP → hostname cache learned from DNS answers, cleartext HTTP Host headers and
the TLS server name (SNI).

Bindings arrive on the packet stream as optional `name_bindings` fields:
[ip, name, client], where client is the device that looked the name up or
connected. One CDN address serves many sites, so the name a particular
device used for it beats whatever name anyone last used.
They are kept in memory only; durable storage is the alert row when a threat
fires. Names come from whoever sent the traffic, so treat them as untrusted
context for humans (and later for triage), never as proof of identity.
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from collections.abc import Iterable

from common.hostnames import valid_hostname

log = logging.getLogger(__name__)


def parse_bindings(packet: dict[str, str]) -> list[tuple[str, str, str | None]]:
    """
    Decode `name_bindings` from a stream entry into (ip, name, client).
    Names are checked again with capture's rule, in case anything else wrote
    to the stream.
    """
    raw = packet.get("name_bindings")
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    out: list[tuple[str, str, str | None]] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) not in (2, 3):
            continue
        ip, name = str(item[0]), valid_hostname(str(item[1]))
        client = str(item[2]) if len(item) == 3 and item[2] else None
        if ip and name:
            out.append((ip, name, client))
    return out


Key = str | tuple[str, str]


class NameCache:
    """
    Bounded LRU cache of hostnames with per-entry TTL, memory only.

    Each binding is stored twice: under (client, ip) for "the name this
    device used", and under ip for "the name anyone last used". Both count
    toward `max_entries`.
    """

    def __init__(self, max_entries: int = 10_000, ttl_seconds: float = 86_400) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        # ip or (client, ip) -> (name, last_seen)
        self._entries: OrderedDict[Key, tuple[str, float]] = OrderedDict()
        self.evicted = 0

    def __len__(self) -> int:
        return len(self._entries)

    def observe(self, packet: dict[str, str], now: float | None = None) -> int:
        """Learn from any name bindings on this packet. Returns how many were stored."""
        now = now if now is not None else time.time()
        n = 0
        for ip, name, client in parse_bindings(packet):
            keys: list[Key] = [ip] if client is None else [(client, ip), ip]
            for key in keys:
                self._entries[key] = (name, now)
                self._entries.move_to_end(key)
            n += 1
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
            self.evicted += 1
        return n

    def _get(self, key: Key, now: float) -> str | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        name, seen = entry
        if now - seen > self.ttl_seconds:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return name

    def lookup(self, ip: str, now: float | None = None, client: str | None = None) -> str | None:
        """The name `client` used for `ip` if known, else the latest name for `ip`."""
        now = now if now is not None else time.time()
        if client:
            name = self._get((client, ip), now)
            if name:
                return name
        return self._get(ip, now)

    def resolve(self, *ips: str, now: float | None = None) -> dict[str, str]:
        """Map each IP that has a fresh name; omit unknowns."""
        now = now if now is not None else time.time()
        return {ip: name for ip in ips if (name := self.lookup(ip, now))}

    def resolve_pairs(
        self, pairs: Iterable[tuple[str, str]], now: float | None = None
    ) -> dict[str, str]:
        """
        Names for both ends of each (a, b) pair, each looked up as seen from
        the other end. An IP named by an earlier pair keeps that name.
        """
        now = now if now is not None else time.time()
        out: dict[str, str] = {}
        for a, b in pairs:
            for ip, peer in ((a, b), (b, a)):
                if ip and ip not in out and (name := self.lookup(ip, now, client=peer)):
                    out[ip] = name
        return out

    def prune(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        expired = [ip for ip, (_, seen) in self._entries.items() if now - seen > self.ttl_seconds]
        for ip in expired:
            del self._entries[ip]
        return len(expired)
