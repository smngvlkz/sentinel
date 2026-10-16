"""
The notifier: reads new alerts and decides what to send, when.

Each pass (every couple of seconds):
1. New alerts at or above `min_severity` become notifications, unless quiet
   hours or the hourly limit hold them back for a summary. A repeat of an
   alert already notified within `repeat_minutes` isn't sent at all. Alerts that were
   already old when the notifier saw them (it was stopped, or its settings
   were broken) go into the summary too, rather than arriving one by one.
2. Held alerts go out as one summary once quiet hours are over and the
   hourly limit has room.
3. Test requests from the dashboard are sent straight away to every channel
   that's turned on, whatever the rules above say.
4. Queued messages are sent. A failed send is logged and retried later with
   growing waits, then given up on.

It runs as its own service, separate from detection, so a slow or broken
channel can never hold up the analyzer.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Callable

from common.threats import at_least, severity_of

from . import messages
from .channels import SENDERS, SendError
from .config import Settings

log = logging.getLogger(__name__)

# Waits before each retry of a failed send; after the last, it's given up on.
RETRY_DELAYS = [dt.timedelta(seconds=s) for s in (30, 120, 600, 1800, 3600)]
# An alert this old when first seen goes into the summary instead.
STALE_AFTER = dt.timedelta(minutes=30)

Sender = Callable[[dict[str, Any], dict[str, str]], None]


def _aware(ts: Any) -> dt.datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)


class Notifier:

    def __init__(self, store, senders: dict[str, Sender] | None = None) -> None:
        self.store = store
        self.senders = senders or SENDERS
        self.settings: Settings = Settings()
        self.config_error: str | None = None
        self.position: int | None = None

    def quiet_now(self, now: dt.datetime) -> bool:
        quiet = self.settings.quiet
        return quiet is not None and quiet.active(now.astimezone(self.settings.zone).time())

    def run_once(self, now: dt.datetime) -> None:
        if self.position is None:
            self.position = self.store.position()
        if self.config_error is None:
            self._read_alerts(now)
            self._flush_digest(now)
        self._send_tests(now)
        self._deliver(now)

    def _read_alerts(self, now: dt.datetime) -> None:
        s = self.settings
        while True:
            alerts = self.store.new_alerts(self.position)
            if not alerts:
                return
            last = int(alerts[-1]["id"])
            queued: list[tuple[str, list[int], dict[str, str]]] = []
            held: list[int] = []
            if s.enabled:
                sent = self.store.messages_in_last_hour(now)
                quiet = self.quiet_now(now)
                wanted = [a for a in alerts if at_least(severity_of(str(a["threat_type"])), s.min_severity)]
                built = {int(a["id"]): messages.for_alert(a, s.dashboard_url, s.zone, s.ips_only) for a in wanted}
                recent: set[str] = set()
                if s.repeat_minutes > 0:
                    keys = sorted({m["repeat_key"] for m in built.values()})
                    recent = self.store.notified_since(keys, now - dt.timedelta(minutes=s.repeat_minutes))
                for alert in wanted:
                    message = built[int(alert["id"])]
                    if message["repeat_key"] in recent:
                        continue  # a repeat of an attack already notified: the dashboard has it
                    severity = message["severity"]
                    stale = now - _aware(alert["timestamp"]) > STALE_AFTER
                    let_through = s.quiet is not None and s.quiet.let_high_through and severity == "high"
                    if stale or (quiet and not let_through) or sent >= s.max_per_hour:
                        held.append(int(alert["id"]))
                        continue
                    queued.append(("alert", [int(alert["id"])], message))
                    sent += 1
                    if s.repeat_minutes > 0:
                        recent.add(message["repeat_key"])
            # Notifications off: move past these alerts without sending them, so
            # turning notifications on later doesn't send a backlog.
            self.store.commit_batch(last, queued, held, list(s.channels), now)
            self.position = last

    def _flush_digest(self, now: dt.datetime) -> None:
        s = self.settings
        if not s.enabled or self.quiet_now(now):
            return
        if self.store.messages_in_last_hour(now) >= s.max_per_hour:
            return
        held = self.store.held_alerts()
        if not held:
            return
        message = messages.digest(held, s.dashboard_url, s.zone, s.ips_only)
        self.store.queue_digest([int(a["id"]) for a in held], message, list(s.channels), now)

    def _send_tests(self, now: dt.datetime) -> None:
        if self.config_error is not None:
            return
        n = self.store.queue_tests(messages.test(self.settings.dashboard_url), list(self.settings.channels), now)
        if n and not self.settings.channels:
            log.warning("test notification requested, but no channel is turned on in notifications.toml")

    def _deliver(self, now: dt.datetime) -> None:
        for row in self.store.due(now):
            channel = row["channel"]
            channel_settings = self.settings.channels.get(channel)
            if channel_settings is None or self.config_error is not None:
                if self.config_error is None:
                    self.store.mark_failed_attempt(row["id"], f"{channel} is no longer turned on", None)
                continue
            try:
                self.senders[channel](channel_settings, row["message"])
            except SendError as e:
                attempt = int(row["attempts"]) + 1
                retry_at = now + RETRY_DELAYS[attempt - 1] if attempt <= len(RETRY_DELAYS) else None
                self.store.mark_failed_attempt(row["id"], str(e), retry_at)
                if retry_at is None:
                    log.error("%s notification %s failed %d times, giving up: %s", channel, row["id"], attempt, e)
                else:
                    log.warning("%s notification %s failed (attempt %d), retrying at %s: %s",
                                channel, row["id"], attempt, retry_at.strftime("%H:%M:%S"), e)
            except Exception as e:  # a bug in a sender mustn't stop the others
                log.exception("%s notification %s: unexpected error", channel, row["id"])
                self.store.mark_failed_attempt(row["id"], f"unexpected error: {e.__class__.__name__}", None)
            else:
                self.store.mark_sent(row["id"], now)
                log.info("sent %s notification %s by %s", row["kind"], row["id"], channel)
