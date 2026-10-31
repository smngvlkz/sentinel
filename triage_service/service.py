"""
The triage service: groups new alerts and asks the model about each group
once it has been quiet for 10 minutes.

Each pass (every few seconds):
1. New alerts join their group, or start one (triage_service/groups.py).
2. Groups with no alert for 10 minutes stop collecting and wait for the model.
3. The newest waiting group is triaged. Low-severity groups are skipped. If
   Ollama can't be reached, or isn't running the pinned model, the group
   stays "not triaged" and is tried again later; groups that wait more than
   a day are skipped, so a long outage can't leave a backlog.

It runs as its own service, after alerts are stored, so a slow or missing
model never holds up detection or notifications. The model's opinion is
written only to the triage table, never to an alert.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import time
from typing import Any, Callable

from common.threats import severity_of

from . import groups
from .config import Settings
from .triage import OllamaTriage, TriageError, Verdict

log = logging.getLogger(__name__)

# How long a pass may keep triaging before it goes back to reading alerts.
TRIAGE_SECONDS_PER_PASS = 30.0
# After Ollama can't be reached, wait this long before trying again.
RETRY_AFTER = dt.timedelta(minutes=5)
# A group still waiting this long after its last alert is skipped.
MAX_WAIT = dt.timedelta(hours=24)

Model = Callable[[Settings], OllamaTriage]


def model_input(group: groups.Group, alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """The group as the triage evaluation saw it: alert rows with epoch timestamps and features as a dict."""
    rows = []
    for a in alerts:
        features = a.get("features")
        if isinstance(features, str):
            features = json.loads(features)
        rows.append({**a, "timestamp": a["timestamp"].timestamp(), "features": features or {}})
    return {"threat_type": group.threat_type, "source_ip": group.source_ip,
            "destination_ip": group.destination_ip, "alerts": rows}


class Triage:

    def __init__(self, store, model: Model = lambda s: OllamaTriage(s.url, s.model, s.digest, s.timeout_seconds)):
        self.store = store
        self.make_model = model
        self.settings = Settings()
        self.config_error: str | None = None
        self.model_error: str | None = None
        self.position: int | None = None
        self._model: OllamaTriage | None = None
        self._model_checked_at: dt.datetime | None = None
        self.last_triaged_at: dt.datetime | None = None

    def settings_changed(self) -> None:
        self._model = None
        self._model_checked_at = None
        self.model_error = None

    def run_once(self, now: dt.datetime) -> None:
        if not self.settings.enabled or self.config_error is not None:
            # Off: move past alerts without grouping them, so turning triage on
            # later starts from then instead of triaging a backlog.
            newest = self.store.newest_alert()
            if self.position != newest:
                self.store.skip_to(newest)
                self.position = newest
            return
        if self.position is None:
            self.position = self.store.position()
        self._read_alerts()
        self.store.close_quiet(now)
        self.store.skip_stale(now, MAX_WAIT)
        self._triage_waiting(now)

    def _read_alerts(self) -> None:
        while True:
            alerts = self.store.new_alerts(self.position)
            if not alerts:
                return
            open_groups = self.store.open_groups()
            closed, changed = groups.add(open_groups, alerts)
            last = int(alerts[-1]["id"])
            self.store.save_batch(last, closed, changed)
            self.position = last

    def _ready_model(self, now: dt.datetime) -> OllamaTriage | None:
        """The model, once Ollama has been checked to be running the pinned build."""
        if self._model is not None:
            return self._model
        if self._model_checked_at is not None and now - self._model_checked_at < RETRY_AFTER:
            return None
        self._model_checked_at = now
        model = self.make_model(self.settings)
        try:
            model.check_model()
        except TriageError as e:
            if self.model_error != str(e):
                log.warning("triage paused: %s. Trying again every %d minutes.", e, RETRY_AFTER.seconds // 60)
            self.model_error = str(e)
            return None
        if self.model_error is not None:
            log.info("triage resumed: %s %s on %s", self.settings.model, self.settings.digest, self.settings.url)
        self.model_error = None
        self._model = model
        return model

    def _triage_waiting(self, now: dt.datetime) -> None:
        started = time.monotonic()
        while time.monotonic() - started < TRIAGE_SECONDS_PER_PASS:
            group = self.store.next_waiting(now)
            if group is None:
                return
            if severity_of(group.threat_type) == "low":
                self.store.finish(group.id, "skipped", now, error="low severity")
                continue
            alerts = self.store.group_alerts(group)
            if not alerts:
                self.store.finish(group.id, "skipped", now, error="its alerts were deleted")
                continue
            model = self._ready_model(now)
            if model is None:
                return
            try:
                verdict: Verdict | None = model.triage(model_input(group, alerts))
            except TriageError as e:
                self._model = None  # check the server again before the next group
                self.model_error = str(e)
                log.warning("triage paused: %s", e)
                self.store.retry_later(group.id, str(e), now + RETRY_AFTER)
                return
            s = self.settings
            if verdict is None:
                self.store.finish(group.id, "not triaged", now, model=s.model, digest=s.digest,
                                  error="the model's reply didn't fit the format")
            else:
                self.store.finish(group.id, "triaged", now, verdict.verdict, verdict.reason, s.model, s.digest)
            self.last_triaged_at = now
