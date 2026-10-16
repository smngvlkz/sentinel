"""The notifier's rules: what's sent, held for a summary, retried or given up on."""

import datetime as dt
import os
import sys
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from notifier.channels import SendError
from notifier.config import QuietHours, Settings
from notifier.service import RETRY_DELAYS, Notifier

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
NTFY = {"server": "http://ntfy", "topic": "t", "token": ""}


class FakeStore:
    """The same interface as notifier.store.Store, in memory."""

    def __init__(self, newest=0):
        self.alerts = {}
        self.state = None
        self.newest_at_start = newest
        self.rows = []  # notifications: dicts like the table's rows
        self.digest = set()
        self.tests = 0
        self.next_message = 1

    # setup helpers
    def add(self, threat_type, at=T0, **kw):
        alert_id = max(list(self.alerts) + [self.newest_at_start]) + 1
        self.alerts[alert_id] = {
            "id": alert_id, "timestamp": at, "threat_type": threat_type,
            "source_ip": kw.get("src", "203.0.113.9"), "destination_ip": kw.get("dst", "192.168.1.20"),
            "source_name": None, "destination_name": None, "source_device": None,
            "destination_device": kw.get("device"),
        }
        return alert_id

    # Store interface
    def position(self):
        if self.state is None:
            self.state = max(list(self.alerts) + [self.newest_at_start])
        return self.state

    def new_alerts(self, after_id, limit=500):
        return [self.alerts[i] for i in sorted(self.alerts) if i > after_id][:limit]

    def messages_in_last_hour(self, now):
        return len({r["message_id"] for r in self.rows
                    if r["kind"] in ("alert", "digest") and r["created_at"] > now - dt.timedelta(hours=1)})

    def _queue(self, kind, alert_ids, message, channels, now):
        for ch in channels:
            self.rows.append({"id": len(self.rows) + 1, "message_id": self.next_message, "kind": kind,
                              "channel": ch, "alert_ids": alert_ids, "message": message, "status": "pending",
                              "attempts": 0, "next_attempt_at": now, "created_at": now, "last_error": None})
        self.next_message += 1

    def notified_since(self, keys, since):
        return {r["message"]["repeat_key"] for r in self.rows
                if r["kind"] == "alert" and r["created_at"] > since and r["message"]["repeat_key"] in keys}

    def commit_batch(self, last_alert_id, messages, held, channels, now):
        for kind, ids, message in messages:
            self._queue(kind, ids, message, channels, now)
        self.digest |= set(held)
        self.state = last_alert_id

    def held_alerts(self):
        return [self.alerts[i] for i in sorted(self.digest)]

    def queue_digest(self, alert_ids, message, channels, now):
        self._queue("digest", alert_ids, message, channels, now)
        self.digest -= set(alert_ids)

    def queue_tests(self, message, channels, now):
        n, self.tests = self.tests, 0
        if n and channels:
            self._queue("test", [], message, channels, now)
        return n

    def due(self, now, limit=50):
        return [dict(r) for r in self.rows if r["status"] == "pending" and r["next_attempt_at"] <= now][:limit]

    def _row(self, row_id):
        return next(r for r in self.rows if r["id"] == row_id)

    def mark_sent(self, row_id, now):
        r = self._row(row_id)
        r.update(status="sent", attempts=r["attempts"] + 1)

    def mark_failed_attempt(self, row_id, error, retry_at):
        r = self._row(row_id)
        r.update(attempts=r["attempts"] + 1, last_error=error,
                 status="failed" if retry_at is None else "pending",
                 next_attempt_at=retry_at or r["next_attempt_at"])

    def prune(self, now):
        pass


class Phone:
    """A channel that records what it was sent, and can be told to fail."""

    def __init__(self):
        self.got = []
        self.failing = False

    def __call__(self, settings, message):
        if self.failing:
            raise SendError("couldn't connect: refused")
        self.got.append(message)


def make(store=None, **settings):
    store = store or FakeStore()
    phone = Phone()
    n = Notifier(store, senders={"ntfy": phone, "email": phone, "webhook": phone})
    defaults = dict(enabled=True, channels={"ntfy": NTFY}, zone=ZoneInfo("UTC"))
    n.settings = Settings(**{**defaults, **settings})
    return n, store, phone


def titles(phone):
    return [m["title"] for m in phone.got]


class TestWhatIsSent:
    def test_high_alert_reaches_the_phone_in_one_pass(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD", device="Front door camera")
        n.run_once(T0 + dt.timedelta(seconds=2))
        assert titles(phone) == ["Connection flood"]
        assert "Front door camera" in phone.got[0]["body"]
        assert phone.got[0]["severity"] == "high"

    def test_below_min_severity_is_skipped(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("PORT_SCAN")
        store.add("ANOMALY")
        n.run_once(T0)
        assert phone.got == [] and store.digest == set()
        assert store.state == 2  # moved past them

    def test_min_severity_medium_sends_medium_too(self):
        n, store, phone = make(min_severity="medium")
        n.run_once(T0)
        store.add("PORT_SCAN")
        store.add("LARGE_PAYLOAD")
        n.run_once(T0)
        assert titles(phone) == ["Port scan"]

    def test_existing_alerts_are_not_sent_on_first_start(self):
        store = FakeStore(newest=500)
        n, _, phone = make(store)
        n.run_once(T0)
        assert store.state == 500 and phone.got == []

    def test_disabled_sends_nothing_and_leaves_no_backlog(self):
        n, store, phone = make(enabled=False)
        n.run_once(T0)
        store.add("SYN_FLOOD")
        n.run_once(T0)
        assert phone.got == [] and store.digest == set()
        n.settings = Settings(enabled=True, channels={"ntfy": NTFY})
        n.run_once(T0)
        assert phone.got == []  # turning it on later doesn't send the old alert

    def test_every_channel_gets_each_message(self):
        n, store, phone = make(channels={"ntfy": NTFY, "webhook": {"format": "json", "url": "http://x"}})
        n.run_once(T0)
        store.add("REQUEST_FLOOD")
        n.run_once(T0)
        assert titles(phone) == ["Request flood", "Request flood"]

    def test_alert_seen_late_goes_into_the_summary(self):
        # The notifier was stopped for an hour: old alerts arrive as one summary.
        n, store, phone = make()
        n.run_once(T0)
        a = store.add("SYN_FLOOD", at=T0 - dt.timedelta(hours=1))
        b = store.add("SYN_FLOOD", at=T0 - dt.timedelta(minutes=50), src="198.51.100.7")
        n.run_once(T0)
        assert titles(phone) == ["2 alerts held back"]
        assert store.digest == set() and {a, b} <= set(store.rows[0]["alert_ids"])


class TestHourlyLimit:
    def test_alerts_past_the_limit_wait_for_one_summary(self):
        n, store, phone = make(max_per_hour=3)
        n.run_once(T0)
        for i in range(10):
            store.add("SYN_FLOOD", src=f"203.0.113.{i}")
        n.run_once(T0)
        assert len(phone.got) == 3
        assert len(store.digest) == 7
        # Still within the hour: nothing more.
        n.run_once(T0 + dt.timedelta(minutes=59))
        assert len(phone.got) == 3
        # An hour on there's room again: the 7 go out as one message.
        n.run_once(T0 + dt.timedelta(minutes=61))
        assert len(phone.got) == 4
        assert phone.got[3]["title"] == "7 alerts held back"
        assert "7 × Connection flood (high)" in phone.got[3]["body"]
        assert store.digest == set()

    def test_never_more_than_the_limit_in_any_hour(self):
        n, store, phone = make(max_per_hour=2)
        n.run_once(T0)
        sent_at = []
        for minute in range(0, 180, 5):
            now = T0 + dt.timedelta(minutes=minute)
            store.add("SYN_FLOOD", at=now, src=f"203.0.113.{minute}")
            before = len(phone.got)
            n.run_once(now)
            sent_at += [now] * (len(phone.got) - before)
        for t in sent_at:
            in_hour = [u for u in sent_at if t <= u < t + dt.timedelta(hours=1)]
            assert len(in_hour) <= 2
        # Nothing lost: every alert was sent alone or in a summary, or is still held.
        covered = {i for r in store.rows for i in r["alert_ids"]} | store.digest
        assert covered == set(store.alerts)

    def test_tests_dont_count_towards_the_limit(self):
        n, store, phone = make(max_per_hour=1)
        n.run_once(T0)
        store.tests = 3
        n.run_once(T0)
        store.add("SYN_FLOOD")
        n.run_once(T0)
        assert titles(phone) == ["SentinelAI test notification", "Connection flood"]


class TestRepeats:
    def test_ongoing_attack_notifies_once_an_hour(self):
        n, store, phone = make()
        n.run_once(T0)
        for minute in range(0, 130):  # one alert a minute, as the cooldown allows
            now = T0 + dt.timedelta(minutes=minute)
            store.add("SYN_FLOOD", at=now)
            n.run_once(now)
        assert len(phone.got) == 3  # at the start, then once each hour it goes on
        assert store.digest == set()

    def test_different_devices_or_kinds_are_not_repeats(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        store.add("SYN_FLOOD", src="198.51.100.7")
        store.add("SYN_FLOOD", dst="192.168.1.30")
        store.add("REQUEST_FLOOD")
        store.add("SYN_FLOOD")  # the only repeat
        n.run_once(T0)
        assert len(phone.got) == 4

    def test_renaming_a_device_doesnt_make_a_repeat_new(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        n.run_once(T0)
        store.add("SYN_FLOOD", device="Front door camera")
        n.run_once(T0 + dt.timedelta(minutes=1))
        assert len(phone.got) == 1

    def test_zero_sends_every_repeat(self):
        n, store, phone = make(repeat_minutes=0)
        n.run_once(T0)
        for _ in range(3):
            store.add("SYN_FLOOD")
        n.run_once(T0)
        assert len(phone.got) == 3

    def test_a_held_alert_doesnt_count_as_notified(self):
        # Held by the hourly limit: its repeat later is still sent (in the summary).
        n, store, phone = make(max_per_hour=1)
        n.run_once(T0)
        store.add("REQUEST_FLOOD")
        store.add("SYN_FLOOD")
        n.run_once(T0)
        assert titles(phone) == ["Request flood"] and len(store.digest) == 1


class TestQuietHours:
    QUIET = QuietHours(dt.time(22, 0), dt.time(7, 0), let_high_through=False)

    def test_window_crossing_midnight(self):
        q = self.QUIET
        assert q.active(dt.time(23, 30)) and q.active(dt.time(0, 0)) and q.active(dt.time(6, 59))
        assert not q.active(dt.time(7, 0)) and not q.active(dt.time(12, 0)) and not q.active(dt.time(21, 59))

    def test_window_within_a_day(self):
        q = QuietHours(dt.time(13, 0), dt.time(14, 0), False)
        assert q.active(dt.time(13, 30)) and not q.active(dt.time(14, 0)) and not q.active(dt.time(12, 59))

    def test_held_overnight_then_one_summary_at_the_end(self):
        n, store, phone = make(min_severity="medium", quiet=self.QUIET)
        night = dt.datetime(2026, 10, 16, 23, 0, tzinfo=UTC)
        n.run_once(night)
        store.add("SYN_FLOOD", at=night)
        store.add("PORT_SCAN", at=night + dt.timedelta(hours=1))
        n.run_once(night + dt.timedelta(hours=1))
        n.run_once(night + dt.timedelta(hours=7, minutes=59))
        assert phone.got == []
        n.run_once(night + dt.timedelta(hours=8))  # 07:00
        assert titles(phone) == ["2 alerts held back"]
        body = phone.got[0]["body"]
        assert body.index("Connection flood") < body.index("Port scan")  # most urgent first

    def test_high_let_through_but_medium_held(self):
        quiet = QuietHours(dt.time(22, 0), dt.time(7, 0), let_high_through=True)
        n, store, phone = make(min_severity="medium", quiet=quiet)
        night = dt.datetime(2026, 10, 16, 23, 0, tzinfo=UTC)
        n.run_once(night)
        store.add("SYN_FLOOD", at=night)
        store.add("PORT_SCAN", at=night)
        n.run_once(night)
        assert titles(phone) == ["Connection flood"]
        assert len(store.digest) == 1

    def test_quiet_hours_use_the_configured_time_zone(self):
        # 20:30 UTC is 22:30 in Johannesburg: quiet there.
        n, store, phone = make(quiet=self.QUIET, zone=ZoneInfo("Africa/Johannesburg"))
        now = dt.datetime(2026, 10, 16, 20, 30, tzinfo=UTC)
        assert n.quiet_now(now)
        assert not n.quiet_now(now - dt.timedelta(hours=1))

    def test_single_held_alert_is_sent_as_itself(self):
        n, store, phone = make(quiet=self.QUIET)
        night = dt.datetime(2026, 10, 16, 23, 0, tzinfo=UTC)
        n.run_once(night)
        store.add("SYN_FLOOD", at=night)
        n.run_once(night)
        n.run_once(night + dt.timedelta(hours=8))
        assert titles(phone) == ["Connection flood"]

    def test_tests_ignore_quiet_hours(self):
        n, store, phone = make(quiet=self.QUIET)
        store.tests = 1
        n.run_once(dt.datetime(2026, 10, 16, 23, 0, tzinfo=UTC))
        assert titles(phone) == ["SentinelAI test notification"]


class TestRetries:
    def test_failed_send_is_retried_with_growing_waits_then_given_up(self, caplog):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        phone.failing = True
        now = T0
        n.run_once(now)
        row = store.rows[0]
        for i, wait in enumerate(RETRY_DELAYS):
            assert row["status"] == "pending" and row["attempts"] == i + 1
            n.run_once(now + wait - dt.timedelta(seconds=1))
            assert row["attempts"] == i + 1  # not before the wait is over
            now = now + wait
            n.run_once(now)
        assert row["status"] == "failed"
        assert row["attempts"] == len(RETRY_DELAYS) + 1
        assert "couldn't connect" in row["last_error"]
        assert "giving up" in caplog.text

    def test_recovers_when_the_channel_comes_back(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        phone.failing = True
        n.run_once(T0)
        phone.failing = False
        n.run_once(T0 + RETRY_DELAYS[0])
        assert titles(phone) == ["Connection flood"]
        assert store.rows[0]["status"] == "sent"

    def test_a_failing_channel_doesnt_stop_the_others(self):
        store = FakeStore()
        good, bad = Phone(), Phone()
        bad.failing = True
        n = Notifier(store, senders={"ntfy": bad, "email": good})
        n.settings = Settings(enabled=True, channels={"ntfy": NTFY, "email": {}})
        n.run_once(T0)
        store.add("SYN_FLOOD")
        n.run_once(T0)
        assert len(good.got) == 1
        assert {r["channel"]: r["status"] for r in store.rows} == {"ntfy": "pending", "email": "sent"}

    def test_a_crashing_sender_is_logged_not_fatal(self):
        def broken(settings, message):
            raise RuntimeError("bug")

        store = FakeStore()
        n = Notifier(store, senders={"ntfy": broken})
        n.settings = Settings(enabled=True, channels={"ntfy": NTFY})
        n.run_once(T0)
        store.add("SYN_FLOOD")
        n.run_once(T0)
        assert store.rows[0]["status"] == "failed"

    def test_channel_turned_off_while_waiting(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        phone.failing = True
        n.run_once(T0)
        n.settings = Settings(enabled=True, channels={"email": {}})
        n.run_once(T0 + RETRY_DELAYS[0])
        assert store.rows[0]["status"] == "failed"
        assert "no longer turned on" in store.rows[0]["last_error"]


class TestBrokenSettings:
    def test_nothing_sent_and_alerts_wait_until_fixed(self):
        n, store, phone = make()
        n.run_once(T0)
        n.config_error = "min_severity must be one of high, medium, low"
        store.add("SYN_FLOOD")
        store.tests = 1
        n.run_once(T0)
        assert phone.got == [] and store.state == 0
        n.config_error = None
        n.run_once(T0 + dt.timedelta(minutes=1))
        assert sorted(titles(phone)) == ["Connection flood", "SentinelAI test notification"]

    def test_queued_messages_wait_too(self):
        n, store, phone = make()
        n.run_once(T0)
        store.add("SYN_FLOOD")
        phone.failing = True
        n.run_once(T0)
        n.config_error = "broken"
        phone.failing = False
        n.run_once(T0 + RETRY_DELAYS[0])
        assert phone.got == [] and store.rows[0]["status"] == "pending"


@pytest.mark.parametrize("threat", ["SYN_FLOOD", "REQUEST_FLOOD", "DISTRIBUTED_FLOOD", "RESOURCE_PRESSURE"])
def test_every_high_threat_is_sent_by_default(threat):
    n, store, phone = make()
    n.run_once(T0)
    store.add(threat)
    n.run_once(T0)
    assert len(phone.got) == 1
