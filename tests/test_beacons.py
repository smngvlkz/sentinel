"""Botnet check-in (beaconing) detection."""

import copy
import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alert_service.alert_manager import AlertManager
from analysis_service.feature_extractor import FlowTracker
from detection_engine.config import DEFAULT_CONFIG_PATH, DEFAULTS, load_config
from detection_engine.rules import RuleEngine

DEVICE, SERVER = "192.168.1.20", "198.51.100.200"


def syn(t, src=DEVICE, dst=SERVER, dport=8080, sport=None, transport="TCP"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport or 40000 + int(t) % 20000), "dst_ip": dst,
            "dst_port": str(dport), "protocol": "6" if transport == "TCP" else "17", "packet_size": "60",
            "flags": "S" if transport == "TCP" else "", "transport": transport}


def enabled_config():
    config = copy.deepcopy(DEFAULTS)
    config["beaconing"]["enabled"] = True
    return config


@pytest.fixture
def rules():
    """The check-in rule is off by default; these tests switch it on."""
    return RuleEngine(config=enabled_config())


def replay(times, **kw):
    tracker = FlowTracker()
    features = None
    for i, t in enumerate(times):
        features = tracker.update(syn(t, sport=30000 + i, **kw))
    return tracker, features


class TestBeaconing:

    def test_bot_checking_in_every_101_seconds(self, rules):
        """The Ares bots in CIC-IDS2017 checked in every 101 s, for hours."""
        _, f = replay([i * 101.0 for i in range(40)])  # about 67 minutes
        assert f["checkins_last_hour"] >= 30 and f["checkin_slots_last_hour"] == 12
        assert "BEACONING" in rules.evaluate(f)

    def test_not_before_enough_history(self, rules):
        """30 minutes of check-ins isn't enough to call it persistent."""
        _, f = replay([i * 60.0 for i in range(30)])
        assert "BEACONING" not in rules.evaluate(f)

    def test_irregular_but_persistent_bot(self, rules):
        """Two of the CIC bots alternated 76 s / 23 s / 10 s gaps; persistence still catches them."""
        gaps, t, times = [76, 23, 10], 0.0, []
        for i in range(150):
            times.append(t)
            t += gaps[i % 3]
        _, f = replay(times)
        assert "BEACONING" in rules.evaluate(f)

    def test_burst_of_connections_counts_as_one_checkin(self):
        tracker, _ = replay([0.0, 0.5, 1.0, 1.5])
        assert len(tracker.beacons.checkins[(DEVICE, SERVER, "8080")]) == 1


class TestNormalPeriodicTraffic:
    """Normal software also refreshes on a schedule; these patterns come from CIC-IDS2017."""

    def test_every_15_minutes_all_day(self, rules):
        _, f = replay([i * 900.0 for i in range(32)])
        assert "BEACONING" not in rules.evaluate(f)

    def test_every_9_minutes_all_day(self, rules):
        _, f = replay([i * 542.0 for i in range(50)])
        assert "BEACONING" not in rules.evaluate(f)

    def test_short_burst_every_8_seconds(self, rules):
        """A page refreshing every 8 s for ten minutes: many check-ins, but not persistent."""
        _, f = replay([i * 8.0 for i in range(75)])
        assert f["checkins_last_hour"] == 75
        assert "BEACONING" not in rules.evaluate(f)

    def test_dns_to_an_internet_resolver_is_not_tracked(self, rules):
        _, f = replay([i * 60.0 for i in range(80)], dst="8.8.8.8", dport=53, transport="UDP")
        assert f["checkins_last_hour"] == 0
        assert "BEACONING" not in rules.evaluate(f)

    def test_local_servers_are_not_tracked(self, rules):
        _, f = replay([i * 60.0 for i in range(80)], dst="192.168.1.5", dport=445)
        assert f["checkins_last_hour"] == 0


def test_cleanup_forgets_quiet_series():
    tracker, _ = replay([0.0, 100.0])
    assert tracker.beacons.cleanup(5000.0) == 1
    assert tracker.beacons.checkins == {}


def test_beacon_alert_repeats_hourly_even_across_pruning():
    """Suppression must use the threat's own cooldown, including when entries are pruned."""
    with patch.object(AlertManager, "_connect"), patch.dict(os.environ, {"ALERT_COOLDOWN_SECONDS": "60"}):
        manager = AlertManager()
    with patch.object(manager, "_store") as store, patch.object(manager, "_log"):
        threat = {"type": "BEACONING", "source": "rules", "confidence": 0.9, "cooldown": 3600.0}
        packet = {"timestamp": "1000", "src_ip": DEVICE, "dst_ip": SERVER}
        for minute in range(0, 61):
            now = 1000.0 + minute * 60
            manager.prune(now)
            manager.handle([threat], {**packet, "timestamp": str(now)}, {})
        assert store.call_count == 2  # at 0 and at 60 minutes


class TestOffByDefault:
    """Scheduled software and busy web pages check in the same way, so the rule is opt-in."""

    def test_default_config_and_shipped_file_leave_it_off(self):
        assert DEFAULTS["beaconing"]["enabled"] is False
        assert load_config(DEFAULT_CONFIG_PATH)["beaconing"]["enabled"] is False

    def test_silent_by_default_even_for_a_bot(self):
        _, f = replay([i * 101.0 for i in range(40)])
        assert f["checkins_last_hour"] >= 30  # the pattern is still measured...
        assert "BEACONING" not in RuleEngine(config=DEFAULTS).evaluate(f)  # ...but not alerted on

    def test_turning_it_on_in_the_config_file(self, tmp_path):
        path = tmp_path / "detection.toml"
        path.write_text("[beaconing]\nenabled = true\n")
        _, f = replay([i * 101.0 for i in range(40)])
        assert "BEACONING" in RuleEngine(config=load_config(str(path))).evaluate(f)
