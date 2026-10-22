"""Known botnet servers: the ThreatFox list, matching connections to it, and keeping it current."""

import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from analysis_service.known_servers import CACHE_KEY, KnownServers, Updater, listed, parse_threatfox
from detection_engine.config import DEFAULT_CONFIG_PATH, DEFAULTS, load_config
from detection_engine.detector import DetectionEngine
from detection_engine.rules import RuleEngine

DEVICE, C2 = "192.168.1.20", "198.51.100.66"

EXPORT = """################################################################
# ThreatFox IOCs: recent ip-port - CSV format                  #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-10-17 10:30:30", "1", "198.51.100.66:443", "ip:port", "botnet_cc", "win.qakbot", "QBot,Quakbot", "QakBot", "", "100", "False", "None", "c2", "0", "abuse_ch"
"2026-10-17 10:10:10", "2", "198.51.100.77:8080", "ip:port", "botnet_cc", "win.remcos", "None", "Remcos", "", "50", "False", "None", "c2", "0", "abuse_ch"
"2026-10-17 09:45:57", "3", "198.51.100.88:80", "ip:port", "payload_delivery", "win.x", "None", "X", "", "100", "False", "None", "", "0", "abuse_ch"
"2026-10-17 09:00:00", "4", "[2001:db8::66]:4444", "ip:port", "botnet_cc", "win.y", "None", "Y", "", "75", "False", "None", "", "0", "abuse_ch"
"""


def packet(t, src, sport, dst, dport, flags="S"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6", "packet_size": "60", "flags": flags, "transport": "TCP"}


def enabled_config():
    config = copy.deepcopy(DEFAULTS)
    config["known_servers"]["enabled"] = True
    return config


class TestParsing:

    def test_botnet_servers_at_or_above_the_confidence(self):
        servers = parse_threatfox(EXPORT, min_confidence=75)
        # Remcos is below 75; the payload server isn't a botnet controller.
        assert servers == {("198.51.100.66", "443"): "QakBot", ("2001:db8::66", "4444"): "Y"}

    def test_aliases_with_commas_dont_shift_the_columns(self):
        assert parse_threatfox(EXPORT, min_confidence=0)[("198.51.100.66", "443")] == "QakBot"

    def test_garbage_is_ignored(self):
        assert parse_threatfox("<html>not a list</html>\n,,,\n") == {}


class TestMatching:

    def test_a_device_connecting_to_a_listed_server(self):
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        f = tracker.update(packet(0, DEVICE, 50000, C2, 443))
        assert f["known_server"] == 1.0
        assert "KNOWN_BOTNET_SERVER" in RuleEngine(config=enabled_config()).evaluate(f)

    def test_the_same_address_on_another_port_isnt_a_match(self):
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        assert tracker.update(packet(0, DEVICE, 50000, C2, 80))["known_server"] == 0.0

    def test_only_when_the_connection_opens(self):
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        tracker.update(packet(0, DEVICE, 50000, C2, 443))
        assert tracker.update(packet(0.1, DEVICE, 50000, C2, 443, flags="A"))["known_server"] == 0.0

    def test_joined_mid_stream_from_the_server_side(self):
        """A connection already open when capture started may first be seen from the server."""
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        pkt = packet(0, C2, 443, DEVICE, 50000, flags="PA")
        f = tracker.update(pkt)
        assert f["known_server"] == 1.0 and f["known_server_is_initiator"] == 1.0
        engine = DetectionEngine()
        engine.config = enabled_config()
        engine.rules = RuleEngine(engine.config)
        threat = next(t for t in engine.detect(f, pkt) if t["type"] == "KNOWN_BOTNET_SERVER")
        assert threat["source_ip"] == DEVICE and threat["destination_ip"] == C2
        assert threat["cooldown"] == 3600.0

    def test_internet_hosts_contacting_each_other_arent_matched(self):
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        assert tracker.update(packet(0, "203.0.113.5", 50000, C2, 443))["known_server"] == 0.0

    def test_no_list_no_matches(self):
        assert FlowTracker().update(packet(0, DEVICE, 50000, C2, 443))["known_server"] == 0.0


class TestOnByDefault:

    def test_default_config_and_shipped_file_turn_it_on(self):
        assert DEFAULTS["known_servers"]["enabled"] is True
        assert load_config(DEFAULT_CONFIG_PATH)["known_servers"]["enabled"] is True

    def test_silent_when_turned_off(self):
        config = copy.deepcopy(DEFAULTS)
        config["known_servers"]["enabled"] = False
        tracker = FlowTracker(known_servers=listed([(C2, "443")]))
        f = tracker.update(packet(0, DEVICE, 50000, C2, 443))
        assert "KNOWN_BOTNET_SERVER" not in RuleEngine(config=config).evaluate(f)


class FakeRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value


class TestUpdater:

    def test_download_replaces_the_list_and_caches_it(self):
        known, redis = KnownServers(), FakeRedis()
        assert Updater(known, redis, fetch=lambda url: EXPORT).update()
        assert known.match(C2, "443") == "QakBot" and known.error is None
        assert json.loads(redis.data[CACHE_KEY])["text"] == EXPORT

    def test_a_failed_download_keeps_the_last_good_list(self):
        known, redis = KnownServers(), FakeRedis()
        Updater(known, redis, fetch=lambda url: EXPORT).update()

        def offline(url):
            raise OSError("network is unreachable")

        assert not Updater(known, redis, fetch=offline).update()
        assert known.match(C2, "443") == "QakBot"
        assert "network is unreachable" in known.error

    def test_an_empty_download_doesnt_wipe_the_list(self):
        known, redis = KnownServers(), FakeRedis()
        Updater(known, redis, fetch=lambda url: EXPORT).update()
        assert not Updater(known, redis, fetch=lambda url: "# nothing\n").update()
        assert len(known.servers) == 2

    def test_a_restart_uses_the_cached_list_without_the_internet(self):
        redis = FakeRedis()
        Updater(KnownServers(), redis, fetch=lambda url: EXPORT).update()
        known = KnownServers()
        assert Updater(known, redis).load_cached()
        assert known.match(C2, "443") == "QakBot"

    @pytest.mark.parametrize("age_hours, due", [(1, False), (7, True)])
    def test_refreshes_every_few_hours(self, age_hours, due):
        known = KnownServers()
        known.replace({}, updated_at=0.0)
        assert Updater(known, FakeRedis(), refresh_hours=6).due(age_hours * 3600) is due
