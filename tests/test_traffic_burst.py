"""
The traffic-burst rule end to end: packets through FlowTracker into the rule.
Its false alarms on CIC-IDS2017 were all workstations exchanging a burst of
directory and DNS lookups with the office server: 120-220 small packets in a
tenth of a second, answered by the server. Floods last longer.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.config import DEFAULTS
from detection_engine.rules import RuleEngine

WORKSTATION, SERVER, ATTACKER = "192.168.10.16", "192.168.10.3", "198.51.100.77"


def udp(t, src, sport, dst, dport, size=150):
    return {"timestamp": str(t), "src_ip": src, "dst_ip": dst, "src_port": str(sport), "dst_port": str(dport),
            "protocol": "17", "transport": "UDP", "packet_size": str(size), "flags": ""}


def fires(packets, config=DEFAULTS):
    tracker, rules = FlowTracker(), RuleEngine(config=config)
    return any("HIGH_FREQUENCY" in rules.evaluate(tracker.update(p))
               for p in sorted(packets, key=lambda p: float(p["timestamp"])))


def lookup_burst(start=1000.0, lookups=180, seconds=0.12):
    """A workstation's burst of lookups to the office server, each answered."""
    packets = []
    for i in range(lookups):
        t = start + seconds * i / lookups
        packets += [udp(t, WORKSTATION, 50000 + i, SERVER, 389),
                    udp(t + 0.0004, SERVER, 389, WORKSTATION, 50000 + i, size=280)]
    return packets


def flood(seconds, rate=1500, start=1000.0):
    return [udp(start + i / rate, ATTACKER, 5555, SERVER, 53, size=128) for i in range(int(seconds * rate))]


class TestLookupBursts:

    def test_a_burst_of_directory_lookups_isnt_a_flood(self):
        assert not fires(lookup_burst())

    def test_the_old_rule_would_have_fired_on_it(self):
        """Guards the test itself: without the duration check, this burst is a false alarm."""
        config = {**DEFAULTS, "high_frequency": {**DEFAULTS["high_frequency"], "min_seconds": 0}}
        assert fires(lookup_burst(), config)

    def test_bursts_every_few_minutes_stay_quiet(self):
        packets = [p for k in range(10) for p in lookup_burst(start=1000.0 + k * 120)]
        assert not fires(packets)


class TestFloods:

    @pytest.mark.parametrize("seconds", [1.5, 3, 10])
    def test_a_flood_that_lasts_is_caught(self, seconds):
        assert fires(flood(seconds))

    def test_a_flood_shorter_than_min_seconds_isnt(self):
        assert not fires(flood(0.8))

    def test_a_flood_that_repeats_after_a_quiet_minute_is_caught_again(self):
        tracker, rules = FlowTracker(), RuleEngine(config=DEFAULTS)
        caught = set()
        for burst in range(3):
            for p in flood(3, start=1000.0 + burst * 60):
                if "HIGH_FREQUENCY" in rules.evaluate(tracker.update(p)):
                    caught.add(burst)
        assert caught == {0, 1, 2}
