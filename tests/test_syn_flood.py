"""
The connection-flood rule end to end: packets through FlowTracker into the
rule, so the timing that matters (answers arriving a round trip later) is
part of the test.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import MAX_PENDING_SYNS, FlowTracker
from detection_engine.config import DEFAULTS
from detection_engine.rules import RuleEngine

CLIENT, SERVER = "192.168.10.16", "203.0.113.75"


def pkt(t, src, sport, dst, dport, flags):
    return {
        "timestamp": str(t), "src_ip": src, "dst_ip": dst, "src_port": str(sport), "dst_port": str(dport),
        "protocol": "6", "transport": "TCP", "packet_size": "60", "flags": flags,
    }


def replay(packets):
    """Every packet through the tracker and the rule; returns the last features and whether it ever fired."""
    tracker, rules = FlowTracker(), RuleEngine(config=DEFAULTS)
    fired, features = False, {}
    for p in sorted(packets, key=lambda p: float(p["timestamp"])):
        features = tracker.update(p)
        fired = fired or "SYN_FLOOD" in rules.evaluate(features)
    return features, fired


def browser_burst(start=1000.0, connections=12, spread=0.11, rtt=0.25):
    """What every CIC-IDS2017 false alarm looked like: a dozen connections to one
    web server within ~0.1 s, each answered and completed a round trip later."""
    packets = []
    for i in range(connections):
        t, port = start + spread * i / connections, 50000 + i
        packets += [
            pkt(t, CLIENT, port, SERVER, 443, "S"),
            pkt(t + rtt, SERVER, 443, CLIENT, port, "SA"),
            pkt(t + rtt + 0.0001, CLIENT, port, SERVER, 443, "A"),
            pkt(t + rtt + 0.0002, CLIENT, port, SERVER, 443, "PA"),
        ]
    return packets


class TestBrowserBursts:

    def test_a_burst_of_answered_connections_isnt_a_flood(self):
        features, fired = replay(browser_burst())
        assert not fired
        assert features["unfinished_syns"] == 0

    def test_completed_requests_never_count_once_the_grace_period_is_over(self):
        """A busy page: a fresh burst every half second for ten seconds, all completed."""
        packets = []
        for k in range(20):
            burst = browser_burst(start=1000.0 + k * 0.5)
            # New client ports each time, as a browser would use.
            for p in burst:
                if p["src_ip"] == CLIENT:
                    p["src_port"] = str(int(p["src_port"]) + k * 100)
                else:
                    p["dst_port"] = str(int(p["dst_port"]) + k * 100)
            packets += burst
        features, fired = replay(packets)
        assert not fired
        assert features["unfinished_syns"] == 0

    def test_the_old_rule_would_have_fired_on_it(self):
        """Guards the test itself: without the new condition, this burst is a false alarm."""
        config = {**DEFAULTS, "syn_flood": {**DEFAULTS["syn_flood"], "min_unfinished": 0}}
        tracker, rules = FlowTracker(), RuleEngine(config=config)
        assert any("SYN_FLOOD" in rules.evaluate(tracker.update(p))
                   for p in sorted(browser_burst(), key=lambda p: float(p["timestamp"])))

    @pytest.mark.parametrize("rtt", [0.08, 0.3, 0.9])
    def test_slow_servers_still_finish_within_the_grace_period(self, rtt):
        _, fired = replay(browser_burst(rtt=rtt))
        assert not fired


class TestFloods:

    def test_unanswered_requests(self):
        """The classic flood: requests that get no answer at all."""
        packets = [pkt(1000 + i / 400, CLIENT, 40000 + i, SERVER, 80, "S") for i in range(800)]
        features, fired = replay(packets)
        assert fired
        assert features["unfinished_syns"] >= DEFAULTS["syn_flood"]["min_unfinished"]

    def test_an_open_port_that_answers_but_the_sender_never_finishes(self):
        """hping3 against an open port: the server sends SYN-ACKs, the sender's kernel resets."""
        packets = []
        for i in range(800):
            t, port = 1000 + i / 400, 40000 + i
            packets += [
                pkt(t, CLIENT, port, SERVER, 80, "S"),
                pkt(t + 0.0002, SERVER, 80, CLIENT, port, "SA"),
                pkt(t + 0.0004, CLIENT, port, SERVER, 80, "R"),
            ]
        # Resets are a third of the sender's packets, so the ratio check (>0.8 SYNs)
        # wouldn't pass: this documents that such a flood shows up as RST traffic
        # to the other rules, not as this one.
        features, _ = replay(packets)
        assert features["unfinished_syns"] >= DEFAULTS["syn_flood"]["min_unfinished"]

    def test_its_caught_once_the_grace_period_has_passed(self):
        grace = DEFAULTS["syn_flood"]["handshake_seconds"]
        packets = [pkt(1000 + i / 400, CLIENT, 40000 + i, SERVER, 80, "S") for i in range(400 * 3)]
        tracker, rules = FlowTracker(), RuleEngine(config=DEFAULTS)
        first = next(float(p["timestamp"]) for p in packets if "SYN_FLOOD" in rules.evaluate(tracker.update(p)))
        assert 1000 + grace < first < 1000 + grace + 0.1


class TestBookkeeping:

    def test_a_request_retransmitted_within_the_grace_period_counts_once(self):
        packets = [pkt(1000 + i * 0.2, CLIENT, 40000, SERVER, 80, "S") for i in range(4)]
        features, _ = replay(packets + [pkt(1010, CLIENT, 40001, SERVER, 80, "S")])
        assert features["unfinished_syns"] == 1

    def test_pending_requests_stay_capped(self):
        tracker = FlowTracker()
        for i in range(MAX_PENDING_SYNS * 10):
            tracker.update(pkt(1000 + i * 0.0001, CLIENT, 40000 + i, SERVER, 80, "S"))
        flow = tracker.flows[(CLIENT, SERVER)]
        assert len(flow["pending_syns"]) == MAX_PENDING_SYNS
        # None counted yet: the cap doesn't cut the grace period short.
        assert flow["unfinished_syns"] == 0

    def test_a_burst_bigger_than_the_cap_still_isnt_a_flood(self):
        _, fired = replay(browser_burst(connections=MAX_PENDING_SYNS * 3, spread=0.2))
        assert not fired


class TestRepeatedFloods:
    """A flood that repeats with quiet gaps, like the demo's (5 s every minute)."""

    @staticmethod
    def pulses(minutes, cleanup_offset):
        """Fires per minute, with cleanup checked once a minute as the analyzer does."""
        tracker, rules = FlowTracker(), RuleEngine(config=DEFAULTS)
        last_cleanup, fired = cleanup_offset, set()
        for minute in range(minutes):
            for tick in range(50):
                now = minute * 60 + tick * 0.1
                if now - last_cleanup > 60:
                    tracker.cleanup_stale(now)
                    last_cleanup = now
                for i in range(40):
                    p = pkt(now, CLIENT, 10000 + (minute * 2000 + tick * 40 + i) % 50000, SERVER, 80, "S")
                    if "SYN_FLOOD" in rules.evaluate(tracker.update(p)):
                        fired.add(minute)
        return fired

    @pytest.mark.parametrize("cleanup_offset", [0.0, 15.0, 30.0, 45.0])
    def test_every_burst_is_caught_whenever_cleanup_runs(self, cleanup_offset):
        # Cleanup at the start of a burst used to keep the flow, so the quiet
        # minute dragged its average rate under the threshold for good.
        assert self.pulses(10, cleanup_offset) == set(range(10))


class TestIdleFlows:

    def test_a_flow_idle_past_the_timeout_starts_afresh(self):
        tracker = FlowTracker(flow_timeout=30.0)
        for i in range(20):
            tracker.update(pkt(1000 + i * 0.01, CLIENT, 40000 + i, SERVER, 80, "S"))
        f = tracker.update(pkt(1031, CLIENT, 41000, SERVER, 80, "S"))
        assert f["total_packets"] == 1 and f["flow_duration"] < 0.01
        assert tracker.ip_connection_counts[CLIENT] == 1

    def test_a_flow_with_a_shorter_gap_carries_on(self):
        tracker = FlowTracker(flow_timeout=30.0)
        for i in range(20):
            tracker.update(pkt(1000 + i * 0.01, CLIENT, 40000 + i, SERVER, 80, "S"))
        f = tracker.update(pkt(1029, CLIENT, 41000, SERVER, 80, "S"))
        assert f["total_packets"] == 21
        assert tracker.ip_connection_counts[CLIENT] == 1

    def test_restarting_keeps_the_per_source_count_right_through_cleanup(self):
        tracker = FlowTracker(flow_timeout=30.0)
        tracker.update(pkt(1000, CLIENT, 40000, SERVER, 80, "S"))
        tracker.update(pkt(1040, CLIENT, 40001, SERVER, 80, "S"))  # restarted
        tracker.cleanup_stale(now=1100)
        assert CLIENT not in tracker.ip_connection_counts
