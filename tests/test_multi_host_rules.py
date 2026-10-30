"""Rules built on connections and per-host windows: request floods, distributed floods, sweeps, mass mail."""

import copy
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.feature_extractor import FlowTracker
from detection_engine.config import DEFAULT_CONFIG_PATH, DEFAULTS, load_config
from detection_engine.rules import RuleEngine


def pkt(t, src, sport, dst, dport, flags="", size=60, transport="TCP"):
    return {"timestamp": str(t), "src_ip": src, "src_port": str(sport), "dst_ip": dst, "dst_port": str(dport),
            "protocol": "6" if transport == "TCP" else "17", "packet_size": str(size), "flags": flags,
            "transport": transport}


@pytest.fixture
def rules():
    return RuleEngine(config=DEFAULTS)


def open_connections(tracker, count, src, dst, port, spacing, complete=True, start=0.0):
    """Open `count` TCP connections from src to dst:port; returns the features after the last packet."""
    f = None
    for i in range(count):
        t, sport = start + i * spacing, 20000 + i
        f = tracker.update(pkt(t, src, sport, dst, port, "S"))
        if complete:
            tracker.update(pkt(t + 0.001, dst, port, src, sport, "SA"))
            f = tracker.update(pkt(t + 0.002, src, sport, dst, port, "A"))
    return f


class TestRequestFlood:
    """One source opening completed connections to one service very fast: an HTTP flood."""

    def test_http_flood_detected(self, rules):
        f = open_connections(FlowTracker(), 500, "172.16.0.1", "192.168.10.50", 80, spacing=0.01)
        assert "REQUEST_FLOOD" in rules.evaluate(f)

    def test_busy_but_normal_client_is_not(self, rules):
        """CIC-IDS2017's busiest normal client peaked at 251 connections in 10s."""
        f = open_connections(FlowTracker(), 250, "192.168.10.9", "192.168.10.3", 88, spacing=0.04)
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_dns_queries_are_not_connections(self, rules):
        """Hundreds of DNS lookups a second are normal for a resolver, and they're UDP."""
        tracker = FlowTracker()
        for i in range(1000):
            f = tracker.update(pkt(i * 0.005, "192.168.10.3", 30000 + i, "8.8.8.8", 53, transport="UDP"))
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_half_open_connections_are_a_syn_flood_not_this(self, rules):
        f = open_connections(FlowTracker(), 500, "203.0.113.66", "192.168.1.10", 80, spacing=0.01, complete=False)
        assert "REQUEST_FLOOD" not in rules.evaluate(f)

    def test_boundary(self, rules):
        base = {"conn_established": 1.0}
        assert "REQUEST_FLOOD" not in rules.evaluate({**base, **_quiet(), "service_new_conns_10s": 400})
        assert "REQUEST_FLOOD" in rules.evaluate({**base, **_quiet(), "service_new_conns_10s": 401})


class TestDistributedFlood:
    """Many internet sources converging on one host: the attack no single-source rule sees."""

    def test_many_internet_sources_detected(self, rules):
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 0.1, f"203.0.113.{i + 1}", 40000, "192.168.1.10", 443, "S"))
        assert f["responder_external_sources_60s"] == 60
        assert "DISTRIBUTED_FLOOD" in rules.evaluate(f)

    def test_many_local_sources_are_not(self, rules):
        """Every device on a big office network using the same local server is normal."""
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 0.1, f"192.168.1.{i + 20}", 40000, "192.168.1.3", 53, transport="UDP"))
        assert f["responder_external_sources_60s"] == 0
        assert "DISTRIBUTED_FLOOD" not in rules.evaluate(f)

    def test_sources_spread_over_more_than_a_minute_are_not(self, rules):
        tracker = FlowTracker()
        for i in range(60):
            f = tracker.update(pkt(i * 2.0, f"203.0.113.{i + 1}", 40000, "192.168.1.10", 443, "S"))
        assert f["responder_external_sources_60s"] <= 31
        assert "DISTRIBUTED_FLOOD" not in rules.evaluate(f)


class TestNetworkSweep:
    """One source contacting many local hosts on the same port: a worm or scanner looking for targets."""

    def test_sweep_detected(self, rules):
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(i * 0.05, "192.168.1.66", 40000 + i, f"192.168.1.{100 + i}", 445, "S"))
        assert f["initiator_same_port_local_hosts_60s"] == 29
        assert "NETWORK_SWEEP" in rules.evaluate(f)

    def test_many_internet_hosts_are_not(self, rules):
        """A DNS resolver or a browser talks to many internet hosts on one port."""
        tracker = FlowTracker()
        for i in range(1, 100):
            f = tracker.update(pkt(i * 0.05, "192.168.1.3", 40000 + i, f"198.51.100.{i}", 53, transport="UDP"))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)

    def test_different_ports_to_many_hosts_are_not(self, rules):
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(i * 0.05, "192.168.1.66", 40000 + i, f"192.168.1.{100 + i}", 1000 + i, "S"))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)

    def test_joining_connections_mid_stream_is_not(self, rules):
        """After a restart, existing connections all appear at once; they aren't new attempts."""
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(0.0, "192.168.1.5", 50000 + i, f"192.168.1.{100 + i}", 445, "PA", size=500))
        assert "NETWORK_SWEEP" not in rules.evaluate(f)



class TestMassMail:
    """A local device delivering mail straight to many internet mail servers: a spam bot."""

    @pytest.fixture
    def rules(self):
        config = copy.deepcopy(DEFAULTS)
        config["mass_mail"]["enabled"] = True
        return RuleEngine(config=config)

    @staticmethod
    def mail(tracker, servers, spacing, src="192.168.1.66", port=25, start=0.0, flags="S"):
        f = None
        for i in range(servers):
            f = tracker.update(pkt(start + i * spacing, src, 40000 + i, f"198.51.100.{i + 1}", port, flags))
        return f

    def test_spam_bot_detected(self, rules):
        """Spam bots in CTU-13 reached 35-45 different mail servers a minute."""
        f = self.mail(FlowTracker(), 40, spacing=1.5)
        assert f["initiator_mail_servers_10m"] == 40
        assert "MASS_MAIL" in rules.evaluate(f)

    def test_boundary(self, rules):
        assert "MASS_MAIL" not in rules.evaluate(self.mail(FlowTracker(), 9, spacing=30))
        assert "MASS_MAIL" in rules.evaluate(self.mail(FlowTracker(), 10, spacing=30))

    def test_spread_over_more_than_ten_minutes_is_not(self, rules):
        f = self.mail(FlowTracker(), 30, spacing=70)
        assert f["initiator_mail_servers_10m"] <= 9
        assert "MASS_MAIL" not in rules.evaluate(f)

    def test_window_survives_cleanup_between_slow_sends(self, rules):
        """A host quiet for more than a minute between sends keeps its 10-minute count."""
        tracker = FlowTracker()
        for i in range(10):
            f = tracker.update(pkt(i * 65.0, "192.168.1.66", 40000 + i, f"198.51.100.{i + 1}", 25, "S"))
            tracker.cleanup_stale(i * 65.0 + 64)
        assert f["initiator_mail_servers_10m"] == 10
        assert "MASS_MAIL" in rules.evaluate(f)

    @pytest.mark.parametrize("port", [587, 465, 443])
    def test_submission_and_web_ports_are_not(self, rules, port):
        """Mail apps send through their provider on 587 or 465."""
        assert "MASS_MAIL" not in rules.evaluate(self.mail(FlowTracker(), 40, spacing=1, port=port))

    def test_one_provider_many_times_is_not(self, rules):
        tracker = FlowTracker()
        for i in range(50):
            f = tracker.update(pkt(i * 2.0, "192.168.1.66", 40000 + i, "198.51.100.25", 25, "S"))
        assert f["initiator_mail_servers_10m"] == 1
        assert "MASS_MAIL" not in rules.evaluate(f)

    def test_local_mail_servers_are_not(self, rules):
        """A scan of the local network on port 25 is the sweep rule's job."""
        tracker = FlowTracker()
        for i in range(1, 30):
            f = tracker.update(pkt(i * 0.5, "192.168.1.66", 40000 + i, f"192.168.1.{100 + i}", 25, "S"))
        assert f["initiator_mail_servers_10m"] == 0

    def test_mail_servers_delivering_to_you_are_not(self, rules):
        """Incoming mail from the internet isn't this device sending it."""
        tracker = FlowTracker()
        for i in range(30):
            f = tracker.update(pkt(i * 1.0, f"198.51.100.{i + 1}", 40000 + i, "192.168.1.25", 25, "S"))
        assert "MASS_MAIL" not in rules.evaluate(f)

    def test_joining_connections_mid_stream_is_not(self, rules):
        f = self.mail(FlowTracker(), 30, spacing=0.0, flags="PA")
        assert "MASS_MAIL" not in rules.evaluate(f)


class TestMassMailOffByDefault:
    """The held-out test had too few spam bots to confirm the rule, so it is opt-in."""

    def test_default_config_and_shipped_file_leave_it_off(self):
        assert DEFAULTS["mass_mail"]["enabled"] is False
        assert load_config(DEFAULT_CONFIG_PATH)["mass_mail"]["enabled"] is False

    def test_silent_by_default_even_for_a_spam_bot(self):
        f = TestMassMail.mail(FlowTracker(), 40, spacing=1.5)
        assert f["initiator_mail_servers_10m"] == 40  # still measured...
        assert "MASS_MAIL" not in RuleEngine(config=DEFAULTS).evaluate(f)  # ...but not alerted on

    def test_turning_it_on_in_the_config_file(self, tmp_path):
        path = tmp_path / "detection.toml"
        path.write_text("[mass_mail]\nenabled = true\n")
        f = TestMassMail.mail(FlowTracker(), 40, spacing=1.5)
        assert "MASS_MAIL" in RuleEngine(config=load_config(str(path))).evaluate(f)


def _quiet():
    """Features for an unremarkable packet, so only the rule under test can fire."""
    return {"syn_ratio": 0.0, "packet_rate": 1, "unanswered_syn_ports": 0, "packet_size": 60,
            "packet_has_ack": 1, "avg_packet_size": 60, "ack_ratio": 1, "total_packets": 1, "flow_duration": 1}
