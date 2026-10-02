"""Unit tests for alert_service.alert_manager.AlertManager deduplication."""

import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alert_service.alert_manager import AlertManager

SYN_FLOOD = {"type": "SYN_FLOOD", "source": "rules", "confidence": 0.9}
PORT_SCAN = {"type": "PORT_SCAN", "source": "rules", "confidence": 0.9}


def _packet(ts, src="10.0.0.99", dst="192.168.1.1"):
    return {"timestamp": str(ts), "src_ip": src, "dst_ip": dst}


@pytest.fixture
def manager():
    with patch.object(AlertManager, "_connect"), \
         patch.dict(os.environ, {"ALERT_COOLDOWN_SECONDS": "60"}):
        m = AlertManager()
    with patch.object(m, "_store") as store, patch.object(m, "_log") as log:
        m.store, m.log = store, log
        yield m


class TestAlertCooldown:

    def test_first_alert_emitted(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0), {})
        assert manager.store.call_count == 1

    def test_repeats_within_cooldown_suppressed(self, manager):
        """A 1000-packet flood produces one alert, not 1000."""
        for i in range(1000):
            manager.handle([SYN_FLOOD], _packet(1000.0 + i * 0.01), {})
        assert manager.store.call_count == 1

    def test_emits_again_after_cooldown_with_suppressed_count(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0), {})
        for i in range(5):
            manager.handle([SYN_FLOOD], _packet(1001.0 + i), {})
        manager.handle([SYN_FLOOD], _packet(1060.0), {})

        assert manager.store.call_count == 2
        assert manager.log.call_args_list[-1].args[2] == 5

    def test_different_threat_types_independent(self, manager):
        manager.handle([SYN_FLOOD, PORT_SCAN], _packet(1000.0), {})
        manager.handle([SYN_FLOOD, PORT_SCAN], _packet(1001.0), {})
        stored = [c.args[0]["type"] for c in manager.store.call_args_list]
        assert stored == ["SYN_FLOOD", "PORT_SCAN"]

    def test_different_sources_independent(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0, src="10.0.0.1"), {})
        manager.handle([SYN_FLOOD], _packet(1000.0, src="10.0.0.2"), {})
        assert manager.store.call_count == 2

    def test_different_destinations_independent(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0, dst="192.168.1.1"), {})
        manager.handle([SYN_FLOOD], _packet(1000.0, dst="192.168.1.2"), {})
        assert manager.store.call_count == 2


class TestPrune:

    def test_prune_removes_expired_only(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0, src="10.0.0.1"), {})
        manager.handle([SYN_FLOOD], _packet(1050.0, src="10.0.0.2"), {})

        assert manager.prune(now=1070.0) == 1
        assert list(manager._recent) == [("SYN_FLOOD", "10.0.0.2", "192.168.1.1")]

    def test_alert_emitted_after_prune(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0), {})
        manager.prune(now=1100.0)
        manager.handle([SYN_FLOOD], _packet(1100.0), {})
        assert manager.store.call_count == 2


class TestMultiHostGrouping:
    """Attacks involving many hosts must not become one alert per host."""

    def test_distributed_flood_is_one_alert_per_victim(self, manager):
        threat = {"type": "DISTRIBUTED_FLOOD", "source": "rules", "confidence": 0.9, "group": "destination"}
        for i in range(100):
            manager.handle([threat], _packet(1000.0 + i * 0.1, src=f"203.0.113.{i}"), {})
        assert manager.store.call_count == 1

    def test_distributed_floods_on_two_victims_are_separate(self, manager):
        threat = {"type": "DISTRIBUTED_FLOOD", "source": "rules", "confidence": 0.9, "group": "destination"}
        manager.handle([threat], _packet(1000.0, src="203.0.113.1", dst="192.168.1.10"), {})
        manager.handle([threat], _packet(1000.0, src="203.0.113.2", dst="192.168.1.11"), {})
        assert manager.store.call_count == 2

    def test_sweep_is_one_alert_per_scanner(self, manager):
        threat = {"type": "NETWORK_SWEEP", "source": "rules", "confidence": 0.9, "group": "source"}
        for i in range(50):
            manager.handle([threat], _packet(1000.0 + i * 0.1, src="192.168.1.66", dst=f"192.168.1.{100 + i}"), {})
        assert manager.store.call_count == 1

    def test_threat_endpoints_override_the_packet(self, manager):
        """Connection rules name the initiator even when a reply packet triggered them."""
        threat = {"type": "REQUEST_FLOOD", "source": "rules", "confidence": 0.9,
                  "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50"}
        reply = _packet(1000.0, src="192.168.10.50", dst="172.16.0.1")
        assert manager._endpoints(threat, reply)[:2] == ("172.16.0.1", "192.168.10.50")


class TestAlertNames:
    """Hostnames are context on the alert only; missing names stay None."""

    def test_names_passed_to_store(self, manager):
        manager.handle(
            [SYN_FLOOD],
            _packet(1000.0, src="10.0.0.1", dst="1.2.3.4"),
            {},
            names={"1.2.3.4": "api.example.com"},
        )
        assert manager.store.call_count == 1
        assert manager.store.call_args.args[3] == {"1.2.3.4": "api.example.com"}

    def test_without_names_still_stores(self, manager):
        manager.handle([SYN_FLOOD], _packet(1000.0), {})
        assert manager.store.call_args.args[3] == {}
