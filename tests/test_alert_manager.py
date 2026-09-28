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
