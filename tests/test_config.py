"""Unit tests for detection_engine.config.load_config."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection_engine.config import DEFAULT_CONFIG_PATH, DEFAULTS, load_config
from detection_engine.rules import RuleEngine


def test_missing_file_uses_defaults(tmp_path):
    assert load_config(str(tmp_path / "nope.toml")) == DEFAULTS


def test_shipped_config_matches_defaults():
    """config/detection.toml documents the defaults; keep them in sync."""
    assert load_config(DEFAULT_CONFIG_PATH) == DEFAULTS


def test_partial_file_overrides_only_given_keys(tmp_path):
    path = tmp_path / "detection.toml"
    path.write_text("[port_scan]\nmin_unique_ports = 100\n")
    config = load_config(str(path))
    assert config["port_scan"]["min_unique_ports"] == 100
    assert config["syn_flood"] == DEFAULTS["syn_flood"]


def test_unknown_keys_ignored(tmp_path):
    path = tmp_path / "detection.toml"
    path.write_text("[port_scan]\nmin_ports = 5\n[bogus]\nx = 1\n")
    assert load_config(str(path)) == DEFAULTS


def test_env_var_selects_file(tmp_path, monkeypatch):
    path = tmp_path / "detection.toml"
    path.write_text("[large_payload]\nmin_packet_size = 500\n")
    monkeypatch.setenv("SENTINEL_CONFIG", str(path))
    assert load_config()["large_payload"]["min_packet_size"] == 500


def test_does_not_mutate_defaults(tmp_path):
    path = tmp_path / "detection.toml"
    path.write_text("[port_scan]\nmin_unique_ports = 3\n")
    load_config(str(path))
    assert DEFAULTS["port_scan"]["min_unique_ports"] == 20


def test_rule_engine_uses_config():
    config = load_config("/nonexistent")
    config["port_scan"]["min_unique_ports"] = 5
    features = {"syn_ratio": 0.0, "packet_rate": 1, "unanswered_syn_ports": 6, "packet_size": 64, "packet_has_ack": 0}
    assert RuleEngine(config=config).evaluate(features) == ["PORT_SCAN"]
