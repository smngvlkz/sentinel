"""
Detection configuration.

Thresholds live in config/detection.toml so they can be tuned per network
without code changes. Any value missing from the file falls back to the
built-in default below, so a partial config file is valid.
"""

from __future__ import annotations

import copy
import logging
import os
import tomllib
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "detection.toml")

DEFAULTS: dict[str, dict[str, float]] = {
    "syn_flood": {"min_syn_ratio": 0.8, "min_packet_rate": 50},
    "port_scan": {"min_unique_ports": 20},
    "large_payload": {"min_packet_size": 10_000},
    "high_frequency": {"min_packet_rate": 1000, "max_avg_packet_size": 300, "max_ack_ratio": 0.5},
    "request_flood": {"min_new_connections_10s": 400},
    "distributed_flood": {"min_external_sources_60s": 50},
    "network_sweep": {"min_local_hosts_60s": 20},
    # Off by default: scheduled software and busy web pages check in the same way (see docs/evaluation.md).
    "beaconing": {"enabled": False, "min_checkins_per_hour": 30, "min_active_slots": 11, "repeat_alert_seconds": 3600},
    "rate_evidence": {"min_packets": 10, "min_duration_seconds": 0.1},
    "anomaly": {"judge_interval_seconds": 5},
    "alerts": {"cooldown_seconds": 60},
    # Off by default: learning DNS/HTTP names is a privacy trade-off. Also set
    # PAYLOAD_INSPECTION=true so capture extracts the bindings.
    "names": {"enabled": False, "max_entries": 10_000, "ttl_seconds": 86_400},
    # Hard caps on the analyzer's in-memory tables; see config/detection.toml.
    "limits": {
        "max_flows": 50_000,
        "max_connections": 200_000,
        "max_hosts": 50_000,
        "max_services": 50_000,
        "max_sweeps": 50_000,
        "max_window_events": 10_000,
        "max_beacon_series": 50_000,
        "max_alert_cooldowns": 10_000,
        "max_judged_flows": 50_000,
    },
    # Old alerts are deleted so the database can't fill the disk; see config/detection.toml.
    "retention": {"max_age_days": 90, "max_alerts": 500_000},
}


def load_config(path: str | None = None) -> dict[str, dict[str, float]]:
    path = path or os.getenv("SENTINEL_CONFIG") or DEFAULT_CONFIG_PATH
    config = copy.deepcopy(DEFAULTS)

    if not os.path.exists(path):
        log.info("no config at %s, using default thresholds", path)
        return config

    with open(path, "rb") as f:
        overrides: dict[str, Any] = tomllib.load(f)

    for section, values in overrides.items():
        if section not in config:
            log.warning("ignoring unknown config section [%s] in %s", section, path)
            continue
        for key, value in values.items():
            if key not in config[section]:
                log.warning("ignoring unknown config key %s.%s in %s", section, key, path)
                continue
            config[section][key] = value

    log.info("loaded detection config from %s", path)
    return config


def has_rate_evidence(features: dict[str, float], config: dict[str, dict[str, float]]) -> bool:
    """
    Whether a flow has enough history for its rates to mean anything.

    One packet over the 1ms duration floor reads as 1000 packets/second, so
    rate-based rules and the anomaly model both skip flows younger than this.
    """
    c = config["rate_evidence"]
    return features["total_packets"] >= c["min_packets"] and features["flow_duration"] >= c["min_duration_seconds"]
