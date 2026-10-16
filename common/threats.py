"""
Each threat type's severity, name and one-line headline, for everything in
Python that shows alerts to people: the dashboard API filters and counts by
severity, and notifications use the names and headlines.

Keep in sync with dashboard/src/lib/threats.ts.
"""

from __future__ import annotations

from typing import NamedTuple


class Threat(NamedTuple):
    severity: str
    name: str
    # Formatted with src= and dst=, each already a display name.
    headline: str


THREATS: dict[str, Threat] = {
    "SYN_FLOOD": Threat("high", "Connection flood", "{src} flooded {dst} with connection requests"),
    "PORT_SCAN": Threat("medium", "Port scan", "{src} checked which ports are open on {dst}"),
    "HIGH_FREQUENCY": Threat("medium", "Traffic burst", "{src} sent an unusually fast burst of traffic to {dst}"),
    "LARGE_PAYLOAD": Threat("low", "Oversized packet", "{src} sent an oversized packet to {dst}"),
    "ANOMALY": Threat("medium", "Unusual traffic", "Traffic from {src} to {dst} didn't match your normal patterns"),
    "REQUEST_FLOOD": Threat("high", "Request flood", "{src} flooded {dst} with requests"),
    "DISTRIBUTED_FLOOD": Threat("high", "Distributed flood", "Many internet hosts converged on {dst}"),
    "NETWORK_SWEEP": Threat("medium", "Network sweep", "{src} probed many devices on your network"),
    "BEACONING": Threat("medium", "Regular check-ins", "{src} keeps checking in with {dst}"),
    "RESOURCE_PRESSURE": Threat(
        "high", "Memory limit reached", "SentinelAI ran out of room tracking traffic around {dst}"
    ),
}

# How urgent each threat type is. Unknown types count as low.
SEVERITY: dict[str, str] = {t: info.severity for t, info in THREATS.items()}
SEVERITIES = ("high", "medium", "low")
_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # low 0, medium 1, high 2


def threat_info(threat_type: str) -> Threat:
    """The threat's details, or a plain fallback for a type this list doesn't know (low)."""
    known = THREATS.get(threat_type)
    if known is not None:
        return known
    name = threat_type.replace("_", " ").lower().capitalize()
    return Threat("low", name, "{src} triggered a " + threat_type.replace("{", "").replace("}", "") + " alert against {dst}")


def severity_of(threat_type: str) -> str:
    return SEVERITY.get(threat_type, "low")


def at_least(severity: str, minimum: str) -> bool:
    """Whether `severity` is `minimum` or more urgent."""
    return _RANK.get(severity, 0) >= _RANK.get(minimum, 0)
