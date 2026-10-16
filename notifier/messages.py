"""
What a notification says. Built once and stored with the notification, so
every channel and every retry sends the same text.

A message is a dict: title, body, severity, url (may be empty), and for a
single alert a repeat_key that's the same for repeats of that alert.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any
from zoneinfo import ZoneInfo

from common.threats import SEVERITIES, threat_info

Message = dict[str, str]


def display_name(ip: str | None, device: str | None, learned: str | None, ips_only: bool) -> str:
    """
    How to show one end of an alert. A name you gave the device stands on its
    own. A hostname learned from traffic gets its IP next to it, because
    whoever sent the traffic chose that name.
    """
    ip = ip or "?"
    if ips_only:
        return ip
    if device:
        return device
    if learned:
        return f"{learned} ({ip})"
    return ip


def _local(ts: Any, zone: ZoneInfo) -> dt.datetime:
    if isinstance(ts, dt.datetime):
        when = ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)
    else:
        when = dt.datetime.fromtimestamp(float(ts), dt.timezone.utc)
    return when.astimezone(zone)


def alert_url(dashboard_url: str, alert_id: int | None = None) -> str:
    if not dashboard_url:
        return ""
    return f"{dashboard_url}/?alert={alert_id}" if alert_id is not None else f"{dashboard_url}/"


def for_alert(alert: dict[str, Any], dashboard_url: str, zone: ZoneInfo, ips_only: bool = False) -> Message:
    """One alert: what happened, between which devices, and when."""
    info = threat_info(str(alert["threat_type"]))
    src = display_name(alert.get("source_ip"), alert.get("source_device"), alert.get("source_name"), ips_only)
    dst = display_name(
        alert.get("destination_ip"), alert.get("destination_device"), alert.get("destination_name"), ips_only
    )
    when = _local(alert["timestamp"], zone)
    headline = info.headline.format(src=src, dst=dst)
    return {
        "title": info.name,
        "body": f"{headline}.\n{info.severity.capitalize()} severity, at {when:%H:%M:%S}.",
        "severity": info.severity,
        "url": alert_url(dashboard_url, int(alert["id"])),
        # Alerts that would read the same are repeats of one another.
        "repeat_key": f"{alert['threat_type']}|{repeat_headline(alert)}",
    }


def repeat_headline(alert: dict[str, Any]) -> str:
    """The headline with addresses only, so renaming a device doesn't break repeat detection."""
    info = threat_info(str(alert["threat_type"]))
    return info.headline.format(src=alert.get("source_ip") or "?", dst=alert.get("destination_ip") or "?")


def digest(alerts: list[dict[str, Any]], dashboard_url: str, zone: ZoneInfo, ips_only: bool = False) -> Message:
    """
    Several alerts held back by quiet hours or the hourly limit, as one
    message: how many of each kind, most urgent first. A single held alert
    is sent as itself.
    """
    if len(alerts) == 1:
        return for_alert(alerts[0], dashboard_url, zone, ips_only)
    kinds = Counter(threat_info(str(a["threat_type"])) for a in alerts)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    lines = [
        f"{n} × {info.name}" + (" (high)" if info.severity == "high" else "")
        for info, n in sorted(kinds.items(), key=lambda kv: (rank[kv[0].severity], -kv[1], kv[0].name))
    ]
    first = min(_local(a["timestamp"], zone) for a in alerts)
    last = max(_local(a["timestamp"], zone) for a in alerts)
    span = f"{first:%H:%M}–{last:%H:%M}" if first.date() == last.date() else f"{first:%d %b %H:%M} – {last:%d %b %H:%M}"
    worst = min((threat_info(str(a["threat_type"])).severity for a in alerts), key=rank.__getitem__)
    return {
        "title": f"{len(alerts)} alerts held back",
        "body": "\n".join(lines) + f"\nBetween {span}.",
        "severity": worst,
        "url": alert_url(dashboard_url),
    }


def test(dashboard_url: str) -> Message:
    return {
        "title": "SentinelAI test notification",
        "body": "Notifications from SentinelAI are working.",
        "severity": "low",
        "url": alert_url(dashboard_url),
    }
