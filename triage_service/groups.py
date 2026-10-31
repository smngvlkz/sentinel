"""
Alert groups, the unit triage gives an opinion on: the alerts with the same
rule and ends, with "*" on the side that changes for rules that alert on many
hosts (as the alert manager groups repeats), joined while each comes within
GAP of the previous one. The same grouping as the triage evaluation.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from common.threats import ALERT_GROUP

GAP = dt.timedelta(minutes=10)

Key = tuple[str, str, str]


def key(alert: dict[str, Any]) -> Key:
    t, side = str(alert["threat_type"]), ALERT_GROUP.get(str(alert["threat_type"]))
    source = "*" if side == "destination" else str(alert["source_ip"])
    destination = "*" if side == "source" else str(alert["destination_ip"])
    return (t, source, destination)


@dataclass
class Group:
    threat_type: str
    source_ip: str
    destination_ip: str
    first_alert_id: int
    last_alert_id: int
    first_at: dt.datetime
    last_at: dt.datetime
    alert_count: int = 1
    id: int | None = None  # None until stored

    @property
    def key(self) -> Key:
        return (self.threat_type, self.source_ip, self.destination_ip)


def add(open_groups: dict[Key, Group], alerts: list[dict[str, Any]]) -> tuple[list[Group], list[Group]]:
    """
    Add alerts (in the order they were stored) to the open groups, updating
    `open_groups` in place. Returns (groups now closed because a later alert
    came more than GAP after them, open groups that changed).
    """
    closed: list[Group] = []
    changed: dict[Key, Group] = {}
    for alert in alerts:
        k, at, alert_id = key(alert), alert["timestamp"], int(alert["id"])
        group = open_groups.get(k)
        if group is not None and at - group.last_at <= GAP:
            group.last_alert_id = max(group.last_alert_id, alert_id)
            group.last_at = max(group.last_at, at)
            group.alert_count += 1
        else:
            if group is not None:
                closed.append(group)
                changed.pop(k, None)
            group = Group(*k, alert_id, alert_id, at, at)
            open_groups[k] = group
        changed[k] = group
    return closed, list(changed.values())
