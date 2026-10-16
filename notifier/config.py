"""
Notification settings, from config/notifications.toml plus secrets from the
environment (.env). Any value missing from the file falls back to the default
below. A setting that can't work (an unknown severity, a quiet-hours time
that isn't HH:MM) is a ConfigError, so the notifier can say exactly what to
fix instead of quietly sending nothing.
"""

from __future__ import annotations

import copy
import datetime as dt
import os
import tomllib
from dataclasses import dataclass, field
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from common.threats import SEVERITIES

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "notifications.toml")

DEFAULTS: dict[str, dict[str, Any]] = {
    "notifications": {
        "enabled": False,
        "min_severity": "high",
        "dashboard_url": "",
        "ips_only": False,
        "max_per_hour": 10,
        "repeat_minutes": 60,
        "timezone": "UTC",
    },
    "quiet_hours": {
        "enabled": False,
        "start": "22:00",
        "end": "07:00",
        "let_high_through": True,
    },
    "ntfy": {"enabled": False, "server": "http://ntfy"},
    "email": {
        "enabled": False,
        "host": "",
        "port": 587,
        "starttls": True,
        "username": "",
        "from": "",
        "to": "",
    },
    "webhook": {"enabled": False, "format": "json", "telegram_chat_id": ""},
}

WEBHOOK_FORMATS = ("json", "discord", "slack", "telegram")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class QuietHours:
    start: dt.time
    end: dt.time
    let_high_through: bool

    def active(self, local: dt.time) -> bool:
        """Whether the local time `local` falls in quiet hours. A window may cross midnight."""
        t = local
        if self.start <= self.end:
            return self.start <= t < self.end
        return t >= self.start or t < self.end


@dataclass(frozen=True)
class Settings:
    enabled: bool = False
    min_severity: str = "high"
    dashboard_url: str = ""
    ips_only: bool = False
    max_per_hour: int = 10
    repeat_minutes: float = 60
    zone: ZoneInfo = field(default_factory=lambda: ZoneInfo("UTC"))
    quiet: QuietHours | None = None
    # name -> that channel's settings, for the channels turned on
    channels: dict[str, dict[str, Any]] = field(default_factory=dict)


def _time(value: Any, key: str) -> dt.time:
    try:
        return dt.time.fromisoformat(str(value))
    except ValueError:
        raise ConfigError(f"quiet_hours.{key} must be a time like \"22:00\", not {value!r}") from None


def _require(section: str, values: dict[str, Any], keys: list[str]) -> None:
    missing = [k for k in keys if not str(values.get(k) or "").strip()]
    if missing:
        raise ConfigError(f"[{section}] is enabled but has no {', '.join(missing)}")


def load(path: str | None = None, env: dict[str, str] | None = None) -> Settings:
    """Read and check the settings. Raises ConfigError if they can't work."""
    path = path or os.getenv("SENTINEL_NOTIFICATIONS_CONFIG") or DEFAULT_PATH
    env = dict(os.environ) if env is None else env
    raw = copy.deepcopy(DEFAULTS)
    if os.path.exists(path):
        with open(path, "rb") as f:
            try:
                overrides = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise ConfigError(f"{os.path.basename(path)} isn't valid TOML: {e}") from None
        for section, values in overrides.items():
            if section not in raw or not isinstance(values, dict):
                raise ConfigError(f"unknown section [{section}]")
            for key, value in values.items():
                if key not in raw[section]:
                    raise ConfigError(f"unknown setting {section}.{key}")
                raw[section][key] = value

    n = raw["notifications"]
    if n["min_severity"] not in SEVERITIES:
        raise ConfigError(f"min_severity must be one of {', '.join(SEVERITIES)}, not {n['min_severity']!r}")
    try:
        max_per_hour = int(n["max_per_hour"])
    except (TypeError, ValueError):
        max_per_hour = 0
    if max_per_hour < 1:
        raise ConfigError(f"max_per_hour must be a whole number of at least 1, not {n['max_per_hour']!r}")
    try:
        repeat_minutes = float(n["repeat_minutes"])
    except (TypeError, ValueError):
        repeat_minutes = -1
    if repeat_minutes < 0:
        raise ConfigError(f"repeat_minutes must be 0 or more, not {n['repeat_minutes']!r}")
    url = str(n["dashboard_url"]).strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        raise ConfigError(f"dashboard_url must start with http:// or https://, not {url!r}")

    try:
        zone = ZoneInfo(str(n["timezone"]))
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"timezone {n['timezone']!r} isn't a known time zone") from None

    quiet = None
    q = raw["quiet_hours"]
    if q["enabled"]:
        start, end = _time(q["start"], "start"), _time(q["end"], "end")
        if start == end:
            raise ConfigError("quiet_hours.start and end are the same time")
        quiet = QuietHours(start, end, bool(q["let_high_through"]))

    channels: dict[str, dict[str, Any]] = {}
    if raw["ntfy"]["enabled"]:
        ntfy = {
            "server": str(raw["ntfy"]["server"]).strip().rstrip("/"),
            "topic": env.get("NTFY_TOPIC", "").strip(),
            "token": env.get("NTFY_TOKEN", "").strip(),
        }
        if not ntfy["server"].startswith(("http://", "https://")):
            raise ConfigError(f"ntfy.server must start with http:// or https://, not {ntfy['server']!r}")
        if not ntfy["topic"]:
            raise ConfigError("ntfy is enabled but NTFY_TOPIC isn't set in .env")
        channels["ntfy"] = ntfy
    if raw["email"]["enabled"]:
        email = dict(raw["email"])
        del email["enabled"]
        _require("email", email, ["host", "from", "to"])
        email["port"] = int(email["port"])
        email["password"] = env.get("SMTP_PASSWORD", "")
        if email["username"] and not email["password"]:
            raise ConfigError("[email] has a username but SMTP_PASSWORD isn't set in .env")
        channels["email"] = email
    if raw["webhook"]["enabled"]:
        hook = {
            "format": str(raw["webhook"]["format"]),
            "telegram_chat_id": str(raw["webhook"]["telegram_chat_id"]).strip(),
            "url": env.get("WEBHOOK_URL", "").strip(),
        }
        if hook["format"] not in WEBHOOK_FORMATS:
            raise ConfigError(f"webhook.format must be one of {', '.join(WEBHOOK_FORMATS)}, not {hook['format']!r}")
        if not hook["url"].startswith(("http://", "https://")):
            raise ConfigError("webhook is enabled but WEBHOOK_URL in .env isn't an http(s) URL")
        if hook["format"] == "telegram" and not hook["telegram_chat_id"]:
            raise ConfigError("webhook.format is telegram but telegram_chat_id is empty")
        channels["webhook"] = hook

    enabled = bool(n["enabled"])
    if enabled and not channels:
        raise ConfigError("notifications are enabled but no channel is (ntfy, email or webhook)")
    return Settings(
        enabled=enabled,
        min_severity=n["min_severity"],
        dashboard_url=url,
        ips_only=bool(n["ips_only"]),
        max_per_hour=max_per_hour,
        repeat_minutes=repeat_minutes,
        zone=zone,
        quiet=quiet,
        channels=channels,
    )
