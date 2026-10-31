"""
Triage settings, from config/triage.toml. Any value missing from the file
falls back to the default below. A setting that can't work is a ConfigError,
so triage can say exactly what to fix instead of quietly doing nothing.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from typing import Any

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "triage.toml")

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "url": "http://host.docker.internal:11434",
    "model": "qwen3.5",
    "digest": "6488c96fa5fa",
    "timeout_seconds": 120,
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    enabled: bool = DEFAULTS["enabled"]
    url: str = DEFAULTS["url"]
    model: str = DEFAULTS["model"]
    digest: str = DEFAULTS["digest"]
    timeout_seconds: float = DEFAULTS["timeout_seconds"]


def load(path: str | None = None) -> Settings:
    """Read and check the settings. Raises ConfigError if they can't work."""
    path = path or os.getenv("SENTINEL_TRIAGE_CONFIG") or DEFAULT_PATH
    raw = dict(DEFAULTS)
    if os.path.exists(path):
        with open(path, "rb") as f:
            try:
                overrides = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise ConfigError(f"{os.path.basename(path)} isn't valid TOML: {e}") from None
        for section, values in overrides.items():
            if section != "triage" or not isinstance(values, dict):
                raise ConfigError(f"unknown section [{section}]")
            for key, value in values.items():
                if key not in raw:
                    raise ConfigError(f"unknown setting triage.{key}")
                raw[key] = value

    if not isinstance(raw["enabled"], bool):
        raise ConfigError(f"enabled must be true or false, not {raw['enabled']!r}")
    url = str(raw["url"]).strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ConfigError(f"url must start with http:// or https://, not {url!r}")
    model, digest = str(raw["model"]).strip(), str(raw["digest"]).strip().lower()
    if not model:
        raise ConfigError("model can't be empty")
    if len(digest) < 12 or any(c not in "0123456789abcdef" for c in digest):
        raise ConfigError(f"digest must be at least the first 12 characters of the model's digest, not {digest!r}")
    try:
        timeout = float(raw["timeout_seconds"])
    except (TypeError, ValueError):
        timeout = 0
    if timeout <= 0:
        raise ConfigError(f"timeout_seconds must be more than 0, not {raw['timeout_seconds']!r}")
    return Settings(raw["enabled"], url, model, digest, timeout)
