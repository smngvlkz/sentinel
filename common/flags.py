"""On/off settings from the environment, read the same way everywhere."""

from __future__ import annotations

_ON = ("1", "true", "yes", "on")


def env_flag(value: str | None) -> bool | None:
    """
    True or False for a set value, or None when it's unset or blank (compose
    passes an unset variable as an empty string). Anything other than
    1/true/yes/on, in any case, is off.
    """
    if value is None or not value.strip():
        return None
    return value.strip().lower() in _ON
