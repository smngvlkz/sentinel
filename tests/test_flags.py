"""Unit tests for common.flags.env_flag, shared by capture and the analyzer."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from common.flags import env_flag


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " On "])
def test_on(value):
    assert env_flag(value) is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "maybe"])
def test_off(value):
    assert env_flag(value) is False


@pytest.mark.parametrize("value", [None, "", "   "])
def test_unset_or_blank(value):
    """Compose passes an unset variable as an empty string: that's unset, not off."""
    assert env_flag(value) is None
