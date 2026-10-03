"""Unit tests for dashboard-api helpers that need no database."""

import importlib.util
import os
import sys

import pytest

if "dashboard_api_main" in sys.modules:  # already loaded by another test file
    api = sys.modules["dashboard_api_main"]
else:
    _spec = importlib.util.spec_from_file_location(
        "dashboard_api_main",
        os.path.join(os.path.dirname(__file__), "..", "dashboard-api", "main.py"),
    )
    api = importlib.util.module_from_spec(_spec)
    # Registered so pydantic can resolve the module's postponed type hints.
    sys.modules[_spec.name] = api
    _spec.loader.exec_module(api)


class TestStreamEntryAge:

    def test_none_when_stream_empty(self):
        assert api.stream_entry_age(None, 1000.0) is None

    def test_age_from_entry_id(self):
        assert api.stream_entry_age("995000-0", 1000.0) == pytest.approx(5.0)

    def test_sequence_suffix_ignored(self):
        assert api.stream_entry_age("995000-42", 1000.0) == pytest.approx(5.0)

    def test_clock_skew_never_negative(self):
        assert api.stream_entry_age("1005000-0", 1000.0) == 0.0


class TestAlertFilter:

    def test_window_only(self):
        where, params = api.alert_filter(24)
        assert where == "timestamp > NOW() - make_interval(hours => %s)"
        assert params == [24]

    def test_high_matches_high_types(self):
        where, params = api.alert_filter(24, "high")
        assert "threat_type = ANY(%s)" in where
        assert params[1] == [t for t, sev in api.SEVERITY.items() if sev == "high"]

    def test_low_includes_unknown_types(self):
        """Low is 'anything not high or medium', so new rule types still show up."""
        where, params = api.alert_filter(24, "low")
        assert "threat_type <> ALL(%s)" in where
        assert set(params[1]) == {t for t, sev in api.SEVERITY.items() if sev != "low"}

    def test_review_status(self):
        assert "reviewed_at IS NULL" in api.alert_filter(24, status="unreviewed")[0]
        assert "reviewed_at IS NOT NULL" in api.alert_filter(24, status="reviewed")[0]
        assert "reviewed_at" not in api.alert_filter(24, status="all")[0]

    def test_every_severity_is_valid(self):
        assert set(api.SEVERITY.values()) <= set(api.SEVERITIES)


class TestReviewRequest:

    def test_by_ids(self):
        assert api.ReviewRequest(ids=[1, 2]).ids == [1, 2]

    def test_by_filter(self):
        req = api.ReviewRequest(hours=24, severity="high")
        assert (req.hours, req.severity, req.reviewed) == (24, "high", True)

    def test_needs_exactly_one_target(self):
        with pytest.raises(ValueError):
            api.ReviewRequest()
        with pytest.raises(ValueError):
            api.ReviewRequest(ids=[1], hours=24)


class TestMutationGuard:
    """POSTs from other websites must be refused; the API has no auth."""

    def test_dashboard_origin_allowed(self):
        api.check_mutation_headers("http://localhost:3001", "application/json")

    def test_no_origin_allowed_for_scripts(self):
        """curl and scripts don't send Origin; they're already on this machine."""
        api.check_mutation_headers(None, "application/json")

    def test_other_origin_refused(self):
        with pytest.raises(api.HTTPException) as e:
            api.check_mutation_headers("https://evil.example", "application/json")
        assert e.value.status_code == 403

    def test_non_json_refused(self):
        """Form posts and text/plain skip the CORS preflight, so they're refused."""
        with pytest.raises(api.HTTPException) as e:
            api.check_mutation_headers("http://localhost:3001", "text/plain")
        assert e.value.status_code == 415


class TestDeviceNameRequest:

    def test_normalises_ip_and_name(self):
        body = api.DeviceNameRequest(ip=" 192.168.1.50 ", name="  Alex's   laptop\n")
        assert body.ip == "192.168.1.50"
        assert body.name == "Alex's laptop"

    def test_ipv6_normalised(self):
        assert api.DeviceNameRequest(ip="FE80::1", name="Pi").ip == "fe80::1"

    def test_blank_name_means_remove(self):
        assert api.DeviceNameRequest(ip="10.0.0.1", name="   ").name is None
        assert api.DeviceNameRequest(ip="10.0.0.1").name is None

    def test_rejects_bad_ip(self):
        with pytest.raises(ValueError):
            api.DeviceNameRequest(ip="not-an-ip", name="x")

    def test_rejects_long_name(self):
        with pytest.raises(ValueError):
            api.DeviceNameRequest(ip="10.0.0.1", name="x" * 65)


def test_alert_select_joins_device_names():
    sql = api.alert_select("'low'")
    assert "LEFT JOIN device_names sd ON sd.ip = alerts.source_ip" in sql
    assert "LEFT JOIN device_names dd ON dd.ip = alerts.destination_ip" in sql


def test_api_and_dashboard_agree_on_severity():
    """The API filters and counts by severity; the dashboard labels by it. They must match."""
    import re

    ts = open(os.path.join(os.path.dirname(__file__), "..", "dashboard", "src", "lib", "threats.ts")).read()
    dashboard = dict(re.findall(r"\n  ([A-Z_]+): \{\n    name: \"[^\"]+\",\n    severity: \"(\w+)\"", ts))
    assert dashboard == api.SEVERITY
