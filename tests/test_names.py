"""Unit tests for analysis_service.names.NameCache."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from analysis_service.names import NameCache, parse_bindings, valid_hostname
from capture_service.capture import _valid_hostname

# 253 characters: the longest a DNS name can be.
LONGEST = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])

# Real names that must survive, including the awkward ones.
VALID = [
    ("API.Example.COM.", "api.example.com"),          # case and trailing dot
    ("api2.cursor.sh", "api2.cursor.sh"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),  # punycode (bücher)
    ("my-service.eu-west-1.example.co.za", "my-service.eu-west-1.example.co.za"),
    ("_dmarc.example.com", "_dmarc.example.com"),     # underscores occur in real DNS
    ("r2---sn-54gpivnu15-q0ge.gvt1.com", "r2---sn-54gpivnu15-q0ge.gvt1.com"),
    ("localhost", "localhost"),
    (LONGEST, LONGEST),
    ("a" * 63 + ".com", "a" * 63 + ".com"),
]

# Anything else is dropped whole, never cleaned into a different name.
INVALID = [
    "",
    ".",
    "pay<b>pal.com",                     # cleaning would give paybpal.com
    "<img src=x onerror=alert(1)>",
    "evil\x00.name",
    "two words.com",
    'quote".com',
    "o'reilly.com",
    "host.com\r\nX-Injected: 1",
    "bücher.de",                         # not punycode-encoded
    "a..b.com",
    ".leading.com",
    "a" * 64 + ".com",                   # label longer than 63
    LONGEST + "e",                       # 254 characters
    "\u202eexe.txt.com",                 # right-to-left override
]


@pytest.mark.parametrize("raw,expected", VALID)
def test_valid_names_pass_in_both(raw, expected):
    assert valid_hostname(raw) == expected
    assert _valid_hostname(raw) == expected


@pytest.mark.parametrize("raw", INVALID)
def test_invalid_names_dropped_in_both(raw):
    assert valid_hostname(raw) is None
    assert _valid_hostname(raw) is None


class TestParseBindings:

    def test_valid(self):
        packet = {"name_bindings": json.dumps([["1.2.3.4", "Api.Example.COM."]])}
        assert parse_bindings(packet) == [("1.2.3.4", "api.example.com", None)]

    def test_missing_or_junk(self):
        assert parse_bindings({}) == []
        assert parse_bindings({"name_bindings": "not-json"}) == []
        assert parse_bindings({"name_bindings": json.dumps([["only-one"]])}) == []

    def test_invalid_name_dropped(self):
        packet = {"name_bindings": json.dumps([["1.2.3.4", "pay<b>pal.com", "10.0.0.5"]])}
        assert parse_bindings(packet) == []


class TestNameCache:

    def test_observe_and_lookup(self):
        cache = NameCache(max_entries=10, ttl_seconds=60)
        cache.observe({"name_bindings": json.dumps([["1.2.3.4", "api.example.com"]])}, now=1000.0)
        assert cache.lookup("1.2.3.4", now=1010.0) == "api.example.com"
        assert cache.lookup("9.9.9.9", now=1010.0) is None

    def test_resolve_for_alerts(self):
        cache = NameCache()
        cache.observe(
            {"name_bindings": json.dumps([["1.2.3.4", "api.example.com"], ["10.0.0.1", "laptop.local"]])},
            now=1.0,
        )
        assert cache.resolve("1.2.3.4", "10.0.0.1", "8.8.8.8", now=2.0) == {
            "1.2.3.4": "api.example.com",
            "10.0.0.1": "laptop.local",
        }

    def test_ttl_expires(self):
        cache = NameCache(ttl_seconds=30)
        cache.observe({"name_bindings": json.dumps([["1.2.3.4", "api.example.com"]])}, now=1000.0)
        assert cache.lookup("1.2.3.4", now=1040.0) is None

    def test_lru_eviction(self):
        cache = NameCache(max_entries=2, ttl_seconds=1000)
        cache.observe({"name_bindings": json.dumps([["1.1.1.1", "a"]])}, now=1.0)
        cache.observe({"name_bindings": json.dumps([["2.2.2.2", "b"]])}, now=2.0)
        cache.observe({"name_bindings": json.dumps([["3.3.3.3", "c"]])}, now=3.0)
        assert cache.lookup("1.1.1.1", now=4.0) is None
        assert cache.lookup("2.2.2.2", now=4.0) == "b"
        assert cache.lookup("3.3.3.3", now=4.0) == "c"

    def test_prune(self):
        cache = NameCache(ttl_seconds=10)
        cache.observe({"name_bindings": json.dumps([["1.1.1.1", "a"]])}, now=100.0)
        cache.observe({"name_bindings": json.dumps([["2.2.2.2", "b"]])}, now=200.0)
        assert cache.prune(now=205.0) == 1
        assert list(cache._entries) == ["2.2.2.2"]


class TestPerDevice:

    def bind(self, cache, ip, name, client, now):
        cache.observe({"name_bindings": json.dumps([[ip, name, client]])}, now=now)

    def test_device_specific_name_wins(self):
        """Two devices reach different sites behind one CDN address."""
        cache = NameCache()
        self.bind(cache, "104.18.0.1", "api2.cursor.sh", "10.0.0.5", now=1.0)
        self.bind(cache, "104.18.0.1", "news.example", "10.0.0.9", now=2.0)
        assert cache.lookup("104.18.0.1", now=3.0, client="10.0.0.5") == "api2.cursor.sh"
        assert cache.lookup("104.18.0.1", now=3.0, client="10.0.0.9") == "news.example"
        # Unknown device falls back to the latest name.
        assert cache.lookup("104.18.0.1", now=3.0, client="10.0.0.7") == "news.example"
        assert cache.lookup("104.18.0.1", now=3.0) == "news.example"

    def test_resolve_pairs_looks_up_from_the_other_end(self):
        cache = NameCache()
        self.bind(cache, "104.18.0.1", "api2.cursor.sh", "10.0.0.5", now=1.0)
        self.bind(cache, "104.18.0.1", "news.example", "10.0.0.9", now=2.0)
        assert cache.resolve_pairs([("10.0.0.5", "104.18.0.1")], now=3.0) == {"104.18.0.1": "api2.cursor.sh"}
        # Reversed orientation (server → device) resolves the same way.
        assert cache.resolve_pairs([("104.18.0.1", "10.0.0.9")], now=3.0) == {"104.18.0.1": "news.example"}

    def test_two_entries_per_binding_count_toward_cap(self):
        cache = NameCache(max_entries=2)
        self.bind(cache, "1.1.1.1", "a", "10.0.0.5", now=1.0)
        assert len(cache) == 2
        self.bind(cache, "2.2.2.2", "b", "10.0.0.5", now=2.0)
        assert len(cache) == 2
        assert cache.lookup("1.1.1.1", now=3.0, client="10.0.0.5") is None


class TestDroppedNamesNeverOverwrite:

    def test_bad_name_keeps_the_good_one(self):
        """A later hostile name for the same IP must not replace the real one."""
        cache = NameCache()
        cache.observe({"name_bindings": json.dumps([["1.2.3.4", "api.example.com", "10.0.0.5"]])}, now=1.0)
        cache.observe({"name_bindings": json.dumps([["1.2.3.4", "<script>.com", "10.0.0.5"]])}, now=2.0)
        assert cache.lookup("1.2.3.4", now=3.0, client="10.0.0.5") == "api.example.com"
        assert cache.lookup("1.2.3.4", now=3.0) == "api.example.com"

    def test_no_name_means_the_alert_shows_the_ip(self):
        """Nothing stored, so the alert gets no name and the dashboard shows the IP."""
        cache = NameCache()
        cache.observe({"name_bindings": json.dumps([["1.2.3.4", "bad name", "10.0.0.5"]])}, now=1.0)
        assert cache.resolve_pairs([("10.0.0.5", "1.2.3.4")], now=2.0) == {}
