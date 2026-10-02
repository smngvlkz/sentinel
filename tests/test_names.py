"""Unit tests for analysis_service.names.NameCache."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis_service.names import NameCache, parse_bindings, sanitize_name


class TestSanitize:

    def test_basic(self):
        assert sanitize_name("Foo.BAR.") == "foo.bar"

    def test_rejects_blank(self):
        assert sanitize_name("") is None


class TestParseBindings:

    def test_valid(self):
        packet = {"name_bindings": json.dumps([["1.2.3.4", "Api.Example.COM."]])}
        assert parse_bindings(packet) == [("1.2.3.4", "api.example.com", None)]

    def test_missing_or_junk(self):
        assert parse_bindings({}) == []
        assert parse_bindings({"name_bindings": "not-json"}) == []
        assert parse_bindings({"name_bindings": json.dumps([["only-one"]])}) == []


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
