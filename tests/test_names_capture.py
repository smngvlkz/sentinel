"""Unit tests for optional DNS/HTTP name extraction in capture."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
import logging

import pytest

from capture_service.capture import parse_packet
from capture_service.names import HelloReassembler, NameDrops, NameExtractor, _parse_sni


@pytest.fixture
def names():
    """Each test counts its own dropped names, and holds its own split handshakes."""
    return NameExtractor()


class TestHostileNamesDropped:
    """Bad names are dropped whole and counted, never cleaned into a real-looking domain."""

    def test_dns_answer(self, names):
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="x.example"),
                an=DNSRR(rrname="pay<b>pal.com", type="A", rdata="1.2.3.4")
                / DNSRR(rrname="real.example.com", type="A", rdata="1.2.3.5"),
            )
        )
        # The good answer in the same packet still counts.
        assert names.bindings(pkt) == [["1.2.3.5", "real.example.com", "10.0.0.1"]]
        assert names.drops.count == 1
        assert names.drops.latest == ("pay<b>pal.com.", "1.2.3.4")

    def test_non_ascii_dns_bytes_not_stripped(self, names):
        """Bytes outside ASCII used to be silently removed, which could form a different name."""
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(id=1, qr=1, qd=DNSQR(qname="x.example"),
                  an=DNSRR(rrname=b"pay\xffpal.com", type="A", rdata="1.2.3.4"))
        )
        assert names.bindings(pkt) == []
        assert names.drops.count == 1

    def test_http_host(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="9.9.9.9")
            / TCP(sport=40000, dport=80)
            / Raw(b"GET / HTTP/1.1\r\nHost: <img src=x onerror=alert(1)>\r\n\r\n")
        )
        assert names.bindings(pkt) == []
        assert names.drops.count == 1


class TestDropLog:

    def test_one_summary_a_minute(self, caplog):
        drops = NameDrops(interval=60)
        drops.maybe_log(0.0)                     # starts the window
        for _ in range(500):
            drops.record("junk name", "1.2.3.4")
        with caplog.at_level(logging.WARNING):
            assert drops.maybe_log(30.0) is False   # too soon
            assert drops.maybe_log(61.0) is True
            assert drops.maybe_log(62.0) is False   # nothing new since
        lines = [r.getMessage() for r in caplog.records]
        assert len(lines) == 1
        assert "dropped 500 invalid name(s) in the last 61s" in lines[0]

    def test_bad_name_escaped_and_truncated(self, caplog):
        drops = NameDrops(interval=60)
        drops.maybe_log(0.0)
        drops.record("evil\nFAKE LOG LINE \x1b[31m" + "x" * 100, "1.2.3.4")
        with caplog.at_level(logging.WARNING):
            drops.maybe_log(60.0)
        msg = caplog.records[0].getMessage()
        assert "\n" not in msg and "\x1b" not in msg     # no forged lines or control codes
        assert "'evil\\nFAKE LOG LINE \\x1b[31m" in msg  # shown escaped
        assert msg.count("x") < 40                        # truncated
        assert "..." in msg

    def test_quiet_when_nothing_dropped(self, caplog):
        drops = NameDrops(interval=60)
        drops.maybe_log(0.0)
        with caplog.at_level(logging.WARNING):
            assert drops.maybe_log(120.0) is False
        assert not caplog.records


class TestDnsBindings:

    def test_a_records(self, names):
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="api.example.com"),
                an=DNSRR(rrname="api.example.com", type="A", rdata="1.2.3.4")
                / DNSRR(rrname="api.example.com", type="A", rdata="1.2.3.5"),
            )
        )
        assert names.bindings(pkt) == [
            ["1.2.3.4", "api.example.com", "10.0.0.1"],
            ["1.2.3.5", "api.example.com", "10.0.0.1"],
        ]

    def test_aaaa_record(self, names):
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=2,
                qr=1,
                qd=DNSQR(qname="v6.example.com"),
                an=DNSRR(rrname="v6.example.com", type="AAAA", rdata="2001:db8::1"),
            )
        )
        assert names.bindings(pkt) == [["2001:db8::1", "v6.example.com", "10.0.0.1"]]

    def test_query_ignored(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=3, qr=0, qd=DNSQR(qname="api.example.com"))
        )
        assert names.bindings(pkt) == []


class TestHttpHostBindings:

    def test_host_header(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="9.9.9.9")
            / TCP(sport=40000, dport=80)
            / Raw(b"GET / HTTP/1.1\r\nHost: api2.cursor.sh\r\n\r\n")
        )
        assert names.bindings(pkt) == [["9.9.9.9", "api2.cursor.sh", "10.0.0.1"]]

    def test_host_with_port(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="9.9.9.9")
            / TCP(sport=40000, dport=8080)
            / Raw(b"GET / HTTP/1.1\r\nHost: svc.internal:8080\r\n\r\n")
        )
        assert names.bindings(pkt) == [["9.9.9.9", "svc.internal", "10.0.0.1"]]

    def test_non_http_payload_ignored(self, names):
        pkt = IP(src="10.0.0.1", dst="9.9.9.9") / TCP(sport=40000, dport=443) / Raw(b"\x16\x03\x01tls")
        assert names.bindings(pkt) == []


def client_hello(sni: str | None, *, before: int = 0) -> bytes:
    """A minimal TLS 1.2-style ClientHello, with `before` bytes of padding extension first."""
    exts = b""
    if before:
        exts += (21).to_bytes(2, "big") + before.to_bytes(2, "big") + b"\x00" * before
    if sni is not None:
        name = sni.encode()
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        body = len(entry).to_bytes(2, "big") + entry
        exts += b"\x00\x00" + len(body).to_bytes(2, "big") + body
    hello = (
        b"\x03\x03" + b"\x00" * 32      # version, random
        + b"\x00"                         # session id
        + b"\x00\x02\x13\x01"             # one cipher suite
        + b"\x01\x00"                     # null compression
        + len(exts).to_bytes(2, "big") + exts
    )
    hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class TestTlsSni:

    def test_parse(self):
        assert _parse_sni(client_hello("api2.cursor.sh")) == "api2.cursor.sh"

    def test_after_other_extensions(self):
        assert _parse_sni(client_hello("example.org", before=300)) == "example.org"

    def test_no_sni(self):
        assert _parse_sni(client_hello(None)) is None

    def test_truncated_before_sni(self):
        """A ClientHello split across segments: SNI in the missing part is skipped, not misread."""
        data = client_hello("example.org", before=300)
        assert _parse_sni(data[:200]) is None

    def test_not_a_client_hello(self):
        assert _parse_sni(b"\x16\x03\x01tls") is None
        assert _parse_sni(b"\x17\x03\x03" + b"\x00" * 60) is None

    def test_binding(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="104.18.0.1")
            / TCP(sport=40000, dport=443)
            / Raw(client_hello("API2.Cursor.SH"))
        )
        assert names.bindings(pkt) == [["104.18.0.1", "api2.cursor.sh", "10.0.0.1"]]

    def test_junk_name_dropped(self, names):
        pkt = (
            IP(src="10.0.0.1", dst="104.18.0.1")
            / TCP(sport=40000, dport=443)
            / Raw(client_hello("bad name<script>"))
        )
        assert names.bindings(pkt) == []


class TestParsePacketNames:

    def test_bindings_added_when_enabled(self, names):
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="api.example.com"),
                an=DNSRR(rrname="api.example.com", type="A", rdata="1.2.3.4"),
            )
        )
        entry = parse_packet(pkt, names=names)
        assert entry is not None
        assert json.loads(entry["name_bindings"]) == [["1.2.3.4", "api.example.com", "10.0.0.1"]]

    def test_bindings_omitted_when_disabled(self):
        pkt = (
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="api.example.com"),
                an=DNSRR(rrname="api.example.com", type="A", rdata="1.2.3.4"),
            )
        )
        entry = parse_packet(pkt, names=None)
        assert entry is not None
        assert "name_bindings" not in entry


def segment(payload: bytes, seq: int, sport: int = 40000):
    return IP(src="10.0.0.1", dst="104.18.0.1") / TCP(sport=sport, dport=443, seq=seq, flags="PA") / Raw(payload)


class TestSplitClientHello:
    """Post-quantum ClientHellos (~2 KB) span two segments; the name can be in the second."""

    def test_name_in_second_segment(self, names):
        hello = client_hello("api2.cursor.sh", before=1600)   # name lands past byte 1600
        first, second = hello[:1400], hello[1400:]
        assert _parse_sni(first) is None                      # not readable from the first alone
        assert names.tls_sni(segment(first, 1000), now=0.0) == []
        assert names.tls_sni(segment(second, 1000 + 1400), now=0.01) == [
            ["104.18.0.1", "api2.cursor.sh", "10.0.0.1"]
        ]
        assert len(names.hellos) == 0                       # nothing left held

    def test_name_in_first_segment_not_held(self, names):
        hello = client_hello("example.org", before=0) + b"\x00" * 1500
        assert names.tls_sni(segment(hello[:1400], 1000), now=0.0) == [
            ["104.18.0.1", "example.org", "10.0.0.1"]
        ]
        assert len(names.hellos) == 0

    def test_three_segments(self, names):
        hello = client_hello("three.example", before=3000)
        parts = [hello[:1400], hello[1400:2800], hello[2800:]]
        seq = 5000
        found = []
        for i, part in enumerate(parts):
            found = names.tls_sni(segment(part, seq), now=i * 0.01)
            seq += len(part)
        assert found == [["104.18.0.1", "three.example", "10.0.0.1"]]

    def test_out_of_order_gives_up(self, names):
        hello = client_hello("x.example", before=1600)
        names.tls_sni(segment(hello[:1400], 1000), now=0.0)
        # A retransmission or gap: wrong sequence number.
        assert names.tls_sni(segment(hello[1400:], 9999), now=0.01) == []
        assert len(names.hellos) == 0

    def test_stale_gives_up(self, names):
        hello = client_hello("x.example", before=1600)
        names.tls_sni(segment(hello[:1400], 1000), now=0.0)
        assert names.tls_sni(segment(hello[1400:], 2400), now=5.0) == []

    def test_other_connections_dont_mix(self, names):
        hello = client_hello("x.example", before=1600)
        names.tls_sni(segment(hello[:1400], 1000, sport=40000), now=0.0)
        # Same bytes on a different connection must not complete the first one.
        assert names.tls_sni(segment(hello[1400:], 2400, sport=40001), now=0.01) == []

    def test_flood_is_bounded(self):
        r = HelloReassembler(max_flows=256)
        partial = client_hello("x.example", before=1600)[:1400]
        for port in range(1000):
            r.feed(("10.0.0.1", port, "1.1.1.1", 443), 1, partial, now=0.0)
        assert len(r) == 256

    def test_byte_cap(self):
        """A hello claiming a huge length with no name is let go at the cap."""
        r = HelloReassembler(max_bytes=4096)
        hello = client_hello(None, before=12000)
        key = ("10.0.0.1", 1, "1.1.1.1", 443)
        seq = 1
        for start in range(0, 6000, 1400):
            r.feed(key, seq, hello[start:start + 1400], now=0.0)
            seq += 1400
        assert len(r) == 0
