"""Unit tests for optional DNS/HTTP name extraction in capture."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
from capture_service.capture import extract_name_bindings, parse_packet, _parse_sni, _sanitize_name


class TestSanitizeName:

    def test_lowercases_and_strips_dot(self):
        assert _sanitize_name("API.Example.COM.") == "api.example.com"

    def test_strips_control_characters(self):
        assert _sanitize_name("evil\x00.name") == "evil.name"

    def test_rejects_empty(self):
        assert _sanitize_name("...") is None
        assert _sanitize_name("\x00\x01") is None


class TestDnsBindings:

    def test_a_records(self):
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
        assert extract_name_bindings(pkt) == [
            ["1.2.3.4", "api.example.com", "10.0.0.1"],
            ["1.2.3.5", "api.example.com", "10.0.0.1"],
        ]

    def test_aaaa_record(self):
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
        assert extract_name_bindings(pkt) == [["2001:db8::1", "v6.example.com", "10.0.0.1"]]

    def test_query_ignored(self):
        pkt = (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=3, qr=0, qd=DNSQR(qname="api.example.com"))
        )
        assert extract_name_bindings(pkt) == []


class TestHttpHostBindings:

    def test_host_header(self):
        pkt = (
            IP(src="10.0.0.1", dst="9.9.9.9")
            / TCP(sport=40000, dport=80)
            / Raw(b"GET / HTTP/1.1\r\nHost: api2.cursor.sh\r\n\r\n")
        )
        assert extract_name_bindings(pkt) == [["9.9.9.9", "api2.cursor.sh", "10.0.0.1"]]

    def test_host_with_port(self):
        pkt = (
            IP(src="10.0.0.1", dst="9.9.9.9")
            / TCP(sport=40000, dport=8080)
            / Raw(b"GET / HTTP/1.1\r\nHost: svc.internal:8080\r\n\r\n")
        )
        assert extract_name_bindings(pkt) == [["9.9.9.9", "svc.internal", "10.0.0.1"]]

    def test_non_http_payload_ignored(self):
        pkt = IP(src="10.0.0.1", dst="9.9.9.9") / TCP(sport=40000, dport=443) / Raw(b"\x16\x03\x01tls")
        assert extract_name_bindings(pkt) == []


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

    def test_binding(self):
        pkt = (
            IP(src="10.0.0.1", dst="104.18.0.1")
            / TCP(sport=40000, dport=443)
            / Raw(client_hello("API2.Cursor.SH"))
        )
        assert extract_name_bindings(pkt) == [["104.18.0.1", "api2.cursor.sh", "10.0.0.1"]]

    def test_junk_name_dropped(self):
        pkt = (
            IP(src="10.0.0.1", dst="104.18.0.1")
            / TCP(sport=40000, dport=443)
            / Raw(client_hello("bad name<script>"))
        )
        assert extract_name_bindings(pkt) == []


class TestParsePacketNames:

    def test_bindings_added_when_enabled(self):
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
        entry = parse_packet(pkt, names=True)
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
        entry = parse_packet(pkt, names=False)
        assert entry is not None
        assert "name_bindings" not in entry
