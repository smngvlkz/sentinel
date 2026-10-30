"""Live capture reads raw frames with libpcap: same fields as scapy, and the right packets go to scapy for names."""

import os
import sys

import pytest
from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether, Raw

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capture_service.capture import DropCounter, may_carry_name, parse_packet  # noqa: E402
from capture_service.frames import parse_frame, tcp_payload  # noqa: E402
from capture_service.names import NameExtractor  # noqa: E402

E = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
FRAMES = [
    E / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80, flags="S"),
    E / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=443, dport=50000, flags="SA"),
    E / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2, flags="FPAUEC") / Raw(b"x" * 40),
    E / IP(src="1.2.3.4", dst="5.6.7.8", options=b"\x01" * 8) / TCP(sport=1, dport=2, flags="R"),
    E / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53),
    E / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
    E / Dot1Q(vlan=7) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="PA"),
    # A later fragment: its first bytes are payload, not ports.
    E / IP(src="10.0.0.1", dst="10.0.0.2", proto=17, frag=185) / Raw(b"\x03\x05\x00\x00" + b"x" * 40),
    E / IP(src="10.0.0.1", dst="10.0.0.2", proto=6, frag=1) / Raw(b"GET / HTTP/1.1\r\n" + b"x" * 20),
]


@pytest.mark.parametrize("pkt", FRAMES, ids=lambda p: p.summary())
def test_same_fields_as_scapy(pkt):
    data = bytes(pkt)
    pkt = Ether(data)
    pkt.time = 1_500_000_000.25
    assert parse_frame(data, 1_500_000_000.25, len(data)) == parse_packet(pkt)


def test_not_ipv4():
    assert parse_frame(bytes(E / Raw(b"\x00" * 40)), 0.0, 54) is None
    assert parse_frame(b"\x00" * 10, 0.0, 10) is None


def test_payload_stops_at_ip_length():
    """Short frames are padded to 60 bytes; the padding isn't payload."""
    data = bytes(E / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1, dport=2) / Raw(b"hi")) + b"\x00" * 4
    assert tcp_payload(data) == b"hi"
    assert tcp_payload(bytes(E / IP() / UDP() / Raw(b"hi"))) == b""
    assert tcp_payload(bytes(E / IP(proto=6, frag=1) / Raw(b"GET / HTTP/1.1\r\n" + b"x" * 20))) == b""


class TestDropCounter:
    def test_adds_up_the_change(self):
        d = DropCounter()
        assert d.update(10) == 0  # what libpcap counted before the first reading isn't ours to know
        assert d.update(15) == 5 and d.update(15) == 5

    def test_wraps_at_32_bits(self):
        d = DropCounter()
        d.update(2**32 - 2)
        assert d.update(3) == 5


def entry_and_data(pkt):
    data = bytes(pkt)
    return parse_frame(data, 0.0, len(data)), data


class TestMayCarryName:
    """Only packets names.bindings() could read go to scapy; nothing it would read is skipped."""

    def check(self, pkt, names=None):
        names = names or NameExtractor()
        return may_carry_name(*entry_and_data(pkt), names)

    def test_dns(self):
        answer = E / IP(src="8.8.8.8", dst="10.0.0.1") / UDP(sport=53, dport=53000) / DNS(
            qr=1, qd=DNSQR(qname="a.example"), an=DNSRR(rrname="a.example", rdata="1.2.3.4"))
        assert self.check(answer)
        assert self.check(E / IP() / UDP(sport=5353, dport=5353))

    def test_http_and_tls_starts(self):
        assert self.check(E / IP() / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
        assert self.check(E / IP() / TCP(dport=443) / Raw(b"\x16\x03\x01\x02\x00\x01"))

    def test_rest_of_a_split_hello(self):
        names = NameExtractor()
        pkt = E / IP(src="10.0.0.1", dst="9.9.9.9") / TCP(sport=40000, dport=443) / Raw(b"\x17" * 20)
        assert not self.check(pkt, names)
        names.hellos._pending[("10.0.0.1", 40000, "9.9.9.9", 443)] = (b"", 0, 0, 0.0)
        assert self.check(pkt, names)

    def test_ordinary_traffic_skipped(self):
        assert not self.check(E / IP() / TCP(dport=443, flags="A"))
        assert not self.check(E / IP() / TCP(dport=443) / Raw(b"\x17\x03\x03" + b"x" * 100))
        assert not self.check(E / IP() / UDP(sport=443, dport=50000) / Raw(b"quic"))
