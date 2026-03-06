"""Unit tests for capture_service.capture.parse_packet."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import IP, TCP, UDP, Ether
from capture_service.capture import parse_packet


class TestTcpPacketParsing:

    def test_returns_dict_for_tcp(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80, flags="S")
        result = parse_packet(pkt)
        assert result is not None
        assert result["src_ip"] == "1.2.3.4"
        assert result["dst_ip"] == "5.6.7.8"
        assert result["src_port"] == "12345"
        assert result["dst_port"] == "80"
        assert result["transport"] == "TCP"
        assert "S" in result["flags"]

    def test_protocol_is_tcp(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=443)
        result = parse_packet(pkt)
        assert result["protocol"] == "6"

    def test_packet_size_is_string(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=80)
        result = parse_packet(pkt)
        assert isinstance(result["packet_size"], str)
        assert int(result["packet_size"]) > 0

    def test_timestamp_is_string(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=80)
        result = parse_packet(pkt)
        assert isinstance(result["timestamp"], str)
        assert float(result["timestamp"]) > 0


class TestUdpPacketParsing:

    def test_returns_dict_for_udp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        result = parse_packet(pkt)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["src_port"] == "5000"
        assert result["dst_port"] == "53"
        assert result["transport"] == "UDP"
        assert result["flags"] == ""

    def test_protocol_is_udp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        result = parse_packet(pkt)
        assert result["protocol"] == "17"


class TestNonIpPacket:

    def test_non_ip_returns_none(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = parse_packet(pkt)
        assert result is None

    def test_ip_without_transport_layer(self):
        """IP packet without TCP/UDP should still parse with transport=OTHER."""
        pkt = IP(src="1.2.3.4", dst="5.6.7.8")
        result = parse_packet(pkt)
        assert result is not None
        assert result["transport"] == "OTHER"
        assert result["src_port"] == "0"
        assert result["dst_port"] == "0"
        assert result["flags"] == ""
