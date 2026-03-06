"""Shared fixtures for SentinelAI IDS test suite."""

import time
import pytest


@pytest.fixture
def sample_tcp_packet():
    """A minimal parsed TCP packet dict as produced by parse_packet."""
    return {
        "timestamp": str(time.time()),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "6",
        "packet_size": "512",
        "src_port": "54321",
        "dst_port": "80",
        "flags": "S",
        "transport": "TCP",
    }


@pytest.fixture
def sample_udp_packet():
    """A minimal parsed UDP packet dict."""
    return {
        "timestamp": str(time.time()),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "17",
        "packet_size": "256",
        "src_port": "12345",
        "dst_port": "53",
        "flags": "",
        "transport": "UDP",
    }


@pytest.fixture
def normal_features():
    """Features representing normal, benign traffic."""
    return {
        "packet_rate": 5.0,
        "byte_rate": 2560.0,
        "avg_packet_size": 512.0,
        "packet_size": 512,
        "unique_dst_ports": 2,
        "flow_duration": 10.0,
        "total_packets": 50,
        "total_bytes": 25600,
        "src_connection_count": 1,
        "syn_count": 1,
        "syn_ratio": 0.02,
    }


@pytest.fixture
def syn_flood_features():
    """Features that should trigger SYN_FLOOD detection."""
    return {
        "packet_rate": 100.0,
        "byte_rate": 6400.0,
        "avg_packet_size": 64.0,
        "packet_size": 64,
        "unique_dst_ports": 1,
        "flow_duration": 2.0,
        "total_packets": 200,
        "total_bytes": 12800,
        "src_connection_count": 1,
        "syn_count": 190,
        "syn_ratio": 0.95,
    }


@pytest.fixture
def port_scan_features():
    """Features that should trigger PORT_SCAN detection."""
    return {
        "packet_rate": 10.0,
        "byte_rate": 640.0,
        "avg_packet_size": 64.0,
        "packet_size": 64,
        "unique_dst_ports": 50,
        "flow_duration": 5.0,
        "total_packets": 50,
        "total_bytes": 3200,
        "src_connection_count": 1,
        "syn_count": 5,
        "syn_ratio": 0.1,
    }


@pytest.fixture
def large_payload_features():
    """Features that should trigger LARGE_PAYLOAD detection."""
    return {
        "packet_rate": 1.0,
        "byte_rate": 15000.0,
        "avg_packet_size": 15000.0,
        "packet_size": 15000,
        "unique_dst_ports": 1,
        "flow_duration": 1.0,
        "total_packets": 1,
        "total_bytes": 15000,
        "src_connection_count": 1,
        "syn_count": 0,
        "syn_ratio": 0.0,
    }


@pytest.fixture
def high_frequency_features():
    """Features that should trigger HIGH_FREQUENCY detection."""
    return {
        "packet_rate": 300.0,
        "byte_rate": 153600.0,
        "avg_packet_size": 512.0,
        "packet_size": 512,
        "unique_dst_ports": 1,
        "flow_duration": 1.0,
        "total_packets": 300,
        "total_bytes": 153600,
        "src_connection_count": 1,
        "syn_count": 5,
        "syn_ratio": 0.017,
    }
