"""
Reads the few header fields SentinelAI uses straight out of a raw Ethernet
frame, without decoding the whole packet. Live capture and the offline
replays (scripts/evaluate.py) both use it, so they see packets the same way.

Measured on an M4 (2026-10-30, 200,000 CIC-IDS2017 packets): decoding with
scapy handled about 9,700 packets a second; reading them with libpcap and
this parser about 360,000.
"""

from __future__ import annotations

import struct

# TCP flag letters in bit order, matching how scapy renders flags ("S", "SA", "PA").
_TCP_FLAGS = "FSRPAUECN"


def flag_str(bits: int) -> str:
    return "".join(ch for i, ch in enumerate(_TCP_FLAGS) if bits & (1 << i))


def _ip_offset(data: bytes) -> int | None:
    """Where the IPv4 header starts, past any VLAN tags, or None if it isn't IPv4."""
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    off = 14
    while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags
        ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    if ethertype != 0x0800 or len(data) < off + 20:
        return None
    return off


def _later_fragment(data: bytes, off: int) -> bool:
    return struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF != 0


def parse_frame(data: bytes, timestamp: float, orig_len: int) -> dict[str, str] | None:
    """The fields parse_packet() produces, from a raw Ethernet frame."""
    off = _ip_offset(data)
    if off is None:
        return None
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    entry = {
        "timestamp": str(timestamp),
        "src_ip": ".".join(map(str, data[off + 12:off + 16])),
        "dst_ip": ".".join(map(str, data[off + 16:off + 20])),
        "protocol": str(proto),
        "packet_size": str(orig_len),
    }
    l4 = off + ihl
    if _later_fragment(data, off):
        # Only the first fragment carries the TCP or UDP header; the rest
        # start mid-payload, so their bytes aren't ports.
        entry.update(src_port="0", dst_port="0", flags="", transport="OTHER")
    elif proto == 6 and len(data) >= l4 + 14:
        sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
        bits = ((data[l4 + 12] & 0x01) << 8) | data[l4 + 13]
        entry.update(src_port=str(sport), dst_port=str(dport), flags=flag_str(bits), transport="TCP")
    elif proto == 17 and len(data) >= l4 + 4:
        sport, dport = struct.unpack("!HH", data[l4:l4 + 4])
        entry.update(src_port=str(sport), dst_port=str(dport), flags="", transport="UDP")
    else:
        entry.update(src_port="0", dst_port="0", flags="", transport="OTHER")
    return entry


def tcp_payload(data: bytes) -> bytes:
    """A TCP segment's payload (as far as it was captured), or b"" for anything else."""
    off = _ip_offset(data)
    if off is None or data[off + 9] != 6 or _later_fragment(data, off):
        return b""
    l4 = off + (data[off] & 0x0F) * 4
    if len(data) < l4 + 13:
        return b""
    total = struct.unpack("!H", data[off + 2:off + 4])[0]
    start = l4 + (data[l4 + 12] >> 4) * 4
    # The IP total length, not the frame length: short frames are padded.
    return data[start:off + total]
