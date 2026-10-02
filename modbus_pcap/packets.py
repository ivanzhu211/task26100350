"""Ethernet / 802.1Q / IPv4 / TCP header parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

ETH_P_IP = 0x0800
_VLAN_TYPES = (0x8100, 0x88A8)  # 802.1Q, 802.1ad
IPPROTO_TCP = 6


@dataclass
class TcpSegment:
    """A parsed TCP segment carrying payload."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    flags: int
    payload: bytes
    # True when IP total_length says more payload existed than captured
    truncated: bool


def parse_segment(frame: bytes) -> Optional[TcpSegment]:
    """Parse an Ethernet frame into a TcpSegment.

    Returns None for non-IPv4/non-TCP/empty-payload frames.
    Handles one or two 802.1Q VLAN tags and Ethernet padding.
    """
    if len(frame) < 14:
        return None
    eth_type = struct.unpack(">H", frame[12:14])[0]
    off = 14
    # Strip up to two VLAN tags
    for _ in range(2):
        if eth_type in _VLAN_TYPES:
            if len(frame) < off + 4:
                return None
            eth_type = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        else:
            break
    if eth_type != ETH_P_IP:
        return None
    if len(frame) < off + 20:
        return None

    vihl = frame[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl:
        return None
    total_length = struct.unpack(">H", frame[off + 2:off + 4])[0]
    if total_length < ihl:
        return None
    protocol = frame[off + 9]
    if protocol != IPPROTO_TCP:
        return None
    frag = struct.unpack(">H", frame[off + 6:off + 8])[0]
    # Skip fragmented packets (task guarantees none, but stay safe)
    if frag & 0x3FFF:
        return None
    src_ip = ".".join(str(b) for b in frame[off + 12:off + 16])
    dst_ip = ".".join(str(b) for b in frame[off + 16:off + 20])

    # Ethernet padding: trust IP total_length, not the captured frame length
    ip_end = off + total_length
    ip_packet = frame[off:ip_end]  # may be shorter than total_length if snaplen cut it
    if len(ip_packet) < ihl + 20:
        return None

    tcp = ip_packet[ihl:]
    src_port, dst_port, seq = struct.unpack(">HHI", tcp[:8])
    data_offset = (tcp[12] >> 4) * 4
    flags = tcp[13]
    if data_offset < 20 or len(tcp) < data_offset:
        return None
    payload = tcp[data_offset:]
    expected_payload = total_length - ihl - data_offset
    truncated = len(payload) < expected_payload
    return TcpSegment(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        flags=flags,
        payload=payload,
        truncated=truncated,
    )
