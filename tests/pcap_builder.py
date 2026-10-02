"""Helpers to synthesize classic pcap files and TCP/IPv4/Ethernet frames."""
from __future__ import annotations

import socket
import struct
from typing import List, Optional, Tuple

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


def ethernet_frame(payload: bytes, eth_type: int = 0x0800,
                   vlans: Tuple[int, ...] = (), pad: int = 0) -> bytes:
    frame = (b"\x02\x00\x00\x00\x00\x01"  # dst mac
             b"\x02\x00\x00\x00\x00\x02")  # src mac
    for tci in vlans:
        frame += struct.pack(">HH", 0x8100, tci)
    frame += struct.pack(">H", eth_type) + payload
    if pad and len(frame) < pad:
        frame += b"\x00" * (pad - len(frame))
    return frame


def ipv4_packet(src_ip: str, dst_ip: str, payload: bytes,
                protocol: int = 6) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0, 0x4000, 64, protocol, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return hdr + payload


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, flags: int, payload: bytes = b"",
                vlans: Tuple[int, ...] = (), pad: int = 0) -> bytes:
    seq %= 1 << 32
    off_flags = (5 << 12) | flags
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, 0,
                      off_flags, 8192, 0, 0) + payload
    ip = ipv4_packet(src_ip, dst_ip, tcp)
    return ethernet_frame(ip, vlans=vlans, pad=pad)


def build_pcap(packets: List[Tuple[float, bytes]], path: str,
               endian: str = "<", nano: bool = False,
               snaplen: int = 65535) -> None:
    """Write a classic pcap. `packets` are (ts_seconds, frame_bytes) or
    (ts_seconds, captured_bytes, wire_length) to emulate snaplen
    truncation."""
    if endian == "<":
        magic = b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1"
    else:
        magic = b"\xa1\xb2\x3c\x4d" if nano else b"\xa1\xb2\xc3\xd4"
    out = [magic]
    out.append(struct.pack(endian + "HHiiii", 2, 4, 0, 0, snaplen, 1))
    scale = 1_000_000_000 if nano else 1_000_000
    for pkt in packets:
        if len(pkt) == 2:
            ts, data = pkt
            wirelen = len(data)
        else:
            ts, data, wirelen = pkt
        sec = int(ts)
        frac = int(round((ts - sec) * scale))
        out.append(struct.pack(endian + "IIII", sec, frac, len(data), wirelen))
        out.append(data)
    with open(path, "wb") as fh:
        fh.write(b"".join(out))


def mbap(tid: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu


def fc16_request(address: int, values: List[int]) -> bytes:
    pdu = struct.pack(">BHHB", 16, address, len(values), len(values) * 2)
    pdu += struct.pack(">" + "H" * len(values), *values)
    return pdu


def fc3_request(address: int, quantity: int) -> bytes:
    return struct.pack(">BHH", 3, address, quantity)


def fc3_response(values: List[int]) -> bytes:
    pdu = struct.pack(">BB", 3, len(values) * 2)
    return pdu + struct.pack(">" + "H" * len(values), *values)


def fc6_request(address: int, value: int) -> bytes:
    return struct.pack(">BHH", 6, address, value)
