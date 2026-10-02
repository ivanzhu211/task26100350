"""Build pcap bytes and Ethernet/IPv4/TCP packets by hand."""

from __future__ import annotations

import struct
from typing import List, Optional, Sequence, Tuple

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 40000
SERVER_PORT = 502

FLAGS_PA = 0x18  # PSH+ACK
FLAGS_SYN = 0x02
FLAGS_FIN = 0x11
FLAGS_RST = 0x04


def mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
               seq: int, payload: bytes = b"", flags: int = FLAGS_PA,
               vlans: Optional[Sequence[int]] = None,
               pad_to: int = 0) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66"
    for vid in (vlans or ()):
        eth += struct.pack(">HH", 0x8100, vid)
    eth += struct.pack(">H", 0x0800)
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, 0,
                      5 << 4, flags, 65535, 0, 0)
    ip_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, ip_len, 0, 0, 64, 6, 0)
    ip += src_b + dst_b
    frame = eth + ip + tcp + payload
    if pad_to and len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))  # Ethernet padding
    return frame


def client_packet(seq: int, payload: bytes = b"", flags: int = FLAGS_PA,
                  **kw) -> bytes:
    return tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT,
                      seq, payload, flags, **kw)


def server_packet(seq: int, payload: bytes = b"", flags: int = FLAGS_PA,
                  **kw) -> bytes:
    return tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT,
                      seq, payload, flags, **kw)


def build_pcap(packets: List[Tuple[float, bytes]], endian: str = "<",
               nanos: bool = False, snaplen: int = 65535) -> bytes:
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1",
        (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1",
        (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nanos)]
    out = [magic + struct.pack(endian + "HHiiii", 2, 4, 0, 0, snaplen, 1)]
    scale = 1e9 if nanos else 1e6
    for ts, data in packets:
        sec = int(ts)
        frac = int(round((ts - sec) * scale))
        out.append(struct.pack(endian + "IIII", sec, frac,
                               len(data), len(data)))
        out.append(data)
    return b"".join(out)


def write_pcap(path: str, packets: List[Tuple[float, bytes]],
               **kw) -> None:
    with open(path, "wb") as fh:
        fh.write(build_pcap(packets, **kw))
