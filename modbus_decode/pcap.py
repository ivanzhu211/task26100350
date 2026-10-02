"""Streaming reader for classic libpcap files.

Handles both byte orders and microsecond/nanosecond timestamp resolution.
Yields (ts_seconds, captured_length, wire_length, packet_bytes) tuples.
"""
from __future__ import annotations

import struct
from typing import Iterator, Tuple

# Magic numbers as stored in the file (first 4 bytes, read raw).
_MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_NSEC_LE = b"\x4d\x3c\xb2\xa1"
_MAGIC_NSEC_BE = b"\xa1\xb2\x3c\x4d"

LINKTYPE_ETHERNET = 1


class PcapError(Exception):
    pass


def read_packets(path: str) -> Iterator[Tuple[float, int, int, bytes]]:
    """Yield (ts, caplen, wirelen, data) for each packet in the file.

    `data` is truncated to caplen bytes; wirelen reflects the original
    on-wire length (may exceed caplen when snaplen truncation occurred).
    """
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic in (_MAGIC_USEC_LE, _MAGIC_NSEC_LE):
            endian = "<"
        elif magic in (_MAGIC_USEC_BE, _MAGIC_NSEC_BE):
            endian = ">"
        else:
            raise PcapError("not a classic pcap file (bad magic)")
        nano = magic in (_MAGIC_NSEC_LE, _MAGIC_NSEC_BE)
        scale = 1_000_000_000 if nano else 1_000_000

        rest = fh.read(20)
        if len(rest) != 20:
            raise PcapError("truncated global header")
        _ver_major, _ver_minor, _tz, _sigfigs, _snaplen, network = struct.unpack(
            endian + "HHiiii", rest
        )
        if network != LINKTYPE_ETHERNET:
            raise PcapError(f"unsupported link type {network} (need Ethernet)")

        rec_hdr = struct.Struct(endian + "IIII")
        while True:
            hdr = fh.read(16)
            if not hdr:
                return
            if len(hdr) != 16:
                raise PcapError("truncated packet header")
            ts_sec, ts_frac, caplen, wirelen = rec_hdr.unpack(hdr)
            data = fh.read(caplen)
            if len(data) != caplen:
                raise PcapError("truncated packet data")
            ts = ts_sec + ts_frac / scale
            yield ts, caplen, wirelen, data
