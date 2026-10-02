"""Classic libpcap file reader (both byte orders, us and ns resolution)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

# Magic numbers as read little-endian from the first 4 bytes
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),  # usec, little-endian
    b"\xa1\xb2\xc3\xd4": (">", False),  # usec, big-endian
    b"\x4d\x3c\xb2\xa1": ("<", True),   # nsec, little-endian
    b"\xa1\xb2\x3c\x4d": (">", True),   # nsec, big-endian
}

LINKTYPE_ETHERNET = 1

_GLOBAL_HDR_LEN = 24
_REC_HDR_LEN = 16


@dataclass
class PcapPacket:
    """One captured packet record."""

    ts: float  # seconds since epoch
    data: bytes  # captured bytes (may be truncated by snaplen)
    orig_len: int  # on-wire length


class PcapError(Exception):
    """Raised for unparseable pcap files."""


class PcapReader:
    """Iterates PcapPacket records from a classic pcap file."""

    def __init__(self, fileobj: BinaryIO) -> None:
        hdr = fileobj.read(_GLOBAL_HDR_LEN)
        if len(hdr) < _GLOBAL_HDR_LEN:
            raise PcapError("file too short for pcap global header")
        magic = hdr[:4]
        if magic not in _MAGIC:
            raise PcapError("not a classic pcap file (bad magic)")
        self._endian, self._ns = _MAGIC[magic]
        (_ver_major, _ver_minor, _thiszone, _sigfigs,
         self.snaplen, self.linktype) = struct.unpack(
            self._endian + "HHiiii", hdr[4:24]
        )
        self._fh = fileobj

    def __iter__(self) -> Iterator[PcapPacket]:
        read = self._fh.read
        endian = self._endian
        ns = self._ns
        while True:
            hdr = read(_REC_HDR_LEN)
            if not hdr:
                return
            if len(hdr) < _REC_HDR_LEN:
                return  # truncated trailing record header: stop quietly
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + "IIII", hdr
            )
            data = read(incl_len)
            if len(data) < incl_len:
                return  # truncated final record
            scale = 1e-9 if ns else 1e-6
            yield PcapPacket(
                ts=ts_sec + ts_frac * scale,
                data=data,
                orig_len=orig_len,
            )


def open_pcap(fileobj: BinaryIO) -> PcapReader:
    """Open a pcap file object and return a reader."""
    return PcapReader(fileobj)
