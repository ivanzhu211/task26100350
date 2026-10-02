"""TCP byte-stream reassembly for one direction of one connection.

Handles: retransmits, overlapping segments (first-received wins),
out-of-order delivery, sequence wraparound, mid-stream capture start,
and bounded buffering (excess treated as loss).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

# Max payload bytes held in the out-of-order buffer per direction
MAX_BUFFERED = 1 << 20  # 1 MiB

_MOD = 1 << 32
_HALF = 1 << 31


def _rel(seq: int, base: int) -> int:
    """Sequence offset of `seq` relative to `base`, mod 2**32."""
    return (seq - base) & 0xFFFFFFFF


@dataclass
class StreamChunk:
    """A contiguous piece of the reassembled stream.

    data is None for a gap of `gap` bytes. ts is the capture time of
    the packet whose arrival made this chunk complete (or the chunk's
    own arrival time when emitted by limit enforcement / flush).
    """

    data: Optional[bytes]
    ts: float
    gap: int = 0


class DirectionReassembler:
    """Reassembles one direction of a TCP connection."""

    def __init__(self) -> None:
        self._started = False
        self._next_seq = 0  # next expected sequence number (mod 2**32)
        # buffered future segments as (seq, data, ts), kept sorted by
        # offset from _next_seq (all offsets are in [0, 2**31))
        self._segments: List[Tuple[int, bytes, float]] = []
        self._buffered = 0

    # -- public API -----------------------------------------------------

    @property
    def started(self) -> bool:
        return self._started

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def feed(self, seq: int, payload: bytes, ts: float) -> List[StreamChunk]:
        """Feed one segment; return newly completable chunks in order."""
        out: List[StreamChunk] = []
        if not payload:
            return out
        if not self._started:
            # Capture may start mid-connection: the first segment seen
            # defines the stream baseline.
            self._started = True
            self._next_seq = seq
        past = _rel(self._next_seq, seq)
        if 0 < past < _HALF:
            # Starts before the expected point: retransmit or overlap
            # with already-emitted data. Emitted bytes were received
            # first, so they win; keep only the new tail.
            if past >= len(payload):
                return out
            payload = payload[past:]
            seq = self._next_seq
        self._insert(seq, payload, ts)
        self._drain(out, ts)
        self._enforce_limit(out)
        return out

    def flush(self) -> List[StreamChunk]:
        """End of connection/capture: emit remaining buffered data,
        declaring unfillable holes as gaps."""
        out: List[StreamChunk] = []
        for seq, data, ts in self._segments:
            gap = _rel(seq, self._next_seq)
            if gap:
                out.append(StreamChunk(data=None, ts=ts, gap=gap))
            out.append(StreamChunk(data=data, ts=ts))
            self._next_seq = (seq + len(data)) & 0xFFFFFFFF
        self._segments = []
        self._buffered = 0
        return out

    # -- internals ------------------------------------------------------

    def _insert(self, seq: int, data: bytes, ts: float) -> None:
        """Insert a segment into the out-of-order buffer, keeping it
        sorted. Where the new segment overlaps already-buffered bytes,
        the buffered copy wins (it was received first)."""
        pos = _rel(seq, self._next_seq)
        pieces: List[Tuple[int, bytes]] = [(pos, data)]
        for eseq, edata, _ in self._segments:
            epos = _rel(eseq, self._next_seq)
            eend = epos + len(edata)
            trimmed: List[Tuple[int, bytes]] = []
            for ppos, pdata in pieces:
                pend = ppos + len(pdata)
                ov_lo = max(ppos, epos)
                ov_hi = min(pend, eend)
                if ov_lo >= ov_hi:
                    trimmed.append((ppos, pdata))
                    continue
                if ov_lo > ppos:
                    trimmed.append((ppos, pdata[: ov_lo - ppos]))
                if ov_hi < pend:
                    trimmed.append((ppos + (ov_hi - ppos), pdata[ov_hi - ppos:]))
            pieces = trimmed
            if not pieces:
                return
        for ppos, pdata in pieces:
            pseq = (self._next_seq + ppos) & 0xFFFFFFFF
            entry = (pseq, pdata, ts)
            idx = len(self._segments)
            while idx > 0 and _rel(self._segments[idx - 1][0], self._next_seq) > ppos:
                idx -= 1
            self._segments.insert(idx, entry)
            self._buffered += len(pdata)

    def _drain(self, out: List[StreamChunk], trigger_ts: float) -> None:
        """Emit buffered segments that are now contiguous."""
        while self._segments:
            seq, data, _ts = self._segments[0]
            if _rel(seq, self._next_seq) != 0:
                break
            self._segments.pop(0)
            self._buffered -= len(data)
            out.append(StreamChunk(data=data, ts=trigger_ts))
            self._next_seq = (self._next_seq + len(data)) & 0xFFFFFFFF

    def _enforce_limit(self, out: List[StreamChunk]) -> None:
        """Bound memory: when the buffer grows past MAX_BUFFERED, give
        up waiting for the missing bytes and treat them as lost."""
        while self._buffered > MAX_BUFFERED and self._segments:
            seq, data, ts = self._segments.pop(0)
            self._buffered -= len(data)
            gap = _rel(seq, self._next_seq)
            if gap:
                out.append(StreamChunk(data=None, ts=ts, gap=gap))
            out.append(StreamChunk(data=data, ts=ts))
            self._next_seq = (seq + len(data)) & 0xFFFFFFFF
