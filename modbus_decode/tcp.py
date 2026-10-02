"""TCP byte-stream reassembly for one direction of one connection.

Accepts segments (seq, payload, ts) in any order and produces an ordered
stream of events:

    ("data", bytes, ts)  - contiguous bytes; ts is the arrival time of the
                           packet that delivered these bytes
    ("gap", count, ts)   - `count` stream bytes were lost

Rules:
- retransmitted/overlapping bytes are delivered only once;
- on conflicting overlap the first-received bytes win;
- out-of-order buffering is bounded; when the bound is exceeded the
  oldest hole is declared lost (a gap) so received data is never dropped.
"""
from __future__ import annotations

from collections import deque
from typing import Deque, List, Optional, Tuple, Union

MAX_BUFFERED = 1 << 20  # 1 MiB of out-of-order bytes per direction

SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31

Event = Union[Tuple[str, bytes, float], Tuple[str, int, float]]


def seq_lt(a: int, b: int) -> bool:
    """True if sequence number a is before b (mod 2**32)."""
    return 0 < ((b - a) % SEQ_MOD) < SEQ_HALF


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


def seq_distance(a: int, b: int) -> int:
    """Forward distance from a to b, mod 2**32."""
    return (b - a) % SEQ_MOD


class DirectionStream:
    def __init__(self) -> None:
        self.next_seq: Optional[int] = None
        # out-of-order intervals, sorted by start seq, non-overlapping
        self.segments: List[Tuple[int, bytes, float]] = []
        self.buffered = 0
        self.ready: Deque[Event] = deque()

    # -- input ---------------------------------------------------------

    def expect(self, seq: int) -> None:
        """Set the initial expected sequence (e.g. from a SYN)."""
        if self.next_seq is None:
            self.next_seq = seq

    def push(self, seq: int, payload: bytes, ts: float) -> None:
        if not payload:
            return
        if self.next_seq is None:
            self.next_seq = seq
        end = (seq + len(payload)) % SEQ_MOD
        if seq_le(end, self.next_seq):
            return  # fully retransmitted
        if seq_lt(seq, self.next_seq):
            trim = seq_distance(seq, self.next_seq)
            payload = payload[trim:]
            seq = self.next_seq
        if seq == self.next_seq:
            self.ready.append(("data", payload, ts))
            self.next_seq = (seq + len(payload)) % SEQ_MOD
            self._drain_buffered()
        else:
            self._insert_out_of_order(seq, payload, ts)
            while self.buffered > MAX_BUFFERED and self.segments:
                self._declare_gap(self.segments[0][2])
                self._drain_buffered()

    def _insert_out_of_order(self, seq: int, payload: bytes, ts: float) -> None:
        pieces = [(seq, payload, ts)]
        for seg_seq, seg_data, _seg_ts in self.segments:
            seg_end = (seg_seq + len(seg_data)) % SEQ_MOD
            nxt: List[Tuple[int, bytes, float]] = []
            for p_seq, p_data, p_ts in pieces:
                p_end = (p_seq + len(p_data)) % SEQ_MOD
                if seq_le(p_end, seg_seq) or seq_le(seg_end, p_seq):
                    nxt.append((p_seq, p_data, p_ts))  # no overlap
                    continue
                if seq_lt(p_seq, seg_seq):  # leading part survives
                    keep = seq_distance(p_seq, seg_seq)
                    nxt.append((p_seq, p_data[:keep], p_ts))
                if seq_lt(seg_end, p_end):  # trailing part survives
                    skip = seq_distance(p_seq, seg_end)
                    nxt.append((seg_end, p_data[skip:], p_ts))
            pieces = nxt
            if not pieces:
                return
        for p_seq, p_data, p_ts in pieces:
            idx = 0
            while idx < len(self.segments) and seq_lt(
                    self.segments[idx][0], p_seq):
                idx += 1
            self.segments.insert(idx, (p_seq, p_data, p_ts))
            self.buffered += len(p_data)

    # -- output --------------------------------------------------------

    def _drain_buffered(self) -> None:
        while self.segments and seq_le(self.segments[0][0], self.next_seq):
            seg_seq, seg_data, seg_ts = self.segments.pop(0)
            self.buffered -= len(seg_data)
            if seq_lt(seg_seq, self.next_seq):
                trim = seq_distance(seg_seq, self.next_seq)
                seg_data = seg_data[trim:]
            if seg_data:
                self.ready.append(("data", seg_data, seg_ts))
                self.next_seq = (self.next_seq + len(seg_data)) % SEQ_MOD

    def _declare_gap(self, ts: float) -> None:
        lost = seq_distance(self.next_seq, self.segments[0][0])
        if lost:
            self.ready.append(("gap", lost, ts))
        self.next_seq = self.segments[0][0]

    def drain(self) -> List[Event]:
        """Pop all pending events in order."""
        out = list(self.ready)
        self.ready.clear()
        return out

    def finalize(self) -> List[Event]:
        """End of connection: declare remaining holes, flush the rest."""
        while self.segments:
            self._declare_gap(self.segments[0][2])
            self._drain_buffered()
        return self.drain()
