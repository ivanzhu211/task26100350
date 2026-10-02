"""Top-level orchestration: pcap -> packets -> streams -> modbus events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from .modbus import (
    KNOWN_FUNCTION_CODES,
    MAX_PDU_LEN,
    ModbusError,
    ModbusFrame,
    frame_length_from_mbap,
    parse_frame,
    resolve_response_addresses,
)
from .packets import TcpSegment, parse_segment
from .pcap import LINKTYPE_ETHERNET, PcapError, PcapReader
from .reassembly import MAX_BUFFERED, DirectionReassembler, StreamChunk

MODBUS_PORT = 502

_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10

# Bytes kept while scanning for a plausible MBAP header after a gap
_MAX_RESYNC = 1 << 16


# -- events -------------------------------------------------------------


@dataclass
class TransactionEvent:
    kind: str  # "transaction"
    connection: tuple
    unit_id: int
    function_code: int
    transaction_id: int
    request_ts: float
    response_ts: float
    request: ModbusFrame
    response: ModbusFrame


@dataclass
class UnansweredRequestEvent:
    kind: str  # "unanswered_request"
    connection: tuple
    unit_id: int
    function_code: int
    transaction_id: int
    ts: float
    request: ModbusFrame


@dataclass
class OrphanResponseEvent:
    kind: str  # "orphan_response"
    connection: tuple
    unit_id: int
    function_code: int
    transaction_id: int
    ts: float
    response: ModbusFrame


@dataclass
class MalformedFrameEvent:
    kind: str  # "malformed_frame"
    connection: tuple
    direction: str
    ts: float
    reason: str
    data: bytes


@dataclass
class StreamGapEvent:
    kind: str  # "stream_gap"
    connection: tuple
    direction: str
    ts: float
    lost_bytes: int


# -- per-direction stream framing ---------------------------------------


class _DirectionParser:
    """Turns an ordered stream of chunks (data / gaps) into Modbus
    frames. Never stitches bytes across a gap."""

    def __init__(self, is_request: bool) -> None:
        self.is_request = is_request
        self.buf = bytearray()
        self.skip = 0  # known stream bytes to discard (rest of a frame
        # whose length we know but whose middle was lost)
        self.resync = False  # stream position unknown: scan for MBAP
        self.resync_dropped = 0  # bytes discarded while resyncing
        self.pending_len: Optional[int] = None

    # -- helpers --------------------------------------------------------

    def _plausible_header(self, buf: bytearray, off: int) -> bool:
        if len(buf) < off + 8:
            return False
        if buf[off + 2] != 0 or buf[off + 3] != 0:
            return False
        length = (buf[off + 4] << 8) | buf[off + 5]
        if length < 2 or length > 1 + MAX_PDU_LEN:
            return False
        fc = buf[off + 7]
        base = fc & 0x7F
        if base not in KNOWN_FUNCTION_CODES:
            return False
        if self.is_request and (fc & 0x80):
            return False
        return True

    def _scan(self) -> int:
        """Return offset of a plausible MBAP header, or -1."""
        limit = len(self.buf) - 8
        for i in range(limit + 1):
            if self._plausible_header(self.buf, i):
                return i
        return -1

    # -- main entry -----------------------------------------------------

    def feed(self, chunks: List[StreamChunk], emit) -> None:
        for chunk in chunks:
            if chunk.data is None:
                self._feed_gap(chunk.gap, chunk.ts, emit)
            else:
                self._feed_data(chunk.data, chunk.ts, emit)

    def _feed_gap(self, gap: int, ts: float, emit) -> None:
        if gap <= 0:
            return
        emit(StreamGapEventPlaceholder(gap, ts))
        if self.skip:
            # The gap eats into bytes we were already discarding.
            self.skip = max(0, self.skip - gap)
            if self.skip:
                return
        if self.buf:
            if self.pending_len is not None:
                remaining = self.pending_len - len(self.buf)
                if gap < remaining:
                    # We know exactly where the broken frame ends.
                    self.skip = remaining - gap
                    self.buf.clear()
                    self.pending_len = None
                    return
                elif gap == remaining:
                    # Lands exactly on a frame boundary.
                    self.buf.clear()
                    self.pending_len = None
                    return
            # Position after the gap is unknown.
            self._start_resync(emit, ts, "frame broken by gap")
        elif not self.resync:
            # At a frame boundary; the lost region may end mid-frame.
            self._start_resync(emit, ts, None)

    def _start_resync(self, emit, ts, reason: Optional[str]) -> None:
        if reason is not None and self.buf:
            emit(MalformedPlaceholder(bytes(self.buf), ts, reason))
        self.resync_dropped = 0 if reason is not None else self.resync_dropped
        self.buf.clear()
        self.pending_len = None
        self.resync = True

    def _feed_data(self, data: bytes, ts: float, emit) -> None:
        if self.skip:
            if len(data) <= self.skip:
                self.skip -= len(data)
                return
            data = data[self.skip:]
            self.skip = 0
        self.buf += data
        if self.resync:
            self._resync(ts, emit)
            if self.resync:
                return
        self._parse_frames(ts, emit)

    def _resync(self, ts: float, emit) -> None:
        off = self._scan()
        if off < 0:
            # Keep the buffer bounded while scanning.
            if len(self.buf) > _MAX_RESYNC:
                drop = len(self.buf) - _MAX_RESYNC
                self.resync_dropped += drop
                del self.buf[:drop]
            return
        dropped = off + self.resync_dropped
        if dropped:
            emit(MalformedPlaceholder(
                bytes(self.buf[:off]), ts,
                "skipped %d byte(s) while resynchronizing" % dropped))
        del self.buf[:off]
        self.resync_dropped = 0
        self.resync = False

    def _parse_frames(self, ts: float, emit) -> None:
        while True:
            if self.pending_len is None:
                if len(self.buf) < 6:
                    return
                try:
                    self.pending_len = frame_length_from_mbap(self.buf[:6])
                except ModbusError:
                    self._start_resync(emit, ts, "invalid MBAP header")
                    self._resync(ts, emit)
                    if self.resync:
                        return
                    continue
            if len(self.buf) < self.pending_len:
                return
            raw = bytes(self.buf[: self.pending_len])
            del self.buf[: self.pending_len]
            self.pending_len = None
            try:
                frame = parse_frame(raw, ts)
            except ModbusError as exc:
                emit(MalformedPlaceholder(raw, ts, str(exc)))
                continue
            emit(frame)

    def flush(self, ts: float, emit) -> None:
        if self.buf:
            emit(MalformedPlaceholder(
                bytes(self.buf), ts, "truncated frame at end of connection"))
            self.buf.clear()
        elif self.resync_dropped:
            emit(MalformedPlaceholder(
                b"", ts, "skipped %d byte(s) while resynchronizing"
                % self.resync_dropped))
            self.resync_dropped = 0
        self.pending_len = None
        self.skip = 0
        self.resync = False


# Internal placeholders, converted to public events by the connection
# (which knows the connection key and direction).
@dataclass
class MalformedPlaceholder:
    data: bytes
    ts: float
    reason: str


@dataclass
class StreamGapEventPlaceholder:
    gap: int
    ts: float


# -- connection state -----------------------------------------------------

_CONNECTION_LIMIT_HEURISTIC = MAX_BUFFERED


class _Connection:
    def __init__(self, key: Tuple[str, int, str, int]) -> None:
        self.key = key  # (client_ip, client_port, server_ip, server_port)
        self.reasm = {
            "c2s": DirectionReassembler(),
            "s2c": DirectionReassembler(),
        }
        self.parser = {
            "c2s": _DirectionParser(is_request=True),
            "s2c": _DirectionParser(is_request=False),
        }
        self.pending: Dict[Tuple[int, int], List[ModbusFrame]] = {}
        # Responses arrived before their request was decoded (the
        # request may still be stuck in the reassembly buffer).
        self.unmatched: Dict[Tuple[int, int], List[ModbusFrame]] = {}
        self.fin = {"c2s": False, "s2c": False}
        self.last_ts = 0.0
        self.syn_seq: Optional[int] = None

    def feed_segment(self, seg: TcpSegment, direction: str, ts: float,
                     emit) -> None:
        reasm = self.reasm[direction]
        # Heuristic: a segment impossibly far in the past means the
        # 4-tuple was reused by a new connection whose SYN we missed.
        if reasm.started:
            past = (reasm.next_seq - seg.seq) & 0xFFFFFFFF
            if 0 < past < (1 << 31) and past > _CONNECTION_LIMIT_HEURISTIC:
                self._reset(emit)
        chunks = reasm.feed(seg.seq, seg.payload, ts)
        self._handle_chunks(chunks, direction, emit)

    def _handle_chunks(self, chunks, direction, emit) -> None:
        def convert(item):
            if isinstance(item, ModbusFrame):
                self._handle_frame(item, direction, emit)
            elif isinstance(item, StreamGapEventPlaceholder):
                emit(StreamGapEvent(
                    kind="stream_gap", connection=self.key,
                    direction=direction, ts=item.ts, lost_bytes=item.gap))
            elif isinstance(item, MalformedPlaceholder):
                emit(MalformedFrameEvent(
                    kind="malformed_frame", connection=self.key,
                    direction=direction, ts=item.ts, reason=item.reason,
                    data=item.data))
        self.parser[direction].feed(chunks, convert)

    def _handle_frame(self, frame: ModbusFrame, direction: str, emit) -> None:
        key = (frame.transaction_id, frame.unit_id)
        if direction == "c2s":
            waiting = self.unmatched.get(key)
            if waiting:
                response = waiting.pop(0)
                if not waiting:
                    del self.unmatched[key]
                self._pair(frame, response, emit)
            else:
                self.pending.setdefault(key, []).append(frame)
        else:
            queue = self.pending.get(key)
            if queue:
                request = queue.pop(0)
                if not queue:
                    del self.pending[key]
                self._pair(request, frame, emit)
            else:
                self.unmatched.setdefault(key, []).append(frame)

    def _pair(self, request: ModbusFrame, response: ModbusFrame,
              emit) -> None:
        resolve_response_addresses(request, response)
        emit(TransactionEvent(
            kind="transaction", connection=self.key,
            unit_id=response.unit_id,
            function_code=response.function_code,
            transaction_id=response.transaction_id,
            request_ts=request.ts, response_ts=response.ts,
            request=request, response=response))

    def _reset(self, emit) -> None:
        """Abandon current state (connection reuse detected)."""
        self.finalize(emit)
        self.reasm = {
            "c2s": DirectionReassembler(),
            "s2c": DirectionReassembler(),
        }
        self.parser = {
            "c2s": _DirectionParser(is_request=True),
            "s2c": _DirectionParser(is_request=False),
        }
        self.pending = {}
        self.unmatched = {}
        self.fin = {"c2s": False, "s2c": False}

    def finalize(self, emit) -> None:
        for direction in ("c2s", "s2c"):
            chunks = self.reasm[direction].flush()
            self._handle_chunks(chunks, direction, emit)
            self.parser[direction].flush(self.last_ts, _wrap_emit(
                self, direction, emit))
        for queue in self.pending.values():
            for request in queue:
                emit(UnansweredRequestEvent(
                    kind="unanswered_request", connection=self.key,
                    unit_id=request.unit_id,
                    function_code=request.function_code,
                    transaction_id=request.transaction_id,
                    ts=request.ts, request=request))
        self.pending = {}
        for queue in self.unmatched.values():
            for response in queue:
                emit(OrphanResponseEvent(
                    kind="orphan_response", connection=self.key,
                    unit_id=response.unit_id,
                    function_code=response.function_code,
                    transaction_id=response.transaction_id,
                    ts=response.ts, response=response))
        self.unmatched = {}


def _wrap_emit(conn: _Connection, direction: str, emit):
    def convert(item):
        if isinstance(item, MalformedPlaceholder):
            emit(MalformedFrameEvent(
                kind="malformed_frame", connection=conn.key,
                direction=direction, ts=item.ts, reason=item.reason,
                data=item.data))
        elif isinstance(item, ModbusFrame):
            conn._handle_frame(item, direction, emit)
    return convert


# -- top level ------------------------------------------------------------


def decode(path: str) -> Iterator[object]:
    """Decode a pcap file, yielding events as they are discovered."""
    events: List[object] = []

    def emit(event) -> None:
        events.append(event)

    with open(path, "rb") as fh:
        reader = PcapReader(fh)
        if reader.linktype != LINKTYPE_ETHERNET:
            raise PcapError(
                "unsupported link type %d (Ethernet expected)"
                % reader.linktype)
        connections: Dict[Tuple[str, int, str, int], _Connection] = {}
        for pkt in reader:
            seg = parse_segment(pkt.data)
            if seg is None:
                continue
            if seg.dst_port == MODBUS_PORT:
                key = (seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port)
                direction = "c2s"
            elif seg.src_port == MODBUS_PORT:
                key = (seg.dst_ip, seg.dst_port, seg.src_ip, seg.src_port)
                direction = "s2c"
            else:
                continue
            conn = connections.get(key)
            if seg.flags & _TCP_SYN and not seg.flags & _TCP_ACK:
                # A SYN with a fresh ISN means the 4-tuple was reused;
                # a retransmitted SYN (same ISN) is ignored.
                if conn is None or conn.syn_seq != seg.seq:
                    if conn is not None:
                        conn.finalize(emit)
                    conn = _Connection(key)
                    conn.syn_seq = seg.seq
                    connections[key] = conn
            elif conn is None:
                conn = _Connection(key)
                connections[key] = conn
            conn.last_ts = pkt.ts
            if seg.payload:
                conn.feed_segment(seg, direction, pkt.ts, emit)
            if seg.flags & _TCP_FIN:
                conn.fin[direction] = True
            if seg.flags & _TCP_RST or all(conn.fin.values()):
                conn.finalize(emit)
                del connections[key]
            yield from events
            events.clear()
        for conn in connections.values():
            conn.finalize(emit)
        yield from events
