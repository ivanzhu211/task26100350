"""Orchestration: pcap -> ethernet/IP/TCP -> reassembly -> Modbus events."""
from __future__ import annotations

import socket
import struct
from collections import defaultdict, deque
from typing import Dict, Iterator, List, Optional, Tuple

from . import modbus
from .events import (
    ConnectionId, MalformedFrame, OrphanResponse, StreamGap,
    Transaction, UnansweredRequest,
)
from .pcap import read_packets
from .tcp import DirectionStream, SEQ_MOD

MODBUS_PORT = 502
ETH_P_IP = 0x0800
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
IPPROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04

RESYNC_BUFFER_MAX = 1 << 18  # 256 KiB scan window while unsynchronized


# ---------------------------------------------------------------- link layer

def _parse_tcp_packet(data: bytes):
    """Extract (src_ip, dst_ip, sport, dport, seq, flags, payload) or None.

    Ethernet padding is stripped via the IP total length; packets cut by
    snaplen are dropped entirely (their bytes are treated as lost, which
    the reassembly layer reports as a gap)."""
    if len(data) < 14:
        return None
    (eth_type,) = struct.unpack_from(">H", data, 12)
    off = 14
    while eth_type in VLAN_TYPES:  # one or two 802.1Q tags
        if len(data) < off + 4:
            return None
        (eth_type,) = struct.unpack_from(">H", data, off + 2)
        off += 4
    if eth_type != ETH_P_IP or len(data) < off + 20:
        return None
    ver_ihl = data[off]
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4 or ihl < 20:
        return None
    (total_len,) = struct.unpack_from(">H", data, off + 2)
    if total_len < ihl:
        return None
    (flags_frag,) = struct.unpack_from(">H", data, off + 6)
    if flags_frag & 0x3FFF:  # MF flag or fragment offset: no reassembly
        return None
    if data[off + 9] != IPPROTO_TCP:
        return None
    if len(data) < off + total_len:
        return None  # truncated by snaplen
    src_ip = socket.inet_ntoa(data[off + 12:off + 16])
    dst_ip = socket.inet_ntoa(data[off + 16:off + 20])
    tcp = off + ihl
    if len(data) < tcp + 20:
        return None
    sport, dport, seq, _ack, off_flags = struct.unpack_from(">HHIIH", data, tcp)
    doff = (off_flags >> 12) * 4
    if doff < 20:
        return None
    flags = off_flags & 0x1FF
    payload = data[tcp + doff:off + total_len]
    return src_ip, dst_ip, sport, dport, seq, flags, payload


# ------------------------------------------------------------ frame parsing

class _FrameParser:
    """Turns reassembled stream events into Modbus frames for one
    direction of one connection."""

    def __init__(self, conn: "_Connection", direction: str) -> None:
        self.conn = conn
        self.direction = direction
        self.is_request = direction == "request"
        self.buf = bytearray()
        self.runs: deque = deque()  # [length, arrival_ts] runs covering buf
        self.aligned = False
        self.skip = 0
        self.last_ts = 0.0
        self.out: list = []

    def _consume(self, n: int) -> float:
        """Drop the first n buffered bytes; return the latest arrival
        timestamp among them (the moment those bytes were all present)."""
        del self.buf[:n]
        ts = 0.0
        while n and self.runs:
            run = self.runs[0]
            take = min(run[0], n)
            run[0] -= take
            n -= take
            ts = max(ts, run[1])
            if run[0] == 0:
                self.runs.popleft()
        return ts

    # -- stream events -------------------------------------------------

    def feed(self, ev) -> None:
        if ev[0] == "data":
            self._feed_data(ev[1], ev[2])
        else:
            self._feed_gap(ev[1], ev[2])

    def _feed_data(self, data: bytes, ts: float) -> None:
        self.last_ts = ts
        if self.skip:
            n = min(self.skip, len(data))
            data = data[n:]
            self.skip -= n
            if not data:
                return
        self.buf += data
        self.runs.append([len(data), ts])
        if not self.aligned and len(self.buf) > RESYNC_BUFFER_MAX:
            self._consume(len(self.buf) - RESYNC_BUFFER_MAX)
        self._parse(ts)

    def _feed_gap(self, count: int, ts: float) -> None:
        self.out.append(StreamGap(self.conn.cid, self.direction, count, ts))
        if self.aligned and len(self.buf) >= modbus.MBAP_HEADER_LEN:
            hdr = modbus.parse_mbap(bytes(self.buf))
            if hdr is not None and modbus.validate_mbap(hdr):
                remaining = hdr.frame_length - len(self.buf)
                if 0 < count < remaining:
                    # The gap swallowed the middle of the in-progress
                    # frame; exactly `remaining - count` residual bytes
                    # of it will still arrive. Discard them and land
                    # back on a frame boundary.
                    self.skip = remaining - count
                    self.buf.clear()
                    self.runs.clear()
                    return
        # Alignment after the gap is unknown: resynchronize.
        self.buf.clear()
        self.runs.clear()
        self.aligned = False
        self.skip = 0

    # -- frame extraction ----------------------------------------------

    def _fc_plausible_at(self, off: int) -> bool:
        if off + modbus.MBAP_HEADER_LEN > len(self.buf):
            return False
        fc = self.buf[off + modbus.MBAP_HEADER_LEN]
        if self.is_request:
            return fc in modbus.KNOWN_FUNCTION_CODES
        return (fc & 0x7F) in modbus.KNOWN_FUNCTION_CODES

    def _pdu_ok(self, pdu: bytes) -> bool:
        if not pdu:
            return False
        fc = pdu[0]
        body = pdu[1:]
        try:
            if fc & 0x80 and not self.is_request:
                if len(body) != 1:
                    return False
            elif self.is_request:
                modbus.parse_request_pdu(fc, body)
            else:
                modbus.parse_response_pdu(fc, body)
        except modbus.ModbusError:
            return False
        return True

    def _resync(self, final: bool) -> bool:
        buf = self.buf
        weak: Optional[int] = None
        for off in range(0, len(buf) - modbus.MBAP_HEADER_LEN + 1):
            hdr = modbus.parse_mbap(bytes(buf[off:off + modbus.MBAP_HEADER_LEN]))
            if hdr is None or not modbus.validate_mbap(hdr):
                continue
            if not self._fc_plausible_at(off):
                continue
            flen = hdr.frame_length
            if off + flen > len(buf):
                continue  # frame not fully buffered yet
            pdu = bytes(buf[off + modbus.MBAP_HEADER_LEN:off + flen])
            if not self._pdu_ok(pdu):
                continue
            nxt = off + flen
            strong = False
            if nxt < len(buf):
                hdr2 = modbus.parse_mbap(bytes(buf[nxt:nxt + modbus.MBAP_HEADER_LEN]))
                strong = (hdr2 is not None and modbus.validate_mbap(hdr2)
                          and self._fc_plausible_at(nxt))
            if strong:
                self._lock(off)
                return True
            if weak is None:
                weak = off
        if weak is not None and (weak == 0 or final):
            self._lock(weak)
            return True
        if final:
            self.buf.clear()
        return False

    def _lock(self, off: int) -> None:
        if off:
            self._consume(off)
        self.aligned = True

    def _parse(self, ts: float, final: bool = False) -> None:
        while True:
            if not self.aligned and not self._resync(final):
                return
            if len(self.buf) < modbus.MBAP_HEADER_LEN:
                return
            hdr = modbus.parse_mbap(
                bytes(self.buf[:modbus.MBAP_HEADER_LEN]))
            if hdr is None or not modbus.validate_mbap(hdr):
                self.out.append(MalformedFrame(
                    self.conn.cid, self.direction, "invalid MBAP header",
                    ts, bytes(self.buf[:16])))
                self.aligned = False
                continue
            if len(self.buf) < hdr.frame_length:
                return
            frame_len = hdr.frame_length
            frame = bytes(self.buf[:frame_len])
            frame_ts = self._consume(frame_len)
            pdu = frame[modbus.MBAP_HEADER_LEN:]
            fc = pdu[0]
            if self.is_request:
                known = fc in modbus.KNOWN_FUNCTION_CODES
            else:
                known = (fc & 0x7F) in modbus.KNOWN_FUNCTION_CODES
            if not known:
                self.out.append(MalformedFrame(
                    self.conn.cid, self.direction,
                    f"unsupported function code {fc}", ts, frame))
                continue
            if not self._pdu_ok(pdu):
                self.out.append(MalformedFrame(
                    self.conn.cid, self.direction, "malformed PDU",
                    ts, frame))
                continue
            self.out.append(("frame", hdr, pdu, frame_ts))

    def finish(self) -> None:
        """Final flush at end of connection."""
        self._parse(self.last_ts, final=True)
        if self.aligned and self.buf:
            self.out.append(MalformedFrame(
                self.conn.cid, self.direction,
                "truncated frame at end of connection",
                self.last_ts, bytes(self.buf)))
            self.buf.clear()
            self.runs.clear()


# ---------------------------------------------------------------- pairing

class _Connection:
    def __init__(self, cid: ConnectionId) -> None:
        self.cid = cid
        self.req = DirectionStream()
        self.resp = DirectionStream()
        self.req_parser = _FrameParser(self, "request")
        self.resp_parser = _FrameParser(self, "response")
        self.pending: Dict[Tuple[int, int], deque] = defaultdict(deque)
        self.deferred: deque = deque()  # responses awaiting request-side holes
        self.touched = False
        self.fin: set = set()


class _Decoder:
    def __init__(self) -> None:
        self.conns: Dict[Tuple, _Connection] = {}
        self.indices: Dict[Tuple, int] = defaultdict(int)

    # -- packets --------------------------------------------------------

    def packet(self, ts: float, data: bytes) -> List:
        parsed = _parse_tcp_packet(data)
        if parsed is None:
            return []
        src_ip, dst_ip, sport, dport, seq, flags, payload = parsed
        if sport != MODBUS_PORT and dport != MODBUS_PORT:
            return []
        if dport == MODBUS_PORT:
            client, server = (src_ip, sport), (dst_ip, dport)
            direction = "request"
        else:
            client, server = (dst_ip, dport), (src_ip, sport)
            direction = "response"
        key = (client, server)
        events: List = []
        conn = self.conns.get(key)

        if flags & TCP_SYN and direction == "request":
            # A new connection on a possibly reused 4-tuple.
            if conn is not None and conn.touched:
                events += self._finalize_conn(key, conn)
            conn = self._new_conn(key, client, server)
            conn.req.expect((seq + 1) % SEQ_MOD)
        elif conn is None:
            conn = self._new_conn(key, client, server)

        if flags & TCP_SYN and direction == "response":
            conn.resp.expect((seq + 1) % SEQ_MOD)
        conn.touched = True

        if payload:
            if direction == "request":
                conn.req.push(seq, payload, ts)
                for ev in conn.req.drain():
                    conn.req_parser.feed(ev)
            else:
                conn.resp.push(seq, payload, ts)
                for ev in conn.resp.drain():
                    conn.resp_parser.feed(ev)
            events += self._drain_parser(conn)
            events += self._flush_deferred(conn)

        if flags & TCP_RST:
            events += self._finalize_conn(key, conn)
        elif flags & TCP_FIN:
            conn.fin.add(direction)
            if len(conn.fin) == 2:
                events += self._finalize_conn(key, conn)
        return events

    def _new_conn(self, key, client, server) -> _Connection:
        idx = self.indices[key]
        self.indices[key] = idx + 1
        conn = _Connection(ConnectionId(
            client_ip=client[0], client_port=client[1],
            server_ip=server[0], server_port=server[1], index=idx))
        self.conns[key] = conn
        return conn

    # -- frame -> event -------------------------------------------------

    def _drain_parser(self, conn: _Connection) -> List:
        events: List = []
        for parser in (conn.req_parser, conn.resp_parser):
            for item in parser.out:
                if isinstance(item, tuple) and item[0] == "frame":
                    events += self._pair(conn, parser.direction,
                                         item[1], item[2], item[3])
                else:
                    events.append(item)
            parser.out.clear()
        return events

    def _pair(self, conn: _Connection, direction: str,
              hdr: modbus.MbapHeader, pdu: bytes, ts: float) -> List:
        fc = pdu[0]
        body = pdu[1:]
        key = (hdr.transaction_id, hdr.unit_id)
        if direction == "request":
            req = modbus.parse_request_pdu(fc, body)
            conn.pending[key].append((fc, req, ts))
            return []
        exception = bool(fc & 0x80)
        real_fc = (fc & 0x7F) if exception else fc
        queue = conn.pending.get(key)
        req_rec = queue[0] if queue else None
        if req_rec is None and conn.req.segments:
            # The request stream has an unresolved hole; the matching
            # request may still be recovered later. Defer the decision.
            conn.deferred.append((hdr, pdu, ts))
            return []
        if exception:
            code = body[0] if body else 0
            resp = {
                "exception_code": code,
                "exception_name": modbus.EXCEPTION_CODES.get(code, "unknown"),
            }
        else:
            resp = modbus.parse_response_pdu(
                real_fc, body, req_rec[1] if req_rec else None)
        if req_rec is not None:
            queue.popleft()
            if not queue:
                conn.pending.pop(key, None)
            return [Transaction(
                connection=conn.cid, transaction_id=hdr.transaction_id,
                unit_id=hdr.unit_id, function_code=req_rec[0],
                request=req_rec[1], response=resp,
                request_ts=req_rec[2], response_ts=ts, exception=exception)]
        return [OrphanResponse(
            connection=conn.cid, transaction_id=hdr.transaction_id,
            unit_id=hdr.unit_id, function_code=real_fc, response=resp,
            response_ts=ts, exception=exception)]

    def _flush_deferred(self, conn: _Connection, final: bool = False) -> List:
        if not conn.deferred:
            return []
        if not final and conn.req.segments:
            return []
        events: List = []
        while conn.deferred:
            hdr, pdu, ts = conn.deferred.popleft()
            events += self._pair(conn, "response", hdr, pdu, ts)
        return events

    # -- finalization ---------------------------------------------------

    def _finalize_conn(self, key, conn: _Connection) -> List:
        for stream, parser in ((conn.req, conn.req_parser),
                               (conn.resp, conn.resp_parser)):
            for ev in stream.finalize():
                parser.feed(ev)
            parser.finish()
        events = self._drain_parser(conn)
        events += self._flush_deferred(conn, final=True)
        for (tid, uid), queue in sorted(conn.pending.items()):
            for fc, req, ts in queue:
                events.append(UnansweredRequest(
                    connection=conn.cid, transaction_id=tid, unit_id=uid,
                    function_code=fc, request=req, request_ts=ts))
        conn.pending.clear()
        self.conns.pop(key, None)
        return events

    def finish(self) -> List:
        events: List = []
        for key in list(self.conns):
            events += self._finalize_conn(key, self.conns[key])
        return events


def decode(path: str) -> Iterator:
    """Stream decode events from a pcap file."""
    dec = _Decoder()
    for ts, _caplen, _wirelen, pkt in read_packets(path):
        yield from dec.packet(ts, pkt)
    yield from dec.finish()
