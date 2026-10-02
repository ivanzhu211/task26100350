import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from modbus_pcap import decode
from modbus_pcap.decoder import (
    MalformedFrameEvent,
    OrphanResponseEvent,
    StreamGapEvent,
    TransactionEvent,
    UnansweredRequestEvent,
)
from helpers import (
    CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
    FLAGS_FIN, FLAGS_PA, FLAGS_SYN,
    build_pcap, client_packet, mbap, server_packet, tcp_packet,
)

CONN = (CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)


def run_decode(packets, **kw):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        fh.write(build_pcap(packets, **kw))
        path = fh.name
    try:
        return list(decode(path))
    finally:
        os.unlink(path)


def kinds(events):
    return [e.kind for e in events]


class BasicTest(unittest.TestCase):
    def test_simple_transaction(self):
        req = mbap(1, 1, struct.pack(">BHH", 3, 0x006B, 2))
        resp = mbap(1, 1, struct.pack(">BBHH", 3, 4, 0x0222, 0x0000))
        events = run_decode([
            (1.0, client_packet(1000, req)),
            (2.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        ev = events[0]
        self.assertEqual(ev.connection, CONN)
        self.assertEqual(ev.function_code, 3)
        self.assertEqual(ev.unit_id, 1)
        self.assertEqual(ev.request_ts, 1.0)
        self.assertEqual(ev.response_ts, 2.0)
        self.assertEqual(ev.response.address_values,
                         [(0x006B, 0x0222), (0x006C, 0x0000)])

    def test_multiple_frames_one_packet(self):
        req1 = mbap(1, 1, struct.pack(">BHH", 6, 0x0010, 0x00FF))
        req2 = mbap(2, 1, struct.pack(">BHH", 6, 0x0011, 0x0001))
        resp1 = mbap(1, 1, struct.pack(">BHH", 6, 0x0010, 0x00FF))
        resp2 = mbap(2, 1, struct.pack(">BHH", 6, 0x0011, 0x0001))
        events = run_decode([
            (1.0, client_packet(1000, req1 + req2)),
            (2.0, server_packet(5000, resp1 + resp2)),
        ])
        self.assertEqual(kinds(events), ["transaction", "transaction"])
        self.assertEqual(events[1].request.start_address, 0x0011)

    def test_frame_split_across_packets(self):
        req = mbap(9, 1, struct.pack(">BHH", 3, 0, 10))
        resp = mbap(9, 1, bytes([3, 20]) + b"\x00" * 20)
        events = run_decode([
            (1.0, client_packet(1000, req[:5])),
            (2.0, client_packet(1005, req[5:])),
            (3.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        self.assertEqual(events[0].request_ts, 2.0)  # completed at 2nd pkt

    def test_exception_response(self):
        req = mbap(4, 1, struct.pack(">BHH", 3, 0, 1))
        resp = mbap(4, 1, bytes([0x83, 0x02]))
        events = run_decode([
            (1.0, client_packet(1000, req)),
            (2.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        self.assertTrue(events[0].response.is_exception)
        self.assertEqual(events[0].response.exception_code, 2)

    def test_unanswered_request(self):
        req = mbap(7, 1, struct.pack(">BHH", 3, 0, 1))
        events = run_decode([(1.0, client_packet(1000, req))])
        self.assertEqual(kinds(events), ["unanswered_request"])
        self.assertEqual(events[0].transaction_id, 7)

    def test_vlan_tags_and_padding(self):
        req = mbap(1, 1, struct.pack(">BHH", 3, 0x006B, 1))
        resp = mbap(1, 1, struct.pack(">BBH", 3, 2, 0x00AE))
        events = run_decode([
            (1.0, client_packet(1000, req, vlans=[100], pad_to=64)),
            (2.0, server_packet(5000, resp, vlans=[100, 200], pad_to=64)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        self.assertEqual(events[0].response.address_values, [(0x006B, 0xAE)])

    def test_big_endian_nanosecond_pcap(self):
        req = mbap(1, 1, struct.pack(">BHH", 3, 0, 1))
        resp = mbap(1, 1, struct.pack(">BBH", 3, 2, 0x0007))
        events = run_decode([
            (1.25, client_packet(1000, req)),
            (2.5, server_packet(5000, resp)),
        ], endian=">", nanos=True)
        self.assertEqual(kinds(events), ["transaction"])
        self.assertAlmostEqual(events[0].request_ts, 1.25)
        self.assertAlmostEqual(events[0].response_ts, 2.5)


class SplitRetransmitWrapTest(unittest.TestCase):
    """A write-multiple-registers request split in three segments:
    middle segment arrives last, first segment retransmitted, and the
    sequence space wraps 2**32 in the middle of the frame."""

    def test_split_retransmit_wrap(self):
        values = [0xAAAA, 0xBBBB, 0xCCCC]
        pdu = struct.pack(">BHHB", 16, 0x0010, 3, 6)
        pdu += struct.pack(">HHH", *values)
        req = mbap(0x1234, 1, pdu)
        self.assertEqual(len(req), 19)

        p1, p2, p3 = req[:8], req[8:14], req[14:]
        seq0 = 0xFFFFFFFC  # wraps around inside p1
        resp = mbap(0x1234, 1, struct.pack(">BHH", 16, 0x0010, 3))
        events = run_decode([
            (1.0, client_packet(seq0, p1)),
            (2.0, client_packet(seq0, p1)),          # retransmit
            (3.0, client_packet((seq0 + 14) & 0xFFFFFFFF, p3)),
            (4.0, client_packet((seq0 + 8) & 0xFFFFFFFF, p2)),
            (5.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        ev = events[0]
        self.assertEqual(ev.function_code, 16)
        self.assertEqual(ev.request.start_address, 0x0010)
        self.assertEqual(ev.request.quantity, 3)
        self.assertEqual(ev.request.address_values,
                         [(0x0010, 0xAAAA), (0x0011, 0xBBBB),
                          (0x0012, 0xCCCC)])
        self.assertEqual(ev.request_ts, 4.0)
        self.assertEqual(ev.response_ts, 5.0)


class GapMidFrameTest(unittest.TestCase):
    """A gap lands in the middle of a frame. The residual half-frame
    after the gap contains bytes that look exactly like a legal MBAP
    header. No pseudo frame may be emitted; the next complete request
    after the gap must pair with its response."""

    def test_gap_with_fake_mbap_in_residue(self):
        # req A: complete read request (will stay unanswered)
        req_a = mbap(1, 1, struct.pack(">BHH", 3, 0x0064, 2))
        # req B: write-multiple-registers whose register data is
        # precisely a plausible MBAP header: tid=5, pid=0, len=6,
        # unit=1, fc=3 (looks like a read-holding-registers request)
        fake_mbap = bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03])
        pdu_b = struct.pack(">BHHB", 16, 0x0000, 4, 8) + fake_mbap
        req_b = mbap(2, 1, pdu_b)
        self.assertEqual(len(req_b), 21)
        self.assertEqual(req_b[13:21], fake_mbap)
        # req C: complete read request after the gap
        req_c = mbap(3, 1, struct.pack(">BHH", 3, 0x000A, 2))
        resp_c = mbap(3, 1, struct.pack(">BBHH", 3, 4, 0x1111, 0x2222))

        seq = 1000
        pkts = [(1.0, client_packet(seq, req_a))]
        seq += len(req_a)
        pkts.append((2.0, client_packet(seq, req_b[:10])))   # MBAP+fc+addr
        seq += 10
        seq += 3                                             # 3 bytes lost
        pkts.append((3.0, client_packet(seq, req_b[13:])))   # == fake MBAP
        seq += len(req_b) - 13
        pkts.append((4.0, client_packet(seq, req_c)))
        pkts.append((5.0, server_packet(5000, resp_c)))
        events = run_decode(pkts)

        ks = kinds(events)
        # no pseudo frame from the fake MBAP (tid 5 must never appear)
        for ev in events:
            for frame in (getattr(ev, "request", None),
                          getattr(ev, "response", None)):
                if frame is not None:
                    self.assertNotEqual(frame.transaction_id, 5)
        # exactly one gap event, 3 bytes lost, client->server
        gaps = [e for e in events if e.kind == "stream_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].lost_bytes, 3)
        self.assertEqual(gaps[0].direction, "c2s")
        self.assertEqual(gaps[0].connection, CONN)
        # req C pairs with its response
        txns = [e for e in events if e.kind == "transaction"]
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0].transaction_id, 3)
        self.assertEqual(txns[0].response.address_values,
                         [(0x000A, 0x1111), (0x000B, 0x2222)])
        # req A is reported unanswered; req B vanished with the gap
        un = [e for e in events if e.kind == "unanswered_request"]
        self.assertEqual([e.transaction_id for e in un], [1])


class MidStreamStartTest(unittest.TestCase):
    """Capture starts mid-connection: the first packet begins with
    the tail of some frame. The client pipelines several requests
    before any response arrives. Responses whose requests were not
    captured become orphan responses; the rest pair normally."""

    def test_midstream_start_pipelined_requests(self):
        # req X (tid 0x100) is only partially captured: its tail
        req_x = mbap(0x100, 1, struct.pack(">BHHB", 16, 0x0020, 2, 4)
                     + struct.pack(">HH", 0xDEAD, 0xBEEF))
        tail_x = req_x[10:]  # capture begins inside req X
        req_y = mbap(0x101, 1, struct.pack(">BHH", 3, 0x0030, 2))
        req_z = mbap(0x102, 1, struct.pack(">BHH", 3, 0x0040, 1))
        resp_x = mbap(0x100, 1, struct.pack(">BHH", 16, 0x0020, 2))
        resp_y = mbap(0x101, 1, struct.pack(">BBHH", 3, 4, 0x00AA, 0x00BB))
        resp_z = mbap(0x102, 1, struct.pack(">BBH", 3, 2, 0x00CC))

        cseq = 777777  # arbitrary mid-stream client seq
        sseq = 888888
        pkts = [
            (1.0, client_packet(cseq, tail_x)),
            # client pipelines Y and Z before any response arrives
            (2.0, client_packet(cseq + len(tail_x), req_y)),
            (3.0, client_packet(cseq + len(tail_x) + len(req_y), req_z)),
            (4.0, server_packet(sseq, resp_x)),
            (5.0, server_packet(sseq + len(resp_x), resp_y)),
            (6.0, server_packet(sseq + len(resp_x) + len(resp_y), resp_z)),
        ]
        events = run_decode(pkts)

        txns = [e for e in events if e.kind == "transaction"]
        self.assertEqual([e.transaction_id for e in txns],
                         [0x101, 0x102])
        self.assertEqual(txns[0].response.address_values,
                         [(0x0030, 0x00AA), (0x0031, 0x00BB)])
        self.assertEqual(txns[1].response.address_values,
                         [(0x0040, 0x00CC)])
        # response X has no captured request: orphan
        orphans = [e for e in events if e.kind == "orphan_response"]
        self.assertEqual(len(orphans), 1)
        self.assertEqual(orphans[0].transaction_id, 0x100)
        self.assertEqual(orphans[0].function_code, 16)
        # no unanswered requests: Y and Z both got responses
        self.assertNotIn("unanswered_request", kinds(events))


class RobustnessTest(unittest.TestCase):
    def test_connection_reuse_same_tuple(self):
        # first connection: one unanswered request, then FIN
        req1 = mbap(1, 1, struct.pack(">BHH", 3, 0, 1))
        # second connection on the same 4-tuple: full transaction
        req2 = mbap(2, 1, struct.pack(">BHH", 3, 0x10, 1))
        resp2 = mbap(2, 1, struct.pack(">BBH", 3, 2, 0x0055))
        events = run_decode([
            (1.0, client_packet(0, b"", FLAGS_SYN)),
            (2.0, client_packet(1000, req1)),
            (3.0, client_packet(0, b"", FLAGS_FIN)),
            (4.0, server_packet(0, b"", FLAGS_FIN)),
            # same 4-tuple reused
            (5.0, client_packet(0, b"", FLAGS_SYN)),
            (6.0, client_packet(5000, req2)),
            (7.0, server_packet(9000, resp2)),
        ])
        ks = kinds(events)
        self.assertIn("unanswered_request", ks)
        self.assertIn("transaction", ks)
        txn = events[ks.index("transaction")]
        self.assertEqual(txn.transaction_id, 2)
        self.assertEqual(txn.response.address_values, [(0x10, 0x55)])
        un = events[ks.index("unanswered_request")]
        self.assertEqual(un.transaction_id, 1)

    def test_conflicting_overlap_first_wins(self):
        req = mbap(8, 1, struct.pack(">BHH", 3, 0x0050, 1))
        resp = mbap(8, 1, struct.pack(">BBH", 3, 2, 0x0042))
        corrupted = bytearray(req)
        corrupted[8] ^= 0xFF  # different content, same seq range
        events = run_decode([
            (1.0, client_packet(1000, req[:8])),
            (2.0, client_packet(1008, req[8:])),
            (3.0, client_packet(1000, bytes(corrupted))),  # overlap, loses
            (4.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])
        self.assertEqual(events[0].request.start_address, 0x0050)

    def test_snaplen_truncation_recovers(self):
        # a truncated packet loses its tail; the stream must declare a
        # gap and still decode the next complete frame
        req1 = mbap(1, 1, struct.pack(">BHH", 3, 0, 1))
        req2 = mbap(2, 1, struct.pack(">BHH", 3, 0x10, 1))
        resp2 = mbap(2, 1, struct.pack(">BBH", 3, 2, 0x0009))
        full = client_packet(1000, req1)
        truncated = full[:-4]  # snaplen cut the last 4 bytes
        with tempfile.NamedTemporaryFile(suffix=".pcap",
                                         delete=False) as fh:
            fh.write(build_pcap([
                (1.0, truncated),
                (2.0, client_packet(1000 + len(req1), req2)),
                (3.0, server_packet(5000, resp2)),
            ]))
            path = fh.name
        try:
            events = list(decode(path))
        finally:
            os.unlink(path)
        ks = kinds(events)
        self.assertIn("stream_gap", ks)
        gap = events[ks.index("stream_gap")]
        self.assertEqual(gap.lost_bytes, 4)
        self.assertIn("transaction", ks)
        self.assertEqual(events[ks.index("transaction")].transaction_id, 2)

    def test_malformed_bytes_then_recovery(self):
        req = mbap(3, 1, struct.pack(">BHH", 3, 0, 1))
        resp = mbap(3, 1, struct.pack(">BBH", 3, 2, 0x0077))
        garbage = b"\xff\xff\xff\xffGARBAGE!!"
        events = run_decode([
            (1.0, client_packet(1000, garbage)),
            (2.0, client_packet(1000 + len(garbage), req)),
            (3.0, server_packet(5000, resp)),
        ])
        ks = kinds(events)
        self.assertIn("malformed_frame", ks)
        self.assertIn("transaction", ks)
        self.assertEqual(events[ks.index("transaction")].transaction_id, 3)

    def test_buffer_limit_treated_as_loss(self):
        import modbus_pcap.reassembly as reasm_mod
        # hole of 5 bytes, then more than MAX_BUFFERED bytes arrive:
        # the hole must be declared lost and decoding must continue
        req_a = mbap(1, 1, struct.pack(">BHH", 3, 0, 1))
        frames = [mbap(t, 1, struct.pack(">BHH", 3, t, 1))
                  for t in range(2, 8)]
        resps = [mbap(t, 1, struct.pack(">BBH", 3, 2, t)) for t in range(2, 8)]
        seq = 1000
        pkts = [(1.0, client_packet(seq, req_a))]
        seq += len(req_a) + 5  # 5 bytes lost
        ts = 2.0
        for f in frames:
            pkts.append((ts, client_packet(seq, f)))
            seq += len(f)
            ts += 1.0
        sseq = 5000
        for r in resps:
            pkts.append((ts, server_packet(sseq, r)))
            sseq += len(r)
            ts += 1.0
        old = reasm_mod.MAX_BUFFERED
        reasm_mod.MAX_BUFFERED = 64
        try:
            events = run_decode(pkts)
        finally:
            reasm_mod.MAX_BUFFERED = old
        ks = kinds(events)
        self.assertIn("stream_gap", ks)
        gap = events[ks.index("stream_gap")]
        self.assertEqual(gap.lost_bytes, 5)
        self.assertEqual(gap.direction, "c2s")
        txn_ids = sorted(e.transaction_id for e in events
                         if e.kind == "transaction")
        self.assertEqual(txn_ids, [2, 3, 4, 5, 6, 7])

    def test_non_modbus_ports_ignored(self):
        other = tcp_packet(CLIENT_IP, SERVER_IP, 1234, 80, 1000,
                           b"GET / HTTP/1.0\r\n\r\n")
        req = mbap(1, 1, struct.pack(">BHH", 3, 0, 1))
        resp = mbap(1, 1, struct.pack(">BBH", 3, 2, 0x0001))
        events = run_decode([
            (0.5, other),
            (1.0, client_packet(1000, req)),
            (2.0, server_packet(5000, resp)),
        ])
        self.assertEqual(kinds(events), ["transaction"])


if __name__ == "__main__":
    unittest.main()
