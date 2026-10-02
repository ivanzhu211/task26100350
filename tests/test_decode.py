import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modbus_decode import (decode, MalformedFrame, OrphanResponse, StreamGap,
                           Transaction, UnansweredRequest)
from tests.pcap_builder import (TCP_ACK, TCP_SYN, build_pcap, fc3_request,
                                fc3_response, fc6_request, fc16_request, mbap,
                                tcp_segment)

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CPORT = 40000
SPORT = 502
SEQ_MOD = 1 << 32


def req(pkt_seq, payload, ts, flags=TCP_ACK, **kw):
    return (ts, tcp_segment(CLIENT, SERVER, CPORT, SPORT, pkt_seq, flags,
                            payload, **kw))


def resp(pkt_seq, payload, ts, flags=TCP_ACK, **kw):
    return (ts, tcp_segment(SERVER, CLIENT, SPORT, CPORT, pkt_seq, flags,
                            payload, **kw))


class DecodeTestBase(unittest.TestCase):
    def run_decode(self, packets, **pcap_kw):
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            build_pcap(packets, path, **pcap_kw)
            return list(decode(path))
        finally:
            os.unlink(path)


class TestFragmentedWriteMultiple(DecodeTestBase):
    """FC16 request split into 3 segments: middle arrives last, first
    segment retransmitted, sequence wraps 2**32 in the middle of the
    frame. Address and values must decode exactly."""

    def test_reassembly(self):
        base = SEQ_MOD - 5  # wrap happens 5 bytes into the frame
        frame = mbap(1, 1, fc16_request(100, [0x1111, 0x2222, 0x3333]))
        assert len(frame) == 19
        p1, p2, p3 = frame[:8], frame[8:14], frame[14:]
        packets = [
            req(base - 1, b"", 0.5, flags=TCP_SYN),
            resp(5000, b"", 0.6, flags=TCP_SYN | TCP_ACK),
            req(base, p1, 1.0),
            req(base, p1, 2.0),                      # retransmission
            req((base + 14) % SEQ_MOD, p3, 3.0),     # tail arrives early
            req((base + 8) % SEQ_MOD, p2, 4.0),      # middle completes it
            resp(5001, mbap(1, 1, struct.pack(">BHH", 16, 100, 3)), 5.0),
        ]
        events = self.run_decode(packets)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 1, events)
        txn = txns[0]
        self.assertEqual(txn.transaction_id, 1)
        self.assertEqual(txn.unit_id, 1)
        self.assertEqual(txn.function_code, 16)
        self.assertEqual(txn.request["address"], 100)
        self.assertEqual(txn.request["quantity"], 3)
        self.assertEqual(txn.request["values"],
                         {100: 0x1111, 101: 0x2222, 102: 0x3333})
        self.assertEqual(txn.response, {"address": 100, "quantity": 3})
        self.assertEqual(txn.request_ts, 4.0)   # completed by middle segment
        self.assertEqual(txn.response_ts, 5.0)
        self.assertFalse(txn.exception)
        # no noise
        self.assertEqual([e for e in events if isinstance(
            e, (StreamGap, MalformedFrame, OrphanResponse,
                UnansweredRequest))], [])


class TestGapWithFakeMbapInResidual(DecodeTestBase):
    """A gap lands in the middle of a frame. The residual half-frame
    after the gap contains bytes that look like a valid MBAP header.
    No fake frame may be emitted; the next complete request must pair
    with its response."""

    def test_gap_recovery(self):
        frame_b = mbap(2, 1, fc16_request(
            0, [0x0005, 0x0000, 0x0006, 0x0103]))
        # residual bytes frame_b[13:21] == 00 05 00 00 00 06 01 03
        self.assertEqual(frame_b[13:21],
                         b"\x00\x05\x00\x00\x00\x06\x01\x03")
        req_c = mbap(0x0303, 1, fc3_request(10, 1))
        packets = [
            req(999, b"", 0.0, flags=TCP_SYN),
            req(1000, mbap(1, 1, fc3_request(0, 2)), 1.0),
            resp(8000, mbap(1, 1, fc3_response([0xAAAA, 0xBBBB])), 2.0),
            req(1012, frame_b[:10], 3.0),        # gap: frame_b[10:13] lost
            req(1025, frame_b[13:], 4.0),        # residual half-frame
            req(1033, req_c, 5.0),
            resp(8013, mbap(0x0303, 1, fc3_response([0x00C9])), 6.0),
        ]
        events = self.run_decode(packets)

        gaps = [e for e in events if isinstance(e, StreamGap)]
        self.assertEqual(len(gaps), 1, events)
        self.assertEqual(gaps[0].direction, "request")
        self.assertEqual(gaps[0].bytes_lost, 3)

        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual([t.transaction_id for t in txns], [1, 0x0303])
        self.assertEqual(txns[1].request["address"], 10)
        self.assertEqual(txns[1].response["values"], {10: 0x00C9})

        # the fake MBAP header (transaction id 5) must produce nothing
        for e in events:
            self.assertNotEqual(getattr(e, "transaction_id", None), 5, e)
        self.assertEqual([e for e in events if isinstance(
            e, (OrphanResponse, UnansweredRequest, MalformedFrame))], [])


class TestMidCaptureStart(DecodeTestBase):
    """Capture starts mid-connection: first packet begins with half a
    frame; the client pipelined several requests. Responses whose
    requests were not captured are orphans; the rest pair normally."""

    def test_mid_capture(self):
        tail = b"\x03\x00\x0a\x00\x02"  # tail of an uncaptured request
        req1 = mbap(11, 1, fc3_request(0, 1))
        req2 = mbap(12, 1, fc6_request(1, 0x00FF))
        packets = [
            req(5000, tail + req1 + req2, 1.0),
            resp(9000, mbap(10, 1, fc3_response([0xBEEF])), 2.0),
            resp(9011, mbap(11, 1, fc3_response([0x0001])), 3.0),
            resp(9022, mbap(12, 1, fc6_request(1, 0x00FF)), 4.0),
        ]
        events = self.run_decode(packets)

        orphans = [e for e in events if isinstance(e, OrphanResponse)]
        self.assertEqual(len(orphans), 1, events)
        self.assertEqual(orphans[0].transaction_id, 10)
        self.assertEqual(orphans[0].function_code, 3)

        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual([t.transaction_id for t in txns], [11, 12])
        self.assertEqual(txns[0].response["values"], {0: 1})
        self.assertEqual(txns[1].request["address"], 1)
        self.assertEqual(txns[1].request["value"], 0x00FF)
        self.assertEqual([e for e in events if isinstance(
            e, (StreamGap, MalformedFrame, UnansweredRequest))], [])


class TestBasicEndianVlanPadding(DecodeTestBase):
    """Big-endian nanosecond pcap, double 802.1Q tags, padded short
    frames, plus one unanswered request."""

    def test_basic(self):
        packets = [
            req(100, b"", 0.1, flags=TCP_SYN, vlans=(100, 200), pad=60),
            resp(200, b"", 0.2, flags=TCP_SYN | TCP_ACK, vlans=(100, 200),
                 pad=60),
            req(101, mbap(1, 1, fc3_request(5, 2)), 1.0,
                vlans=(100, 200), pad=60),
            resp(201, mbap(1, 1, fc3_response([7, 8])), 2.0,
                 vlans=(100, 200), pad=60),
            req(113, mbap(2, 1, fc3_request(9, 1)), 3.0,
                vlans=(100, 200), pad=60),
        ]
        events = self.run_decode(packets, endian=">", nano=True)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 1, events)
        self.assertEqual(txns[0].response["values"], {5: 7, 6: 8})
        self.assertEqual(txns[0].connection.client_ip, CLIENT)
        self.assertEqual(txns[0].connection.server_port, 502)
        unans = [e for e in events if isinstance(e, UnansweredRequest)]
        self.assertEqual(len(unans), 1, events)
        self.assertEqual(unans[0].transaction_id, 2)


if __name__ == "__main__":
    unittest.main()
