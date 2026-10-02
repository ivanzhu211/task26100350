import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modbus_decode import (decode, OrphanResponse, StreamGap, Transaction,
                           UnansweredRequest)
from tests.pcap_builder import (TCP_ACK, TCP_FIN, TCP_SYN, build_pcap,
                                fc3_request, fc3_response, mbap, tcp_segment)
from tests.test_decode import CLIENT, CPORT, SERVER, SPORT, DecodeTestBase


def req(pkt_seq, payload, ts, flags=TCP_ACK, **kw):
    return (ts, tcp_segment(CLIENT, SERVER, CPORT, SPORT, pkt_seq, flags,
                            payload, **kw))


def resp(pkt_seq, payload, ts, flags=TCP_ACK, **kw):
    return (ts, tcp_segment(SERVER, CLIENT, SPORT, CPORT, pkt_seq, flags,
                            payload, **kw))


class TestExceptionResponse(DecodeTestBase):
    def test_exception(self):
        packets = [
            req(1000, mbap(1, 1, fc3_request(0, 10)), 1.0),
            resp(2000, mbap(1, 1, b"\x83\x02"), 2.0),
        ]
        events = self.run_decode(packets)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 1, events)
        txn = txns[0]
        self.assertTrue(txn.exception)
        self.assertEqual(txn.function_code, 3)
        self.assertEqual(txn.response["exception_code"], 2)
        self.assertEqual(txn.response["exception_name"],
                         "illegal_data_address")


class TestConnectionReuse(DecodeTestBase):
    """The same 4-tuple carries two sequential connections."""

    def test_reuse(self):
        packets = [
            req(100, b"", 0.1, flags=TCP_SYN),
            resp(900, b"", 0.2, flags=TCP_SYN | TCP_ACK),
            req(101, mbap(1, 1, fc3_request(0, 1)), 1.0),
            resp(901, mbap(1, 1, fc3_response([42])), 2.0),
            req(113, b"", 3.0, flags=TCP_FIN | TCP_ACK),
            resp(912, b"", 3.1, flags=TCP_FIN | TCP_ACK),
            # second connection on the same 4-tuple
            req(5000, b"", 4.0, flags=TCP_SYN),
            resp(8000, b"", 4.1, flags=TCP_SYN | TCP_ACK),
            req(5001, mbap(2, 1, fc3_request(7, 1)), 5.0),
            resp(8001, mbap(2, 1, fc3_response([99])), 6.0),
        ]
        events = self.run_decode(packets)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 2, events)
        self.assertEqual(txns[0].connection.index, 0)
        self.assertEqual(txns[1].connection.index, 1)
        self.assertEqual(txns[0].response["values"], {0: 42})
        self.assertEqual(txns[1].response["values"], {7: 99})
        self.assertEqual([e for e in events
                          if isinstance(e, UnansweredRequest)], [])


class TestSnaplenTruncation(DecodeTestBase):
    """A packet cut by snaplen is treated as lost: a gap is reported,
    the affected frame is dropped, later frames still decode."""

    def test_truncation(self):
        req_b = mbap(2, 1, fc3_request(0, 1))
        full_b = tcp_segment(CLIENT, SERVER, CPORT, SPORT, 1012, TCP_ACK,
                             req_b)
        cut_b = full_b[:40]  # captured shorter than the IP total length
        packets = [
            req(1000, mbap(1, 1, fc3_request(0, 2)), 1.0),
            resp(8000, mbap(1, 1, fc3_response([1, 2])), 2.0),
            (3.0, cut_b, len(full_b)),          # snaplen truncated
            req(1024, mbap(3, 1, fc3_request(4, 1)), 4.0),
            resp(8013, mbap(2, 1, fc3_response([55])), 5.0),
            resp(8024, mbap(3, 1, fc3_response([66])), 6.0),
        ]
        events = self.run_decode(packets)
        gaps = [e for e in events if isinstance(e, StreamGap)]
        self.assertEqual(len(gaps), 1, events)
        self.assertEqual(gaps[0].bytes_lost, 12)
        self.assertEqual(gaps[0].direction, "request")
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual([t.transaction_id for t in txns], [1, 3])
        orphans = [e for e in events if isinstance(e, OrphanResponse)]
        self.assertEqual([o.transaction_id for o in orphans], [2])


class TestReadWriteMultiple(DecodeTestBase):
    def test_fc23_and_fc15(self):
        fc23_req = struct.pack(">BHHHHB", 23, 10, 2, 20, 2, 4) \
            + struct.pack(">HH", 0x1111, 0x2222)
        fc23_resp = struct.pack(">BB", 23, 4) + struct.pack(">HH", 0xAA, 0xBB)
        fc15_req = struct.pack(">BHHBBB", 15, 30, 10, 2, 0b01100101, 0b00000010)
        fc15_resp = struct.pack(">BHH", 15, 30, 10)
        packets = [
            req(1000, mbap(1, 1, fc23_req) + mbap(2, 1, fc15_req), 1.0),
            resp(2000, mbap(1, 1, fc23_resp), 2.0),
            resp(2013, mbap(2, 1, fc15_resp), 3.0),
        ]
        events = self.run_decode(packets)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 2, events)
        t23, t15 = txns
        self.assertEqual(t23.function_code, 23)
        self.assertEqual(t23.request["read_address"], 10)
        self.assertEqual(t23.request["write_address"], 20)
        self.assertEqual(t23.request["values"], {20: 0x1111, 21: 0x2222})
        self.assertEqual(t23.response["values"], {10: 0xAA, 11: 0xBB})
        self.assertEqual(t15.function_code, 15)
        self.assertEqual(t15.request["values"][30], True)
        self.assertEqual(t15.request["values"][31], False)
        self.assertEqual(t15.request["values"][32], True)
        self.assertEqual(t15.request["values"][38], False)
        self.assertEqual(t15.request["values"][39], True)
        self.assertEqual(t15.response, {"address": 30, "quantity": 10})


if __name__ == "__main__":
    unittest.main()


class TestCoilsAndSingleWrite(DecodeTestBase):
    def test_fc1_and_fc5(self):
        fc1_req = struct.pack(">BHH", 1, 20, 3)
        fc1_resp = struct.pack(">BBB", 1, 1, 0b00000101)
        fc5_req = struct.pack(">BHH", 5, 7, 0xFF00)
        fc5_resp = struct.pack(">BHH", 5, 7, 0xFF00)
        packets = [
            req(1000, mbap(1, 1, fc1_req), 1.0),
            req(1012, mbap(2, 1, fc5_req), 1.5),
            resp(2000, mbap(1, 1, fc1_resp), 2.0),
            resp(2010, mbap(2, 1, fc5_resp), 2.5),
        ]
        events = self.run_decode(packets)
        txns = [e for e in events if isinstance(e, Transaction)]
        self.assertEqual(len(txns), 2, events)
        t1, t5 = txns
        self.assertEqual(t1.function_code, 1)
        self.assertEqual(t1.response["values"],
                         {20: True, 21: False, 22: True})
        self.assertEqual(t5.function_code, 5)
        self.assertEqual(t5.request["address"], 7)
        self.assertTrue(t5.request["value"])
        self.assertTrue(t5.response["value"])
