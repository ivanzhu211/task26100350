import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modbus_decode.tcp import DirectionStream, SEQ_MOD


class TestDirectionStream(unittest.TestCase):
    def test_wrap_out_of_order_retransmit(self):
        s = DirectionStream()
        base = SEQ_MOD - 4
        s.push(base, b"AAAA", 1.0)
        s.push((base + 8) % SEQ_MOD, b"CCCC", 3.0)
        s.push((base + 4) % SEQ_MOD, b"BBBB", 2.0)
        s.push(base, b"AAAA", 1.5)  # retransmit
        self.assertEqual(s.drain(),
                         [("data", b"AAAA", 1.0), ("data", b"BBBB", 2.0),
                          ("data", b"CCCC", 3.0)])
        self.assertEqual(s.next_seq, (base + 12) % SEQ_MOD)

    def test_conflicting_overlap_first_wins(self):
        s = DirectionStream()
        s.push(100, b"hello", 1.0)
        s.push(100, b"HELLO", 2.0)
        s.push(105, b"WORLD", 3.0)
        self.assertEqual(s.drain(),
                         [("data", b"hello", 1.0), ("data", b"WORLD", 3.0)])

    def test_partial_overlap_with_buffered(self):
        s = DirectionStream()
        s.push(0, b"ab", 1.0)
        s.push(4, b"XYZ", 2.0)
        s.push(2, b"cdefg", 3.0)
        self.assertEqual(s.drain(),
                         [("data", b"ab", 1.0), ("data", b"cdefg", 3.0)])
        self.assertEqual(s.next_seq, 7)

    def test_gap_at_finalize(self):
        s = DirectionStream()
        s.push(0, b"ab", 1.0)
        s.push(6, b"gh", 2.0)
        self.assertEqual(s.drain(), [("data", b"ab", 1.0)])
        self.assertEqual(s.finalize(),
                         [("gap", 4, 2.0), ("data", b"gh", 2.0)])

    def test_buffer_cap_declares_gap(self):
        import modbus_decode.tcp as tcp
        old = tcp.MAX_BUFFERED
        tcp.MAX_BUFFERED = 4
        try:
            s = DirectionStream()
            s.push(0, b"ab", 1.0)
            s.push(10, b"kl", 2.0)     # buffered (2 bytes)
            s.push(20, b"yz", 3.0)     # 4 bytes buffered, ok
            s.push(30, b"QR", 4.0)     # exceeds cap -> gap to 10, drain
            events = s.drain()
            self.assertEqual(events[0], ("data", b"ab", 1.0))
            self.assertIn(("gap", 8, 2.0), events)
            self.assertIn(("data", b"kl", 2.0), events)
        finally:
            tcp.MAX_BUFFERED = old


if __name__ == "__main__":
    unittest.main()
