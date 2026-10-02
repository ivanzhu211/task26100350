# task26100350
# modbus_decode

Offline Modbus TCP traffic decoder for classic libpcap captures.
Pure Python standard library - no scapy/dpkt/pyshark, no external tools.

## Usage

```python
from modbus_decode import decode, Transaction, StreamGap

for event in decode("capture.pcap"):
    if isinstance(event, Transaction):
        print(event.function_code, event.request, event.response)
```

`decode(path)` is a generator streaming these event types
(see `modbus_decode/events.py`):

- `Transaction` - request paired with its response (per connection +
  transaction id; multiple outstanding requests supported). Function
  codes 1, 2, 3, 4, 5, 6, 15, 16, 23 decode addresses, quantities and
  concrete values; read values are mapped onto absolute addresses.
  Exception responses decode the exception code (`event.exception`).
- `UnansweredRequest` - request with no response before the connection
  ended.
- `OrphanResponse` - response whose request was never seen.
- `MalformedFrame` - bytes that failed MBAP/PDU validation.
- `StreamGap` - lost bytes in one direction of a connection
  (`bytes_lost`).

## Handles

- classic pcap, both byte orders, microsecond and nanosecond timestamps
- Ethernet with 0-2 802.1Q tags, IPv4 (fragments skipped), TCP port 502
- short frames with Ethernet padding, snaplen-truncated packets
- retransmission, overlapping segments (first-received wins), reordering,
  packet loss, mid-capture starts, sequence-number wraparound, and
  4-tuple reuse across sequential connections
- frames spanning multiple packets and multiple frames per packet

Frame timestamps are the capture time of the packet that delivered the
frame's final byte. Every emitted Modbus frame is an exactly contiguous
slice of the reassembled stream; after a gap the decoder resynchronizes
within the same connection instead of emitting fabricated frames.

Memory is bounded by the number of simultaneously active connections;
out-of-order buffering per direction is capped (excess is declared a
gap). The capture file is read as a stream.

## Tests

```
python3 -m unittest discover -s tests
```
