"""Modbus TCP (MBAP) frame parsing and request/response decoding."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_COILS = 15
WRITE_MULTIPLE_REGISTERS = 16
READ_WRITE_MULTIPLE_REGISTERS = 23

KNOWN_FUNCTION_CODES = {
    READ_COILS, READ_DISCRETE_INPUTS, READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS, WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER,
    WRITE_MULTIPLE_COILS, WRITE_MULTIPLE_REGISTERS,
    READ_WRITE_MULTIPLE_REGISTERS,
}

EXCEPTION_NAMES = {
    1: "ILLEGAL_FUNCTION",
    2: "ILLEGAL_DATA_ADDRESS",
    3: "ILLEGAL_DATA_VALUE",
    4: "SERVER_DEVICE_FAILURE",
    5: "ACKNOWLEDGE",
    6: "SERVER_DEVICE_BUSY",
    8: "MEMORY_PARITY_ERROR",
    10: "GATEWAY_PATH_UNAVAILABLE",
    11: "GATEWAY_TARGET_FAILED",
}

MBAP_HEADER_LEN = 7
MAX_PDU_LEN = 253
MAX_FRAME_LEN = 6 + 1 + MAX_PDU_LEN  # MBAP(6+unit) + PDU


class ModbusError(Exception):
    """Raised when a frame cannot be parsed."""


@dataclass
class ModbusFrame:
    """One parsed Modbus TCP frame."""

    transaction_id: int
    unit_id: int
    function_code: int
    is_exception: bool
    exception_code: Optional[int]
    pdu: bytes  # function code + data
    raw: bytes  # full MBAP + PDU bytes
    ts: float  # time the last byte of the frame arrived
    start_address: Optional[int] = None
    quantity: Optional[int] = None
    values: Optional[list] = None  # read/written values (self-contained part)
    address_values: Optional[List[Tuple[int, object]]] = None
    write_start_address: Optional[int] = None  # FC23 write side
    write_quantity: Optional[int] = None


def frame_length_from_mbap(header: bytes) -> int:
    """Given >=6 bytes of MBAP header, return total frame length.

    Raises ModbusError if the header is implausible.
    """
    if len(header) < 6:
        raise ModbusError("MBAP header too short")
    protocol_id, length = struct.unpack(">HH", header[2:6])
    if protocol_id != 0:
        raise ModbusError("protocol id != 0")
    if length < 2 or length > 1 + MAX_PDU_LEN:
        raise ModbusError("implausible MBAP length %d" % length)
    return 6 + length


def _bits(data: bytes, count: int) -> List[bool]:
    out = []
    for i in range(count):
        out.append(bool(data[i >> 3] >> (i & 7) & 1))
    return out


def _regs(data: bytes) -> List[int]:
    return [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data), 2)]


def parse_frame(raw: bytes, ts: float) -> ModbusFrame:
    """Parse a complete Modbus TCP frame (MBAP header + PDU)."""
    if len(raw) < MBAP_HEADER_LEN + 1:
        raise ModbusError("frame too short")
    transaction_id, protocol_id, length, unit_id = struct.unpack(
        ">HHHB", raw[:MBAP_HEADER_LEN]
    )
    if protocol_id != 0:
        raise ModbusError("protocol id != 0")
    if 6 + length != len(raw):
        raise ModbusError("length field mismatch")
    pdu = raw[MBAP_HEADER_LEN:]
    function_code = pdu[0]
    is_exception = bool(function_code & 0x80)
    frame = ModbusFrame(
        transaction_id=transaction_id,
        unit_id=unit_id,
        function_code=function_code & 0x7F if is_exception else function_code,
        is_exception=is_exception,
        exception_code=None,
        pdu=pdu,
        raw=raw,
        ts=ts,
    )
    if is_exception:
        if len(pdu) < 2:
            raise ModbusError("exception PDU too short")
        frame.exception_code = pdu[1]
        return frame
    body = pdu[1:]
    fc = frame.function_code
    if fc in (READ_COILS, READ_DISCRETE_INPUTS,
              READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS):
        if len(body) == 4:  # request
            frame.start_address, frame.quantity = struct.unpack(">HH", body)
        elif len(body) >= 1:  # response: byte count + data
            count = body[0]
            data = body[1:1 + count]
            if len(data) != count:
                raise ModbusError("short read response")
            if fc in (READ_COILS, READ_DISCRETE_INPUTS):
                frame.values = _bits(data, count * 8)
            else:
                if count % 2:
                    raise ModbusError("odd register byte count")
                frame.values = _regs(data)
        else:
            raise ModbusError("empty PDU body")
    elif fc in (WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER):
        if len(body) != 4:
            raise ModbusError("bad single-write length")
        addr, value = struct.unpack(">HH", body)
        frame.start_address = addr
        frame.quantity = 1
        if fc == WRITE_SINGLE_COIL:
            frame.values = [value == 0xFF00]
        else:
            frame.values = [value]
        frame.address_values = [(addr, frame.values[0])]
    elif fc in (WRITE_MULTIPLE_COILS, WRITE_MULTIPLE_REGISTERS):
        if len(body) == 4:  # response: start + quantity
            frame.start_address, frame.quantity = struct.unpack(">HH", body)
        elif len(body) >= 5:  # request
            start, qty, count = struct.unpack(">HHB", body[:5])
            data = body[5:5 + count]
            if len(data) != count:
                raise ModbusError("short write data")
            frame.start_address = start
            frame.quantity = qty
            if fc == WRITE_MULTIPLE_COILS:
                frame.values = _bits(data, qty)
            else:
                frame.values = _regs(data)
                if len(frame.values) != qty:
                    raise ModbusError("register count mismatch")
            frame.address_values = [
                (start + i, v) for i, v in enumerate(frame.values)
            ]
        else:
            raise ModbusError("bad multiple-write length")
    elif fc == READ_WRITE_MULTIPLE_REGISTERS:
        if len(body) >= 9:  # request
            (rstart, rqty, wstart, wqty, count) = struct.unpack(
                ">HHHHB", body[:9]
            )
            data = body[9:9 + count]
            if len(data) != count:
                raise ModbusError("short FC23 write data")
            frame.start_address = rstart
            frame.quantity = rqty
            frame.write_start_address = wstart
            frame.write_quantity = wqty
            frame.values = _regs(data)
            frame.address_values = [
                (wstart + i, v) for i, v in enumerate(frame.values)
            ]
        elif len(body) >= 1:  # response: byte count + read registers
            count = body[0]
            data = body[1:1 + count]
            if len(data) != count or count % 2:
                raise ModbusError("bad FC23 response")
            frame.values = _regs(data)
        else:
            raise ModbusError("empty FC23 body")
    return frame


def resolve_response_addresses(request: ModbusFrame,
                               response: ModbusFrame) -> None:
    """Fill in per-address values on a read response using the matched
    request's start address and quantity."""
    fc = request.function_code
    if response.is_exception or request.start_address is None:
        return
    if fc in (READ_COILS, READ_DISCRETE_INPUTS,
              READ_HOLDING_REGISTERS, READ_INPUT_REGISTERS,
              READ_WRITE_MULTIPLE_REGISTERS):
        if response.values is None:
            return
        qty = request.quantity
        values = response.values
        if qty is not None and fc in (READ_COILS, READ_DISCRETE_INPUTS):
            values = values[:qty]  # trim padding bits
        response.values = values
        response.address_values = [
            (request.start_address + i, v) for i, v in enumerate(values)
        ]
