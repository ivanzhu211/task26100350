"""Modbus TCP (MBAP + PDU) parsing for function codes
1, 2, 3, 4, 5, 6, 15, 16, 23, plus exception responses."""
from __future__ import annotations

import struct
from typing import Optional

FC_READ_COILS = 1
FC_READ_DISCRETE_INPUTS = 2
FC_READ_HOLDING_REGISTERS = 3
FC_READ_INPUT_REGISTERS = 4
FC_WRITE_SINGLE_COIL = 5
FC_WRITE_SINGLE_REGISTER = 6
FC_WRITE_MULTIPLE_COILS = 15
FC_WRITE_MULTIPLE_REGISTERS = 16
FC_READ_WRITE_MULTIPLE_REGISTERS = 23

KNOWN_FUNCTION_CODES = frozenset({1, 2, 3, 4, 5, 6, 15, 16, 23})

EXCEPTION_CODES = {
    1: "illegal_function",
    2: "illegal_data_address",
    3: "illegal_data_value",
    4: "server_device_failure",
    5: "acknowledge",
    6: "server_device_busy",
    8: "memory_parity_error",
    10: "gateway_path_unavailable",
    11: "gateway_target_failed_to_respond",
}

MBAP_HEADER_LEN = 7
MAX_PDU_LEN = 253


class ModbusError(Exception):
    pass


class MbapHeader:
    __slots__ = ("transaction_id", "protocol_id", "length", "unit_id")

    def __init__(self, transaction_id: int, protocol_id: int,
                 length: int, unit_id: int) -> None:
        self.transaction_id = transaction_id
        self.protocol_id = protocol_id
        self.length = length
        self.unit_id = unit_id

    @property
    def frame_length(self) -> int:
        """Total frame length in bytes: MBAP header + PDU."""
        return MBAP_HEADER_LEN - 1 + self.length


def parse_mbap(buf: bytes, offset: int = 0) -> Optional[MbapHeader]:
    """Parse an MBAP header; None if not enough bytes. Does not validate."""
    if len(buf) - offset < MBAP_HEADER_LEN:
        return None
    tid, pid, length, uid = struct.unpack_from(">HHHB", buf, offset)
    return MbapHeader(tid, pid, length, uid)


def validate_mbap(hdr: MbapHeader) -> bool:
    """Cheap plausibility check used when (re)synchronizing the stream."""
    if hdr.protocol_id != 0:
        return False
    # length covers unit_id + PDU; PDU is 1..253 bytes.
    if hdr.length < 2 or hdr.length > 1 + MAX_PDU_LEN:
        return False
    return True


def _unpack_bits(data: bytes, start_address: int, quantity: int) -> dict:
    """Map packed coil/discrete bits to absolute addresses."""
    values = {}
    for i in range(quantity):
        byte = data[i >> 3] if (i >> 3) < len(data) else 0
        values[start_address + i] = bool((byte >> (i & 7)) & 1)
    return values


def _unpack_registers(data: bytes, start_address: int, quantity: int) -> dict:
    values = {}
    for i in range(quantity):
        off = i * 2
        if off + 2 <= len(data):
            values[start_address + i] = struct.unpack_from(">H", data, off)[0]
    return values


def parse_request_pdu(function_code: int, data: bytes) -> dict:
    """Parse a request PDU body (function code byte excluded)."""
    if function_code in (1, 2, 3, 4):
        if len(data) != 4:
            raise ModbusError("bad read request length")
        address, quantity = struct.unpack(">HH", data)
        return {"address": address, "quantity": quantity}
    if function_code == 5:
        if len(data) != 4:
            raise ModbusError("bad write-single-coil request length")
        address, raw = struct.unpack(">HH", data)
        return {"address": address, "value": bool(raw == 0xFF00), "raw": raw}
    if function_code == 6:
        if len(data) != 4:
            raise ModbusError("bad write-single-register request length")
        address, value = struct.unpack(">HH", data)
        return {"address": address, "value": value}
    if function_code in (15, 16):
        if len(data) < 5:
            raise ModbusError("bad write-multiple request length")
        address, quantity, byte_count = struct.unpack_from(">HHB", data)
        payload = data[5:]
        if len(payload) != byte_count:
            raise ModbusError("write-multiple byte count mismatch")
        if function_code == 15:
            values = _unpack_bits(payload, address, quantity)
        else:
            if byte_count != quantity * 2:
                raise ModbusError("register byte count mismatch")
            values = _unpack_registers(payload, address, quantity)
        return {"address": address, "quantity": quantity, "values": values}
    if function_code == 23:
        if len(data) < 9:
            raise ModbusError("bad read/write-multiple request length")
        (read_addr, read_qty, write_addr, write_qty,
         byte_count) = struct.unpack_from(">HHHHB", data)
        payload = data[9:]
        if len(payload) != byte_count or byte_count != write_qty * 2:
            raise ModbusError("read/write-multiple byte count mismatch")
        return {
            "read_address": read_addr,
            "read_quantity": read_qty,
            "write_address": write_addr,
            "write_quantity": write_qty,
            "values": _unpack_registers(payload, write_addr, write_qty),
        }
    raise ModbusError(f"unsupported function code {function_code}")


def parse_response_pdu(function_code: int, data: bytes,
                       request: Optional[dict] = None) -> dict:
    """Parse a response PDU body. `request` is the parsed request PDU,
    used to map read values onto absolute addresses."""
    if function_code in (1, 2):
        if len(data) < 1:
            raise ModbusError("bad read-bits response")
        byte_count = data[0]
        payload = data[1:]
        if len(payload) != byte_count:
            raise ModbusError("read-bits byte count mismatch")
        address = request["address"] if request else 0
        quantity = request["quantity"] if request else byte_count * 8
        return {"values": _unpack_bits(payload, address, quantity)}
    if function_code in (3, 4):
        if len(data) < 1:
            raise ModbusError("bad read-registers response")
        byte_count = data[0]
        payload = data[1:]
        if len(payload) != byte_count or byte_count % 2:
            raise ModbusError("read-registers byte count mismatch")
        address = request["address"] if request else 0
        quantity = byte_count // 2
        return {"values": _unpack_registers(payload, address, quantity)}
    if function_code == 5:
        if len(data) != 4:
            raise ModbusError("bad write-single-coil response length")
        address, raw = struct.unpack(">HH", data)
        return {"address": address, "value": bool(raw == 0xFF00), "raw": raw}
    if function_code == 6:
        if len(data) != 4:
            raise ModbusError("bad write-single-register response length")
        address, value = struct.unpack(">HH", data)
        return {"address": address, "value": value}
    if function_code in (15, 16):
        if len(data) != 4:
            raise ModbusError("bad write-multiple response length")
        address, quantity = struct.unpack(">HH", data)
        return {"address": address, "quantity": quantity}
    if function_code == 23:
        if len(data) < 1:
            raise ModbusError("bad read/write-multiple response")
        byte_count = data[0]
        payload = data[1:]
        if len(payload) != byte_count or byte_count % 2:
            raise ModbusError("read/write-multiple response byte count mismatch")
        address = request["read_address"] if request else 0
        return {"values": _unpack_registers(payload, address, byte_count // 2)}
    raise ModbusError(f"unsupported function code {function_code}")
