"""Event types produced by decode()."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ConnectionId:
    """Identifies one TCP connection. `index` distinguishes connections
    that reuse the same 4-tuple over time."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    index: int = 0


@dataclass
class Transaction:
    """A Modbus request paired with its response."""
    connection: ConnectionId
    transaction_id: int
    unit_id: int
    function_code: int
    request: dict          # parsed request PDU fields
    response: dict         # parsed response PDU fields (or exception info)
    request_ts: float      # ts of the packet delivering the last request byte
    response_ts: float     # ts of the packet delivering the last response byte
    exception: bool = False
    type: str = "transaction"


@dataclass
class UnansweredRequest:
    connection: ConnectionId
    transaction_id: int
    unit_id: int
    function_code: int
    request: dict
    request_ts: float
    type: str = "unanswered_request"


@dataclass
class OrphanResponse:
    connection: ConnectionId
    transaction_id: int
    unit_id: int
    function_code: int
    response: dict
    response_ts: float
    exception: bool = False
    type: str = "orphan_response"


@dataclass
class MalformedFrame:
    connection: Optional[ConnectionId]
    direction: str          # "request" (client->server) or "response"
    reason: str
    ts: float
    data: bytes = b""
    type: str = "malformed"


@dataclass
class StreamGap:
    connection: ConnectionId
    direction: str          # "request" or "response"
    bytes_lost: int
    ts: float
    type: str = "gap"
