"""Offline Modbus TCP traffic decoder for classic libpcap files.

Public API: decode(path) -> iterator of events.
"""

from .decoder import decode

__all__ = ["decode"]
