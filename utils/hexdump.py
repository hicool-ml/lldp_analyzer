#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure byte-array display utilities.  No network-library dependencies."""

from __future__ import annotations


def strip_ethernet_header(raw: bytes) -> bytes:
    """Return payload after the 14-byte Ethernet header."""
    if len(raw) >= 14:
        return raw[14:]
    return raw


def hexdump(data: bytes, width: int = 16) -> str:
    """Classic hex+ASCII hexdump, Wireshark style.

    Example output for a 32-byte buffer::

        0000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 00 00 00 00  |Hello World!....|
        0010  01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10  |................|
    """
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
        )
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)
