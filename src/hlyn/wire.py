"""The gate's PROXY v2 header (HAProxy's proxy-protocol.txt, section 2.2).

The one piece of wire format the gate and the proxy share: the gate writes
it as the first bytes of each connection it opens to the proxy, naming what
the agent dialled (DESIGN-host-allowlisting.md 5.3, 5.5); the proxy reads it
(`proxy.unheader`). Kept apart from `proxy.py` so the gate, which starts per
run, doesn't have to import the proxy's asyncio server to write it.
"""

from __future__ import annotations

import ipaddress
import struct

__all__ = ["SIGNATURE", "header"]

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def header(
    address: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None, port: int | None = None
) -> bytes:
    """The PROXY v2 header naming what the agent dialled, or "unknown".

    Written by the gate as the first bytes of its connection to the proxy.
    With no address it is a LOCAL header, which the proxy reads as "the
    destination is unknown". The source fields are zero: the proxy has no use
    for the agent's own address, and the gate has none to give.
    """
    if address is None:
        return SIGNATURE + bytes((0x20, 0x00)) + struct.pack("!H", 0)
    ip = ipaddress.ip_address(address)
    if port is None or not 0 <= port < 65536:
        raise ValueError(f"a PROXY header needs a port 0-65535, got {port!r}")
    if ip.version == 4:
        body = bytes(4) + ip.packed + struct.pack("!HH", 0, port)
        return SIGNATURE + bytes((0x21, 0x11)) + struct.pack("!H", len(body)) + body
    body = bytes(16) + ip.packed + struct.pack("!HH", 0, port)
    return SIGNATURE + bytes((0x21, 0x21)) + struct.pack("!H", len(body)) + body
