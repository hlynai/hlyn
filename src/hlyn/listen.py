"""Where the proxy listens: 127.0.0.1 and [::1] on one free port.

Apart from `proxy.py` so the caller can bind the proxy's sockets itself and
hand them over when it starts it -- socket activation, as systemd and launchd
do -- without importing the proxy's asyncio server. The port is then known at
once, and a connection made before the proxy is ready waits in the kernel's
backlog instead of failing (DESIGN-host-allowlisting.md 5.8).
"""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
import sys
from collections.abc import Callable

__all__ = ["bind", "interfaces", "taken"]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

BACKLOG = 128


def bind(port: int = 0, busy: Callable[[int], bool] | None = None) -> list[socket.socket]:
    """Listening sockets on `127.0.0.1:port` and `[::1]:port`, the same port.

    Port 0 picks a free one. A port something else already listens on at
    any of this machine's addresses (`busy`, default `taken`) is skipped
    (5.2 step 1: on macOS, `localhost:P` in the profile also matches those
    addresses), and so is one whose `[::1]` side is taken. IPv6 being off is
    not an error.
    """
    check = taken if busy is None else busy
    for _ in range(20):
        first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            first.bind(("127.0.0.1", port))
        except OSError:
            first.close()
            if port:
                raise
            continue
        chosen = first.getsockname()[1]
        bound = [first]
        try:
            second = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            second = None
        if second is not None:
            second.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                second.bind(("::1", chosen))
                bound.append(second)
            except OSError as exc:
                second.close()
                if exc.errno not in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
                    first.close()
                    if port:
                        raise
                    continue
        if check(chosen):
            for sock in bound:
                sock.close()
            if port:
                raise OSError(errno.EADDRINUSE, f"port {port} is in use on another local address")
            continue
        for sock in bound:
            sock.listen(BACKLOG)
        return bound
    raise OSError(errno.EADDRINUSE, "no free port for the proxy after 20 tries")


def taken(port: int, addresses: tuple[IPAddress, ...] | None = None) -> bool:
    """True if anything accepts a connection on `port` at one of this
    machine's non-loopback addresses."""
    if addresses is None:
        try:
            addresses = interfaces()
        except OSError:
            return False
    for address in addresses:
        if address.is_loopback or address.is_link_local:
            continue
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.5)
            if probe.connect_ex((str(address), port)) == 0:
                return True
    return False


def interfaces() -> tuple[IPAddress, ...]:
    """Every address on this machine's network interfaces.

    Read with libc's `getifaddrs(3)`, the standard call `ifconfig` and `ip`
    use; the standard library has no wrapper, and psutil would be hlyn's
    first dependency. libc is taken from this process itself (`dlopen(NULL)`)
    rather than looked up with `ctypes.util.find_library`, which on Linux
    runs a compiler through a temporary file and so fails once the proxy is
    sealed (measured). Raises `OSError` if the call fails; `Proxy` then keeps
    the last set it read rather than forgetting this machine's addresses.
    """
    import ctypes

    class _Ifaddrs(ctypes.Structure):
        pass

    _Ifaddrs._fields_ = [
        ("next", ctypes.POINTER(_Ifaddrs)),
        ("name", ctypes.c_char_p),
        ("flags", ctypes.c_uint),
        ("addr", ctypes.c_void_p),
        ("netmask", ctypes.c_void_p),
        ("dstaddr", ctypes.c_void_p),
        ("data", ctypes.c_void_p),
    ]
    libc = ctypes.CDLL(None, use_errno=True)
    first = ctypes.POINTER(_Ifaddrs)()
    if libc.getifaddrs(ctypes.byref(first)) != 0:
        code = ctypes.get_errno()
        raise OSError(code, f"getifaddrs failed: {os.strerror(code)}")
    found: list[IPAddress] = []
    try:
        node = first
        while node:
            item = node.contents
            if item.addr:
                raw = ctypes.string_at(item.addr, 24)
                family = raw[1] if sys.platform == "darwin" else int.from_bytes(raw[0:2], sys.byteorder)
                if family == socket.AF_INET:
                    found.append(ipaddress.IPv4Address(raw[4:8]))
                elif family == socket.AF_INET6:
                    found.append(ipaddress.IPv6Address(raw[8:24]))
            node = item.next
    finally:
        libc.freeifaddrs(first)
    return tuple(dict.fromkeys(found))
