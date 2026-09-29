# SPDX-License-Identifier: Apache-2.0
"""The local proxy that makes `net=["api.openai.com"]` mean one host.

DESIGN-host-allowlisting.md 5.5. Standard library only. The rules, the name
grammar and the address classes come from `hosts.py`; this module adds what
reads bytes off a socket and what connects out.

Every connection from the agent ends up here: on macOS because Seatbelt
allows only this port, on Linux because the gate swaps every TCP connect into
a connection to this port and writes a PROXY v2 header first (5.3). The
proxy reads at most three things before it starts forwarding bytes blindly,
and each has its own bounded parser below:

    unheader(data)   the gate's PROXY v2 header (Linux only)
    head(data)       one HTTP request head: a CONNECT line, or a plain-HTTP
                     request with an absolute URI
    hello(data)      a TLS ClientHello, for the server name (SNI)

Each takes the bytes read so far and returns `None` while it needs more, the
parsed result once it has enough, or raises `Bad` with the reason. None of
them ever looks past its own limit, so a slow or endless sender costs a
bounded amount of memory. Nothing tunnelled is ever parsed as HTTP, which
keeps the request-smuggling class out entirely (design section 3).

`Proxy` serves connections; `python -m hlyn.proxy` starts one, seals it
(`hlyn.on(net=True, ...)`: no files, no exec, no secrets) and prints one
JSON line saying where it listens.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import contextvars
import errno
import ipaddress
import os
import socket
import struct
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from . import hosts
from .chain import Upstream, upstream
from .error import Invalid
from .listen import bind, interfaces, taken
from .wire import SIGNATURE, header

__all__ = [
    "Bad",
    "Hello",
    "Limits",
    "Origin",
    "Proxy",
    "Request",
    "Upstream",
    "head",
    "header",
    "hello",
    "unheader",
    "upstream",
]


class Bad(Exception):
    """Bytes from the client that the proxy will not act on. `str()` is why."""


# Before 3.11, asyncio raised its own TimeoutError, not the builtin one.
_TIMEOUT = (TimeoutError, asyncio.TimeoutError)


# ---------------------------------------------------------------------------
# the gate's PROXY v2 header (HAProxy's proxy-protocol.txt, section 2.2)
# ---------------------------------------------------------------------------

# The signature and the writer live in wire.py, shared with the gate.

# The header's own length field allows 64 KiB of extensions. The gate writes
# none, so anything much longer than the IPv6 address block is not the gate.
HEADER_MAX = 16 + 216


@dataclass(frozen=True, slots=True)
class Origin:
    """What the agent dialled, as the gate saw it.

    `address` and `port` are `None` when the gate could not read the address
    (reduced mode, 5.3): the proxy then serves only CONNECT and plain HTTP.
    """

    address: hosts.IPAddress | None = None
    port: int | None = None


def unheader(data: bytes) -> tuple[Origin, int] | None:
    """Parse a PROXY v2 header at the start of `data`.

    Returns `(origin, length)` once the whole header is there, where `length`
    is how many bytes of `data` it took; `None` while more are needed. Raises
    `Bad` on anything else: a different signature, version 1 text, a version
    other than 2, a UDP or unix-socket family, an address block shorter than
    its family needs, or a header over `HEADER_MAX`. Extensions (TLVs) after
    the address block are skipped, not read.
    """
    have = data[: len(SIGNATURE)]
    if SIGNATURE[: len(have)] != have:
        raise Bad("the connection did not start with the gate's PROXY header")
    if len(data) < 16:
        return None
    version, command = data[12] >> 4, data[12] & 0x0F
    if version != 2:
        raise Bad(f"PROXY header version {version}, expected 2")
    if command not in (0, 1):
        raise Bad(f"PROXY header command {command}, expected LOCAL or PROXY")
    family = data[13]
    (size,) = struct.unpack("!H", data[14:16])
    if 16 + size > HEADER_MAX:
        raise Bad(f"PROXY header of {16 + size} bytes, over the {HEADER_MAX}-byte limit")
    if len(data) < 16 + size:
        return None
    block = data[16 : 16 + size]
    if command == 0 or family == 0x00:
        return Origin(), 16 + size
    if family == 0x11:
        if size < 12:
            raise Bad("PROXY header too short for an IPv4 address")
        address: hosts.IPAddress = ipaddress.IPv4Address(block[4:8])
        (port,) = struct.unpack("!H", block[10:12])
    elif family == 0x21:
        if size < 36:
            raise Bad("PROXY header too short for an IPv6 address")
        address = ipaddress.IPv6Address(block[16:32])
        (port,) = struct.unpack("!H", block[34:36])
    else:
        raise Bad(f"PROXY header family {family:#04x}; only TCP over IPv4 or IPv6 is served")
    return Origin(address, port), 16 + size


# The one-byte verdict the proxy sends the gate for a direct connection
# (5.3): 0 when it connected, otherwise the errno it got, which the gate then
# returns from the agent's connect(). Every errno a connect can give fits in
# a byte on Linux and macOS.
OK = 0


def verdict(code: int) -> bytes:
    """The verdict byte for `code` (0 for success, else an errno)."""
    if not 0 <= code < 256:
        code = errno.ECONNREFUSED
    return bytes((code,))


# ---------------------------------------------------------------------------
# one HTTP request head: CONNECT, or plain HTTP with an absolute URI
# ---------------------------------------------------------------------------

HEAD_MAX = 8192

# Most distinct targets `record` mode reports (`hlyn watch`); past this, it
# still lets them through, it only stops listing.
RECORDED = 10000

# RFC 9110 token characters, for methods and header names.
_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
# Header values: visible ASCII, space and tab. Bytes over 0x7f are refused
# rather than guessed at; no header this proxy reads needs them.
_VALUE = frozenset(range(0x20, 0x7F)) | {0x09}
# The request target: visible ASCII only. No spaces, no controls.
_TARGET = frozenset(range(0x21, 0x7F))


@dataclass(frozen=True, slots=True)
class Request:
    """A parsed request head.

    `method` is as sent. `host` is the target host exactly as written
    (brackets removed from an IPv6 literal), `port` the target port. For
    plain HTTP, `path` is the origin-form target (`/v1/x?y`) and `lines` the
    header lines to forward, with the proxy's own headers removed. `rest` is
    whatever the client sent after the head, which belongs to the tunnel or
    the pinned connection.
    """

    method: str
    host: str
    port: int
    path: str = ""
    version: str = "HTTP/1.1"
    lines: tuple[bytes, ...] = ()
    rest: bytes = b""

    @property
    def tunnel(self) -> bool:
        return self.method == "CONNECT"

    def forward(self) -> bytes:
        """The head to send the server, for plain HTTP: origin-form target."""
        first = f"{self.method} {self.path} {self.version}".encode("ascii")
        return b"\r\n".join((first, *self.lines)) + b"\r\n\r\n"


def _authority(text: str, default: int | None) -> tuple[str, int]:
    """Split `host:port` (or `[v6]:port`). Refuses anything that isn't one.

    The host is returned as written; `Proxy` checks it against the grammar
    and the rules. Only the shape is checked here.
    """
    if not text:
        raise Bad("empty host")
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise Bad("unclosed '[' in the host")
        host, rest = text[1:end], text[end + 1 :]
        if not host:
            raise Bad("empty host")
        if rest and not rest.startswith(":"):
            raise Bad("text after ']' that isn't a port")
        port_text = rest[1:] if rest else ""
    else:
        if text.count(":") > 1:
            raise Bad("an IPv6 address must be in brackets")
        host, _, port_text = text.partition(":")
        if not host:
            raise Bad("empty host")
        if _ == ":" and not port_text:
            raise Bad("':' with no port")
    if not port_text:
        if default is None:
            raise Bad("CONNECT needs host:port")
        return host, default
    if not port_text.isdigit() or len(port_text) > 5:
        raise Bad(f"port {port_text!r} is not a number")
    port = int(port_text)
    if not 0 < port < 65536:
        raise Bad(f"port {port} is not 1-65535")
    return host, port


def head(data: bytes, limit: int = HEAD_MAX) -> Request | None:
    """Parse one request head from the start of `data`.

    `None` while the blank line that ends the head hasn't arrived and fewer
    than `limit` bytes have; `Bad` past the limit or on anything malformed.
    Strict on purpose: lines must end in CRLF, header lines can't be folded,
    a bare CR or LF, a NUL, or a byte over 0x7f anywhere is refused, and
    there must be exactly one `Host` header when it matters.

    `CONNECT host:port HTTP/1.x` opens a tunnel. Any other method must use an
    absolute `http://` URI (the form a client sends to a proxy), and its
    `Host` header must name the same host and port. An `https://` URI is
    refused: clients tunnel HTTPS with CONNECT.
    """
    end = data.find(b"\r\n\r\n", 0, limit)
    if end == -1:
        if len(data) >= limit:
            raise Bad(f"request head over {limit} bytes")
        # A bare LF ends a line for lenient parsers, which is exactly the
        # disagreement smuggling exploits. Refuse it as soon as it is seen,
        # and anything that can't be the start of a request line too (a TLS
        # record, say), rather than wait for a blank line that never comes.
        _plain(data, partial=True)
        word = data.split(b" ", 1)[0]
        if not set(word) <= _TOKEN:
            raise Bad("not an HTTP request")
        return None
    raw, rest = data[:end], data[end + 4 :]
    _plain(raw)
    lines = raw.split(b"\r\n")
    first = lines[0].split(b" ")
    if len(first) != 3:
        raise Bad("the request line is not METHOD TARGET VERSION")
    method_b, target_b, version_b = first
    if not method_b or not set(method_b) <= _TOKEN:
        raise Bad("the method is not a token")
    if not target_b or not set(target_b) <= _TARGET:
        raise Bad("the request target has a character that isn't visible ASCII")
    if version_b not in (b"HTTP/1.1", b"HTTP/1.0"):
        raise Bad("only HTTP/1.0 and HTTP/1.1 are served")
    method, target, version = method_b.decode(), target_b.decode(), version_b.decode()

    fields: list[tuple[str, bytes]] = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t"):
            raise Bad("folded header lines are not accepted")
        name, colon, value = line.partition(b":")
        if not colon or not name or not set(name) <= _TOKEN:
            raise Bad("a header line is not NAME: VALUE")
        if not set(value) <= _VALUE:
            raise Bad("a header value has a control character")
        fields.append((name.decode().lower(), line))
    named = [line.partition(b":")[2].strip(b" \t").decode() for key, line in fields if key == "host"]
    if len(named) > 1:
        raise Bad("more than one Host header")

    if method == "CONNECT":
        host, port = _authority(target, None)
        return Request(method, host, port, version=version, rest=rest)

    scheme, sep, after = target.partition("://")
    if not sep:
        raise Bad("a plain-HTTP request to a proxy must use an absolute URI (http://host/...)")
    if scheme.lower() != "http":
        raise Bad(f"{scheme}:// is not served as plain HTTP; tunnel it with CONNECT")
    cut = min((i for i in (after.find("/"), after.find("?")) if i != -1), default=len(after))
    authority, path = after[:cut], after[cut:]
    if "@" in authority:
        raise Bad("user information in the URI")
    if "#" in authority or "#" in path:
        raise Bad("a fragment in the request target")
    host, port = _authority(authority, 80)
    if not path:
        path = "/"
    elif path.startswith("?"):
        path = "/" + path
    if not named:
        raise Bad("no Host header")
    stated, stated_port = _authority(named[0], 80)
    if not _same(stated, host) or stated_port != port:
        raise Bad("the Host header names a different host from the URI")
    # The proxy's own headers stop here: they are addressed to this hop.
    kept = tuple(line for key, line in fields if key not in ("proxy-authorization", "proxy-connection"))
    return Request(method, host, port, path, version, kept, rest)


def _same(one: str, two: str) -> bool:
    """True if two hosts from one request name the same host: equal as IP
    addresses, or equal after `hosts.normalize`. Anything the grammar refuses
    must match exactly; `Proxy` refuses it later anyway."""
    for parse in (ipaddress.ip_address, hosts.normalize):
        try:
            return bool(parse(one) == parse(two))
        except (ValueError, Invalid):
            continue
    return one == two


def _plain(raw: bytes, partial: bool = False) -> None:
    """Refuse a NUL, a bare CR or LF, or a byte over 0x7f in a request head.

    With `partial`, a CR as the very last byte is let through: it may be the
    first half of a CRLF still in flight.
    """
    if b"\x00" in raw:
        raise Bad("a NUL byte in the request head")
    if any(byte > 0x7F for byte in raw):
        raise Bad("a byte over 0x7f in the request head")
    if partial and raw.endswith(b"\r"):
        raw = raw[:-1]
    stripped = raw.replace(b"\r\n", b"")
    if b"\n" in stripped or b"\r" in stripped:
        raise Bad("a bare CR or LF in the request head")


# ---------------------------------------------------------------------------
# the TLS ClientHello, for its server name (RFC 8446 4.1.2, RFC 6066 3)
# ---------------------------------------------------------------------------

# Bytes of handshake messages the proxy buffers looking for one ClientHello.
# A post-quantum ClientHello is about 1.8 KiB; the record layer allows 16 KiB
# per record, and a hello may span records.
HELLO_MAX = 65536

_SNI = 0x0000
_ECH = 0xFE0D  # encrypted_client_hello (RFC 9849)


@dataclass(frozen=True, slots=True)
class Hello:
    """What the ClientHello says: its server name (`None` if it sent none),
    and whether it carries an encrypted inner hello (ECH), whose outer name
    is the only one visible here."""

    name: str | None
    ech: bool = False


class _Reader:
    """Bounds-checked big-endian reads over one buffer. Every overrun is `Bad`."""

    __slots__ = ("at", "data", "end")

    def __init__(self, data: bytes, at: int = 0, end: int | None = None) -> None:
        self.data, self.at = data, at
        self.end = len(data) if end is None else end

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > self.end:
            raise Bad("the ClientHello is truncated or its lengths don't add up")
        out = self.data[self.at : self.at + count]
        self.at += count
        return out

    def number(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def sub(self, width: int) -> _Reader:
        """A reader over the next length-prefixed block, skipping it here."""
        size = self.number(width)
        start = self.at
        self.take(size)
        return _Reader(self.data, start, start + size)

    def left(self) -> int:
        return self.end - self.at


def hello(data: bytes, limit: int = HELLO_MAX) -> Hello | None:
    """Parse the TLS ClientHello at the start of `data`.

    `None` while more bytes are needed; `Bad` if the bytes are not one
    well-formed ClientHello within `limit`. The record layer is unwrapped
    first, since a hello may span records. Duplicate extensions, more than
    one name in the SNI extension, a name type other than host_name, and a
    name the grammar in `hosts.normalize` refuses are all `Bad`: a server
    and this proxy must never be able to disagree about which name was sent.
    """
    # Records: type 22 (handshake), version 3.x, length, fragment.
    body = bytearray()
    at = 0
    need = 4
    while len(body) < need:
        if len(data) - at < 5:
            return _more(data, limit)
        kind, major, size = data[at], data[at + 1], int.from_bytes(data[at + 3 : at + 5], "big")
        if kind != 22:
            raise Bad("a TLS record that isn't a handshake came before the ClientHello")
        if major != 3:
            raise Bad("not a TLS record")
        if size == 0 or size > 16384:
            raise Bad(f"a TLS record of {size} bytes")
        if len(data) - at - 5 < size:
            return _more(data, limit)
        body += data[at + 5 : at + 5 + size]
        at += 5 + size
        if len(body) >= 4:
            if body[0] != 1:
                raise Bad("the first handshake message is not a ClientHello")
            need = 4 + int.from_bytes(body[1:4], "big")
            if need > limit:
                raise Bad(f"a ClientHello of {need} bytes, over the {limit}-byte limit")
    return _hello(bytes(body[4:need]))


def _more(data: bytes, limit: int) -> Hello | None:
    """`None` (read more), unless `limit` bytes (plus record headers) came
    without a whole hello."""
    if len(data) >= limit + 5 * (limit // 16384 + 2):
        raise Bad(f"no complete ClientHello within {limit} bytes")
    return None


def _hello(body: bytes) -> Hello:
    read = _Reader(body)
    read.take(2)  # legacy_version
    read.take(32)  # random
    session = read.sub(1)
    if session.left() > 32:
        raise Bad("a session id over 32 bytes")
    suites = read.sub(2)
    if suites.left() < 2 or suites.left() % 2:
        raise Bad("a malformed cipher suite list")
    if read.sub(1).left() < 1:
        raise Bad("an empty compression method list")
    if read.left() == 0:
        return Hello(None)  # TLS 1.2 without extensions: no name
    extensions = read.sub(2)
    if read.left():
        raise Bad("bytes after the ClientHello's extensions")
    seen: set[int] = set()
    name: str | None = None
    while extensions.left():
        kind = extensions.number(2)
        block = extensions.sub(2)
        if kind in seen:
            raise Bad(f"extension {kind:#06x} appears twice")
        seen.add(kind)
        if kind == _SNI:
            name = _server_name(block)
    return Hello(name, _ECH in seen)


def _server_name(block: _Reader) -> str:
    names = block.sub(2)
    if block.left():
        raise Bad("bytes after the server name list")
    found: list[str] = []
    while names.left():
        kind = names.number(1)
        value = names.sub(2)
        if kind != 0:
            raise Bad(f"server name type {kind}, expected host_name")
        found.append(value.take(value.left()).decode("latin-1"))
    if len(found) != 1:
        raise Bad(f"{len(found)} server names; exactly one is accepted")
    try:
        return hosts.normalize(found[0])
    except Invalid:
        raise Bad("the server name is not a valid host name") from None


# ---------------------------------------------------------------------------
# this machine's own addresses (appendix B's last row)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# chaining through the user's own proxy (5.5, "a corporate proxy")
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# limits and the server
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds on what one client can make the proxy hold (5.5, "Limits").

    Sizes in bytes, times in seconds. `wait` bounds the PROXY header and the
    request head; `peek` is how long to wait for a client's first bytes after
    a tunnel opens before treating it as a server-first protocol; `hello`
    bounds reading the rest of a ClientHello once it has started.
    """

    head: int = HEAD_MAX
    hello: int = HELLO_MAX
    wait: float = 5.0
    peek: float = 1.0
    connect: float = 10.0
    idle: float = 900.0
    total: float = 86400.0
    clients: int = 512


# What a refusal's class looks like in a sentence.
_CLASS = {
    "own-interface": "this machine's own address",
    "cloud-metadata": "a cloud-metadata address",
    "unspecified": "an unspecified address",
}

T = TypeVar("T")
Report = Callable[[dict[str, object]], None]

# The local port the connection being served arrived on; each connection's
# task has its own copy.
_arrived: contextvars.ContextVar[int] = contextvars.ContextVar("arrived", default=0)
Stream = tuple[asyncio.StreamReader, asyncio.StreamWriter]
Dial = Callable[[Sequence[hosts.IPAddress], int], Awaitable[Stream]]
Resolve = Callable[[str, int], Awaitable[Sequence[hosts.IPAddress]]]


class _Refused(Exception):
    """A request the policy refuses: HTTP status, reason text, report event."""

    def __init__(self, status: int, text: str, event: dict[str, object] | None = None) -> None:
        super().__init__(text)
        self.status, self.text, self.event = status, text, event


@dataclass
class Proxy:
    """The allowlisting proxy for one set of `net` rules.

        proxy = Proxy(policy.hosts())
        port = await proxy.listen()
        ...
        await proxy.close()

    `gate=True` expects the Linux gate's PROXY v2 header on every connection
    and closes any without one. `record=True` is `hlyn watch`'s mode, for a
    program running unconfined: every well-formed target is let through
    unchecked, as without hlyn, and reported once as `{"kind": "seen"}`.
    `report` is called with one dict per denial.
    `resolve`, `dial` and `mine` replace name lookup, connecting out and this
    machine's own addresses; tests use them to stand in for the internet.
    """

    rules: Sequence[hosts.Rule]
    gate: bool = False
    upstream: Upstream | None = None
    limits: Limits = field(default_factory=Limits)
    report: Report | None = None
    resolve: Resolve | None = None
    dial: Dial | None = None
    mine: Callable[[], Sequence[hosts.IPAddress]] | None = None
    record: bool = False
    ports: tuple[int, ...] = field(default=(), init=False)
    _recorded: set[str] = field(default_factory=set, init=False, repr=False)
    _servers: dict[int, list[asyncio.Server]] = field(default_factory=dict, init=False, repr=False)
    # Each connection being served, and the port it arrived on.
    _active: dict[asyncio.Task[None], int] = field(default_factory=dict, init=False, repr=False)
    _own: tuple[float, tuple[hosts.IPAddress, ...]] = field(default=(0.0, ()), init=False, repr=False)

    # -- listening ------------------------------------------------------------

    async def listen(self, port: int = 0) -> int:
        """Listen on `127.0.0.1:port` and `[::1]:port`; return the port.

        Port 0 picks a free one. A port something else already listens on at
        any of this machine's addresses is skipped (5.2 step 1: on macOS,
        `localhost:P` in the profile also matches those addresses), and so is
        one whose `[::1]` side is taken. IPv6 being off is not an error.
        """
        return await self.adopt(bind(port, self._taken))

    async def adopt(self, bound: Sequence[socket.socket]) -> int:
        """Serve on sockets already bound and listening, all on one port: the
        caller's own (`bind`), handed over at start (socket activation)."""
        chosen = int(bound[0].getsockname()[1])
        servers = []
        for sock in bound:
            sock.setblocking(False)
            servers.append(await asyncio.start_server(self._handle, sock=sock))
        self._servers[chosen] = servers
        self.ports = (*self.ports, chosen)
        return chosen

    def _taken(self, port: int) -> bool:
        """`listen.taken`, against this proxy's cached view of its addresses."""
        return taken(port, self._addresses())

    def _addresses(self) -> tuple[hosts.IPAddress, ...]:
        """This machine's own addresses, re-read at most every 5 s. If a
        re-read fails, the last set read stays in force."""
        when, known = self._own
        now = time.monotonic()
        if not when or now - when > 5.0:
            with contextlib.suppress(OSError):
                known = tuple(self.mine()) if self.mine else interfaces()
            self._own = (now, known)
        return known

    async def unlisten(self, port: int) -> None:
        """Stop listening on `port` and end the connections that came in on it:
        the run it was opened for is over (5.8)."""
        servers = self._servers.pop(port, [])
        self.ports = tuple(item for item in self.ports if item != port)
        for server in servers:
            server.close()
        ending = [task for task, where in self._active.items() if where == port]
        for task in ending:
            task.cancel()
        await asyncio.gather(*ending, return_exceptions=True)
        for server in servers:
            await server.wait_closed()

    async def close(self) -> None:
        """Stop listening and end every open connection."""
        for port in list(self._servers):
            await self.unlisten(port)
        for task in list(self._active):
            task.cancel()
        await asyncio.gather(*self._active, return_exceptions=True)

    # -- one connection ---------------------------------------------------------

    def _event(self, why: str, target: str, allow: str | None, **more: object) -> dict[str, object]:
        event: dict[str, object] = {"kind": "net", "target": target, "allow": allow, "why": why, **more}
        port = _arrived.get()
        if port:
            # The port a connection came in on names the run it belongs to
            # (5.8), so its denials reach that run's log.
            event["port"] = port
        return event

    def _tell(self, event: dict[str, object] | None) -> None:
        if event is not None and self.report is not None:
            with contextlib.suppress(Exception):
                self.report(event)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        where = writer.get_extra_info("sockname")
        port = int(where[1]) if isinstance(where, tuple) and len(where) >= 2 else 0
        _arrived.set(port)  # this task's own context: see `_event`
        if len(self._active) >= self.limits.clients or task is None:
            limit = self.limits.clients
            self._tell(self._event("busy", "", None,
                                   detail=f"already serving {limit} connection{'s' * (limit != 1)}, "
                                          f"the most it takes at once"))
            writer.close()
            return
        self._active[task] = port
        try:
            await self._serve(reader, writer)
        except (OSError, asyncio.IncompleteReadError, *_TIMEOUT, Bad, asyncio.CancelledError):
            pass
        finally:
            self._active.pop(task, None)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _read(
        self, reader: asyncio.StreamReader, buf: bytes, parse: Callable[[bytes], T | None],
        limit: int, until: float,
    ) -> tuple[T, bytes]:
        """Read into `buf` until `parse(buf)` returns something, before the
        monotonic time `until`. Never asks for more than `limit` bytes in all."""
        while True:
            found = parse(buf)
            if found is not None:
                return found, buf
            left = until - time.monotonic()
            if left <= 0:
                raise asyncio.TimeoutError
            more = await asyncio.wait_for(reader.read(max(1, limit - len(buf))), left)
            if not more:
                raise asyncio.IncompleteReadError(buf, None)
            buf += more

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        buf = b""
        reduced = False
        if self.gate:
            until = time.monotonic() + self.limits.wait
            (origin, used), buf = await self._read(reader, buf, unheader, HEADER_MAX, until)
            buf = buf[used:]
            if origin.address is None:
                reduced = True
            elif not self._ours(origin):
                await self._direct(origin, buf, reader, writer)
                return
        await self._proxied(buf, reader, writer, reduced)

    def _ours(self, origin: Origin) -> bool:
        """True if the gate's header says the agent dialled this proxy."""
        if origin.address is None:
            return False
        address = hosts.unwrap(origin.address)
        return str(address) in ("127.0.0.1", "::1") and origin.port in self.ports

    async def _direct(
        self, origin: Origin, rest: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Mode 3: a program that ignored the proxy dialled an address (Linux)."""
        if origin.address is None or origin.port is None:
            return
        address = hosts.unwrap(origin.address)
        target = _shown(address, origin.port)
        if hosts.match(self.rules, port=origin.port, address=address) is None:
            self._tell(self._event("dns" if origin.port == 53 else "direct", target, _flag(target)))
            writer.write(verdict(errno.EACCES))
            await writer.drain()
            return
        try:
            far_reader, far_writer = await self._dial([address], origin.port)
        except _TIMEOUT:
            writer.write(verdict(errno.ETIMEDOUT))
            await writer.drain()
            return
        except OSError as exc:
            writer.write(verdict(exc.errno or errno.ECONNREFUSED))
            await writer.drain()
            return
        try:
            writer.write(verdict(OK))
            await self._pump(reader, writer, far_reader, far_writer, rest)
        finally:
            far_writer.close()

    async def _proxied(
        self, buf: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, reduced: bool
    ) -> None:
        """Modes 1 and 2: CONNECT, or plain HTTP pinned to its first host."""
        until = time.monotonic() + self.limits.wait
        try:
            request, _ = await self._read(
                reader, buf, lambda data: head(data, self.limits.head), self.limits.head, until
            )
        except (*_TIMEOUT, asyncio.IncompleteReadError):
            if reduced:
                # 5.3: a direct connect from a process whose memory the gate
                # can't read. It was swapped into the proxy; no request came.
                self._tell(self._event("direct", "(unknown address)", None, mode="reduced"))
            raise
        except Bad as exc:
            if reduced:
                # Not a proxy request: a program that connected directly and
                # started talking its own protocol (5.3, reduced mode).
                self._tell(self._event("direct", "(unknown address)", None, mode="reduced"))
                return
            await self._answer(writer, 400, f"hlyn: bad request to the proxy: {exc}")
            return
        try:
            far_reader, far_writer, name, shown = await self._open(request)
        except _Refused as refused:
            self._tell(refused.event)
            await self._answer(writer, refused.status, refused.text)
            return
        try:
            if not request.tunnel:
                far_writer.write(request.forward() + request.rest)
                await self._pump(reader, writer, far_reader, far_writer, b"")
                return
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            first = await self._peek(name, shown, request.rest, reader)
            if first is not None:
                await self._pump(reader, writer, far_reader, far_writer, first)
        finally:
            far_writer.close()

    async def _peek(
        self, name: str | None, target: str, first: bytes, reader: asyncio.StreamReader
    ) -> bytes | None:
        """5.5 step 1.4: check the tunnel's first bytes against the CONNECT
        host `name` (`None` for an address; `target` is how it is shown).
        Returns the bytes to forward first, or `None` to close."""
        if not first:
            try:
                first = await asyncio.wait_for(reader.read(self.limits.hello), self.limits.peek)
            except _TIMEOUT:
                return b""  # a server-first protocol: nothing to check
            if not first:
                return None
        if first[0] != 22 or self.record:
            return first  # not TLS (the host and port are already allowed), or only watching
        until = time.monotonic() + self.limits.wait
        try:
            said, first = await self._read(
                reader, first, lambda data: hello(data, self.limits.hello), self.limits.hello + 1024, until
            )
        except (Bad, *_TIMEOUT, asyncio.IncompleteReadError) as exc:
            self._tell(self._event("sni-mismatch", target, None, detail=f"unreadable ClientHello: {exc}"))
            return None
        if said.name is None and name is None:
            return first  # CONNECT to an address, and no name sent: consistent
        if said.name != name:
            self._tell(self._event(
                "sni-mismatch", target, None,
                detail=f"TLS names {said.name or '(no name)'}" + (" (ECH outer name)" if said.ech else ""),
            ))
            return None
        return first

    async def _open(
        self, request: Request
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str | None, str]:
        """Check the request's target, then connect to a checked address.

        Returns the connection, the target's normalised name (`None` for an
        address) and how the target is shown in reports; or raises
        `_Refused` with the answer for the client.
        """
        port = request.port
        address = _address(request.host)
        name: str | None = None
        if address is None:
            if hosts._loose_ipv4(request.host) is not None:
                raise self._no(request.host, port, "not-listed", known=False)
            try:
                name = hosts.normalize(request.host)
            except Invalid:
                raise self._no(request.host, port, "not-listed", known=False) from None
            rule = hosts.match(self.rules, port=port, name=name)
        else:
            address = hosts.unwrap(address)
            rule = hosts.match(self.rules, port=port, address=address)
        shown = _named(name, port) if address is None else _shown(address, port)
        if self.record:
            if shown not in self._recorded and len(self._recorded) < RECORDED:
                self._recorded.add(shown)
                self._tell({"kind": "seen", "target": shown})
        elif rule is None:
            raise self._no(shown, port, "dns" if port == 53 else "not-listed")

        if address is not None:
            targets: Sequence[hosts.IPAddress] = [address]
        elif name == "localhost":
            targets = [ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv6Address("::1")]
        elif self.upstream is not None and not self.upstream.bypass(name or ""):
            return (*await self._chain(shown, name or "", port), name, shown)
        else:
            targets = await self._lookup(shown, name or "", port)
        try:
            far_reader, far_writer = await self._dial(targets, port)
        except _TIMEOUT:
            raise _Refused(504, f"hlyn: can't connect to {shown}: no answer within "
                                f"{self.limits.connect:g} s") from None
        except OSError as exc:
            status = 504 if exc.errno == errno.ETIMEDOUT else 502
            raise _Refused(status, f"hlyn: can't connect to {shown}: {exc.strerror or exc}") from None
        return far_reader, far_writer, name, shown

    def _no(self, target: str, port: int, why: str, known: bool = True) -> _Refused:
        if not known:
            # 4.6: a name that fails the grammar is shown as this, with no flag.
            return _Refused(
                403,
                "hlyn: (invalid host name) is not in --net: the name isn't one hlyn can check",
                self._event(why, "(invalid host name)", None),
            )
        allow = _flag(target)
        text = f"hlyn: {target} is not in --net" + (f" (allow with {allow})" if allow else "")
        if why == "dns":
            text += "; with --net hosts the proxy resolves names, so programs never need DNS"
        return _Refused(403, text, self._event(why, target, allow))

    async def _lookup(self, shown: str, name: str, port: int) -> list[hosts.IPAddress]:
        """Resolve once and drop every appendix-B address (matching rule 4)."""
        try:
            if self.resolve is not None:
                found = list(await asyncio.wait_for(self.resolve(name, port), self.limits.connect))
            else:
                infos = await asyncio.wait_for(
                    asyncio.get_running_loop().getaddrinfo(
                        name, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
                    ),
                    self.limits.connect,
                )
                found = [ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos]
        except (OSError, *_TIMEOUT, ValueError) as exc:
            raise _Refused(
                502, f"hlyn: can't resolve {shown}: {exc}", self._event("resolve-failed", shown, None)
            ) from None
        found = list(dict.fromkeys(found))
        if self.record:
            return found  # watching an unconfined program: change nothing it does
        mine = self._addresses()
        kept: list[tuple[hosts.IPAddress, str | None]] = []
        dropped: list[tuple[hosts.IPAddress, str | None]] = []
        for address in found:
            why = hosts.classify(address, mine)
            (dropped if why else kept).append((address, why))
        if kept:
            return [address for address, _ in kept]
        if not dropped:
            raise _Refused(502, f"hlyn: {shown} has no address", self._event("resolve-failed", shown, None))
        address, why = dropped[0]
        kind = _CLASS.get(why or "", f"a{'n' if (why or 'x')[0] in 'aeiou' else ''} {why} address")
        allow = _flag(_shown(hosts.unwrap(address), port))
        text = (
            f"hlyn: {name} resolves to {kind} ({address}); allow it by address: {allow}"
        )
        raise _Refused(403, text, self._event("private-address", shown, allow, address=str(address)))

    async def _dial(
        self, targets: Sequence[hosts.IPAddress], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to the first of `targets` that answers (happy eyeballs,
        RFC 8305: the next attempt starts 250 ms after the previous one)."""
        if self.dial is not None:
            return await asyncio.wait_for(self.dial(targets, port), self.limits.connect)

        async def attempt(address: hosts.IPAddress, delay: float) -> Stream:
            await asyncio.sleep(delay)
            return await asyncio.open_connection(str(address), port)

        tasks = [asyncio.ensure_future(attempt(a, 0.25 * i)) for i, a in enumerate(targets)]
        last: OSError = OSError(errno.EHOSTUNREACH, "no address to connect to")
        winner: Stream | None = None
        try:
            for done in asyncio.as_completed(tasks, timeout=self.limits.connect):
                try:
                    winner = await done
                    break
                except OSError as exc:
                    last = exc
        except _TIMEOUT:
            last = OSError(errno.ETIMEDOUT, f"no answer within {self.limits.connect:g} s")
        finally:
            for task in tasks:
                task.cancel()
            for outcome in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(outcome, tuple) and outcome is not winner:
                    outcome[1].close()
        if winner is None:
            raise last
        return winner

    async def _chain(
        self, shown: str, name: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Tunnel through the user's proxy with CONNECT (the name is checked;
        the addresses can't be, since the upstream resolves them)."""
        up = self.upstream
        if up is None:
            raise _Refused(502, "hlyn: no proxy to chain through")
        try:
            far_reader, far_writer = await asyncio.wait_for(
                asyncio.open_connection(up.host, up.port), self.limits.connect
            )
        except (OSError, *_TIMEOUT) as exc:
            raise _Refused(502, f"hlyn: can't reach your proxy {up.host}:{up.port}: {exc}") from None
        ask = f"CONNECT {name}:{port} HTTP/1.1\r\nHost: {name}:{port}\r\n"
        if up.auth:
            ask += f"Proxy-Authorization: Basic {up.auth}\r\n"
        far_writer.write((ask + "\r\n").encode("ascii"))
        try:
            answer = await asyncio.wait_for(far_reader.readuntil(b"\r\n\r\n"), self.limits.connect)
        except (OSError, *_TIMEOUT, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            far_writer.close()
            raise _Refused(502, f"hlyn: your proxy {up.host}:{up.port} gave no answer for {shown}") from None
        status = answer.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or not status[1].startswith(b"2"):
            far_writer.close()
            said = answer.split(b"\r\n", 1)[0].decode("ascii", "replace")
            raise _Refused(502, f"hlyn: your proxy {up.host}:{up.port} refused {shown}: {said}")
        return far_reader, far_writer

    async def _answer(self, writer: asyncio.StreamWriter, status: int, text: str) -> None:
        """An HTTP response whose reason phrase is the whole message (4.5):
        requests and urllib show the reason phrase in their errors."""
        reason = "".join(ch if " " <= ch < "\x7f" else "?" for ch in text)
        body = (reason + "\n").encode("ascii")
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body
        )
        with contextlib.suppress(OSError):
            await writer.drain()

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        far_reader: asyncio.StreamReader,
        far_writer: asyncio.StreamWriter,
        first: bytes,
    ) -> None:
        """Forward bytes both ways, blindly, until both sides end or the
        connection is idle for `limits.idle` or open for `limits.total`."""
        start = last = time.monotonic()

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            nonlocal last
            while True:
                data = await src.read(65536)
                if not data:
                    break
                last = time.monotonic()
                dst.write(data)
                await dst.drain()
            if dst.can_write_eof():
                with contextlib.suppress(OSError):
                    dst.write_eof()

        try:
            if first:
                far_writer.write(first)
                await far_writer.drain()
            pending = {asyncio.ensure_future(pipe(reader, far_writer)),
                       asyncio.ensure_future(pipe(far_reader, writer))}
            try:
                while pending:
                    now = time.monotonic()
                    left = min(last + self.limits.idle, start + self.limits.total) - now
                    if left <= 0:
                        break
                    done, pending = await asyncio.wait(pending, timeout=min(left, 5.0))
                    # A reset on either side ends both: the other side is told
                    # by the close, as it would be without a proxy between.
                    if any(task.exception() is not None for task in done):
                        break
            finally:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            far_writer.close()


def _address(text: str) -> hosts.IPAddress | None:
    """`text` as a strict IP literal (no zone id), or `None`."""
    if "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _shown(address: hosts.IPAddress, port: int) -> str:
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def _named(name: str | None, port: int) -> str:
    return f"{name or '(invalid host name)'}:{port}"


def _flag(target: str) -> str | None:
    """The `--net` flag that would allow `target`, or `None` if it isn't one
    the grammar accepts (then no flag is suggested, per 4.6)."""
    try:
        return hosts.parse(target).flag()
    except Invalid:
        return None


# ---------------------------------------------------------------------------
# python -m hlyn.proxy: the helper process (5.1, 5.2)
# ---------------------------------------------------------------------------

# One event line must fit in one atomic pipe write (POSIX guarantees 512).
_LINE = 512


class Sinks:
    """Where the helper's denials go (design 4.6).

    - `events`: one JSON line per denial on a pipe `hlyn run` reads for its
      report. Non-blocking: a full pipe drops the line.
    - log records (`deny`, the same shape `hlyn.log` writes) on the run's log
      descriptor: the default one given at start, or the one handed over with
      a run's port (`--control`). A log descriptor is often the caller's own
      stderr, whose flags are shared with the caller, so it can't be made
      non-blocking; a writer thread does the writing instead, from a bounded
      queue, and a full queue drops records and says how many.
    - `human`: a line on stderr, for a proxy run by hand.

    Nothing here ever makes the proxy wait.
    """

    QUEUE = 1024

    def __init__(self, log: int | None = None, events: int | None = None, human: bool = False,
                 machine: bool = False) -> None:
        import queue

        self.default = log
        self.logs: dict[int, int] = {}  # port -> the log descriptor of the run it belongs to
        self.seen: dict[int, dict[str, int]] = {}  # per descriptor, for repeat collapsing
        self.events = events
        self.human = human
        self.machine = machine
        self.dropped = 0
        self._queue: queue.Queue[tuple[int, bytes | None]] = queue.Queue(self.QUEUE)
        self._thread: object = None
        if events is not None:
            os.set_blocking(events, False)

    def start(self) -> None:
        """Start the writer. Called after the seal: Landlock refuses to seal a
        process that already has threads."""
        import threading

        thread = threading.Thread(target=self._write, name="hlyn-log", daemon=True)
        thread.start()
        self._thread = thread

    def add(self, port: int, fd: int | None) -> None:
        if fd is not None:
            self.logs[port] = fd

    def remove(self, port: int) -> None:
        """Forget a run's port. Its descriptor is closed by the writer, after
        every record already queued for it, so nothing lands on a reused one."""
        fd = self.logs.pop(port, None)
        if fd is not None:
            self._queue.put((fd, None))

    def __call__(self, event: dict[str, object]) -> None:
        port = event.get("port")
        fd = self.logs.get(port, self.default) if isinstance(port, int) else self.default
        if fd is not None:
            from . import log

            fields = {"what": event.get("kind", "net"), **{k: v for k, v in event.items() if k != "kind"},
                      "by": "hlyn-proxy", "source": "proxy"}
            text = log.line("deny", fields, self.seen.setdefault(fd, {}))
            if text is not None:
                self._put(fd, text)
        if self.events is not None:
            self._event(event)
        if self.human:
            self._say(event)

    def _put(self, fd: int, text: str) -> None:
        import json
        import queue

        try:
            if self.dropped:
                self._queue.put_nowait((fd, (json.dumps({"kind": "dropped", "count": self.dropped,
                                                         "by": "hlyn-proxy"}) + "\n").encode()))
                self.dropped = 0
            self._queue.put_nowait((fd, (text + "\n").encode()))
        except queue.Full:
            self.dropped += 1

    def _write(self) -> None:
        while True:
            fd, data = self._queue.get()
            with contextlib.suppress(OSError):
                if data is None:
                    os.close(fd)
                    continue
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]

    def _event(self, event: dict[str, object]) -> None:
        import json

        if self.events is None:
            return
        line = json.dumps(event, separators=(",", ":"))
        if len(line) >= _LINE:
            # Keep what the report needs; drop the rest, then shorten.
            event = {key: event[key] for key in ("kind", "target", "allow", "why", "port") if key in event}
            line = json.dumps(event, separators=(",", ":"))
        if len(line) >= _LINE:
            event = {**event, "target": str(event.get("target", ""))[:200], "allow": None}
            line = json.dumps(event, separators=(",", ":"))
        # A full pipe drops the event: the proxy never waits on a reader.
        with contextlib.suppress(BlockingIOError, BrokenPipeError):
            os.write(self.events, (line + "\n").encode())

    def _say(self, event: dict[str, object]) -> None:
        import json

        if self.machine:
            print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)
            return
        text = f"hlyn: blocked {event.get('target') or 'a connection'} ({event.get('why')})"
        if event.get("allow"):
            text += f"; allow with {event['allow']}"
        if event.get("detail"):
            text += f": {event['detail']}"
        print(text, file=sys.stderr, flush=True)


def _writer(fd: int | None, machine: bool) -> Report:
    """Events on `fd` as JSON lines, or on stderr for a person (or `machine`)."""
    return Sinks(events=fd, human=fd is None, machine=machine)


def seal() -> str:
    """Confine this helper before it reads a single byte from a client.

    `net=True` so it can resolve and connect; nothing readable beyond the
    runtime and the resolver and CA files that `net` brings (5.1); no write,
    no exec, and an empty environment. A parser bug here then buys an
    attacker network access and nothing else. Returns the level `on` applied.
    """
    from . import jail
    from .policy import Policy

    done = jail.on(Policy(read=(), write=False, exec=False, net=True, env=False, tmp=False, log=False))
    return str(done["level"])


def main(argv: Sequence[str] | None = None) -> int:
    """Start a proxy for `--net` entries, seal it, and serve until stdin ends.

    Prints one line when ready: where it listens and that it is sealed
    (`--json` for a machine-readable line). The caller keeps the other end of
    stdin; when that closes -- the caller exited -- so does the proxy.

    With `--control FD` it listens nowhere at first. Its caller asks it for a
    port per run over that socket instead (`route.Shared`, design 5.8), each
    with that run's log, and closes the port when the run ends.
    """
    import json

    default = Limits()
    parser = argparse.ArgumentParser(
        prog="python -m hlyn.proxy",
        description="hlyn's allowlisting proxy: lets connections through only to the hosts named "
        "with --net. Started by hlyn itself when a policy names hosts.",
    )
    parser.add_argument("--net", action="append", default=[], metavar="HOST",
                        help="a host to allow (api.openai.com, *.example.com, localhost:5432, "
                             "10.0.0.5:5432); repeat for more")
    parser.add_argument("--gate", action="store_true",
                        help="expect the Linux gate's PROXY v2 header on every connection")
    parser.add_argument("--upstream", metavar="URL",
                        help="chain through this http:// proxy (the user's HTTPS_PROXY)")
    parser.add_argument("--skip", metavar="LIST", default="",
                        help="with --upstream: hosts that go direct (the user's NO_PROXY)")
    parser.add_argument("--port", type=int, default=0, help="port to listen on (default: any free one)")
    parser.add_argument("--listen-fd", type=int, action="append", default=[], metavar="FD",
                        help="serve on this listening socket, bound by the caller (socket activation); "
                             "repeat for its [::1] twin")
    parser.add_argument("--log", type=int, metavar="FD",
                        help="write a deny record for each block to this descriptor (hlyn's log)")
    parser.add_argument("--events", type=int, metavar="FD",
                        help="write denial events as JSON lines to this descriptor")
    parser.add_argument("--control", type=int, metavar="FD",
                        help="take requests for per-run ports on this unix datagram socket")
    parser.add_argument("--quiet", action="store_true", help="print nothing for each block")
    parser.add_argument("--connect", type=float, default=default.connect, metavar="SECONDS",
                        help=f"connect timeout (default {default.connect:g})")
    parser.add_argument("--idle", type=float, default=default.idle, metavar="SECONDS",
                        help=f"close a connection idle this long (default {default.idle:g})")
    parser.add_argument("--clients", type=int, default=default.clients, metavar="N",
                        help=f"most connections at once (default {default.clients})")
    parser.add_argument("--stay", action="store_true",
                        help="keep serving when stdin closes (for running it by hand)")
    parser.add_argument("--detach", action="store_true",
                        help="leave the parent's process tree first (how hlyn starts it)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--record", action="store_true",
                        help="let every host through unchecked and report each once (hlyn watch)")
    args = parser.parse_args(argv)

    try:
        if args.record and args.net:
            raise Invalid("--record lets every host through: leave out --net")
        if not args.net and not args.record:
            raise Invalid("name at least one host: --net api.openai.com")
        rules = tuple(hosts.parse(entry) for entry in args.net)
        chain = None
        if args.upstream:
            try:
                chain = upstream({"HTTPS_PROXY": args.upstream, "NO_PROXY": args.skip})
            except Invalid:
                raise Invalid(f"--upstream {args.upstream!r} isn't a proxy hlyn can chain through: "
                              f"give an http:// URL, e.g. --upstream http://proxy.corp:3128") from None
        if args.connect <= 0 or args.idle <= 0 or args.clients <= 0:
            raise Invalid("--connect, --idle and --clients must be above 0")
        if args.control is not None and args.port:
            raise Invalid("--port and --control don't mix: with --control, each run gets its own port")
        if args.listen_fd and (args.port or args.control is not None):
            raise Invalid("--listen-fd is where the proxy listens: leave out --port and --control")
        for fd in args.listen_fd:
            try:
                kind = socket.socket(fileno=fd)
            except OSError:
                raise Invalid(f"--listen-fd {fd}: no such open socket") from None
            try:
                if kind.type != socket.SOCK_STREAM or kind.family not in (socket.AF_INET, socket.AF_INET6):
                    raise Invalid(f"--listen-fd {fd}: not a TCP socket")
            finally:
                kind.detach()
        for name in ("log", "events", "control"):
            fd = getattr(args, name)
            if fd is not None:
                try:
                    os.fstat(fd)
                except OSError:
                    raise Invalid(f"--{name} {fd}: no such open descriptor") from None
        limits = Limits(connect=args.connect, idle=args.idle, clients=args.clients)
    except Invalid as exc:
        print(f"hlyn: {exc}", file=sys.stderr)
        return 2

    if args.detach:
        _detach()
    sinks = Sinks(log=args.log, events=args.events,
                  human=not (args.quiet or args.log is not None or args.events is not None),
                  machine=args.json)
    try:
        return asyncio.run(_main(rules, args, chain, limits, sinks, json.dumps))
    except KeyboardInterrupt:
        return 130


async def _main(
    rules: tuple[hosts.Rule, ...],
    args: argparse.Namespace,
    chain: Upstream | None,
    limits: Limits,
    sinks: Sinks,
    dumps: Callable[[object], str],
) -> int:
    proxy = Proxy(rules, gate=args.gate, upstream=chain, limits=limits, report=sinks, record=args.record)
    port: int | None = None
    if args.listen_fd:
        port = await proxy.adopt([socket.socket(fileno=fd) for fd in args.listen_fd])
    elif args.control is None:
        try:
            port = await proxy.listen(args.port)
        except OSError as exc:
            print(f"hlyn: the proxy can't listen: {exc}. Pick another --port, or leave it out.",
                  file=sys.stderr)
            return 1
    # Sealed after binding, before accepting: nothing a client sends is read
    # by an unconfined process. If the seal fails, the proxy never serves.
    try:
        level = seal()
    except Exception as exc:  # noqa: BLE001 - any failure to seal means never serve
        print(f"hlyn: the proxy could not seal itself, so it won't serve: {exc}", file=sys.stderr)
        await proxy.close()
        return 1
    sinks.start()
    where = [] if port is None else [f"127.0.0.1:{port}"] + (
        [f"[::1]:{port}"] if len(proxy._servers.get(port, ())) > 1 else [])
    # The own-address check must keep working once sealed (appendix B's last
    # row). Read once more now, so a seal that breaks it is seen at start.
    try:
        own: int | None = len(interfaces())
    except OSError as exc:
        own = None
        print(f"hlyn: warning: the proxy can't re-read this machine's addresses once sealed ({exc}); "
              f"it keeps the ones read before sealing.", file=sys.stderr, flush=True)
    # The caller may have stopped listening for this line (a run that was
    # over before the proxy was ready); that must not end the proxy.
    with contextlib.suppress(OSError):
        if args.json:
            print(dumps({"port": port, "listen": where, "pid": os.getpid(), "sealed": level, "own": own,
                         "net": [str(rule) for rule in rules]}), flush=True)
        else:
            at = " and ".join(where) if where else "ports given out per run"
            print(f"hlyn: proxy for {', '.join(str(rule) for rule in rules)} on {at} "
                  f"(pid {os.getpid()}, sealed: {level})", flush=True)

    ended = asyncio.Event()
    watching = None if args.stay else await _watch(ended)
    control = None if args.control is None else _Control(args.control, proxy, sinks, dumps)
    try:
        await ended.wait()
    finally:
        if watching is not None:
            watching.cancel()
        if control is not None:
            control.close()
        await proxy.close()
    return 0


def _detach() -> None:
    """Fork, and let the first process exit at once (the classic daemon
    double fork, with the caller's fork as the first).

    The proxy then belongs to init (launchd on macOS), not to the process
    that started it: nobody else's `waitpid(-1)` or SIGCHLD handler ever sees
    it, and if it dies it is reaped rather than left a zombie (5.2). Done
    first thing, in a fresh single-threaded interpreter, before any socket or
    thread exists. The caller reaps the first process; the proxy's own pid is
    in its ready line.
    """
    if os.fork():
        os._exit(0)


class _Control:
    """Per-run ports, asked for over a unix seqpacket socket (a datagram
    one on macOS; route.start says why) (design 5.8).

    One datagram per request, one per answer, so a descriptor sent with a
    request can never be mistaken for another's:

        {"open": ID} + optional log descriptor  ->  {"open": ID, "port": P}
        {"close": P}                             ->  {"close": P}

    Anything else is answered with {"error": why}. The caller is the process
    that started this proxy; nothing else holds the other end.
    """

    def __init__(self, fd: int, proxy: Proxy, sinks: Sinks, dumps: Callable[[object], str]) -> None:
        self.sock = socket.socket(fileno=fd)
        self.sock.setblocking(False)
        self.proxy, self.sinks, self.dumps = proxy, sinks, dumps
        self.loop = asyncio.get_running_loop()
        self.tasks: set[asyncio.Task[None]] = set()
        self.loop.add_reader(self.sock.fileno(), self._readable)

    def _readable(self) -> None:
        try:
            data, fds, _, _ = socket.recv_fds(self.sock, 4096, 4)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.loop.remove_reader(self.sock.fileno())
            return
        if not data and not fds:
            # Seqpacket: the caller closed its end. Nothing more will come.
            self.loop.remove_reader(self.sock.fileno())
            return
        task = self.loop.create_task(self._answer(data, fds))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _answer(self, data: bytes, fds: list[int]) -> None:
        import json

        reply: dict[str, object]
        try:
            ask = json.loads(data)
            if not isinstance(ask, dict):
                raise ValueError("not an object")
            if "open" in ask and len(fds) <= 1:
                port = await self.proxy.listen()
                self.sinks.add(port, fds.pop() if fds else None)
                reply = {"open": ask["open"], "port": port}
            elif "close" in ask and isinstance(ask["close"], int) and not fds:
                await self.proxy.unlisten(ask["close"])
                self.sinks.remove(ask["close"])
                reply = {"close": ask["close"]}
            else:
                raise ValueError(f"unknown request {data[:80]!r}")
        except (ValueError, OSError) as exc:
            reply = {"error": str(exc)}
        for fd in fds:
            os.close(fd)
        with contextlib.suppress(OSError):
            self.sock.send(self.dumps(reply).encode())

    def close(self) -> None:
        self.loop.remove_reader(self.sock.fileno())
        for task in self.tasks:
            task.cancel()
        self.sock.close()


async def _watch(ended: asyncio.Event) -> asyncio.Task[None] | None:
    """Set `ended` when stdin reaches end-of-file: the caller has gone.
    Returns the task that watches, to be cancelled on the way out."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    try:
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    except (ValueError, OSError):
        # stdin is a regular file or closed: there is no caller to outlive.
        ended.set()
        return None

    async def drain() -> None:
        while await reader.read(4096):
            pass
        ended.set()

    return loop.create_task(drain())


if __name__ == "__main__":
    sys.exit(main())
