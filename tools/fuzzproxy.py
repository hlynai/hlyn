# SPDX-License-Identifier: Apache-2.0
"""Coverage-guided fuzzing of the parsers that read untrusted bytes
(DESIGN-host-allowlisting.md section 9, "Fuzzing"; REMAINING part 1 #18).

    python3 tools/fuzzproxy.py TARGET [libFuzzer flags, e.g. -max_total_time=600]

TARGET is one of:
  header   the gate's PROXY v2 header (`proxy.unheader`)
  head     a CONNECT or plain-HTTP request head (`proxy.head`)
  hello    a TLS ClientHello, for its server name (`proxy.hello`)
  sockaddr the address the gate reads from the agent's memory (`notify.sockaddr`)

Each parser has one contract, the one the Hypothesis tests in
tests/test_proxy.py check: it returns a result, returns None ("need more")
only while under its size limit, or raises `proxy.Bad`. Anything else -- any
other exception, a hang, "need more" past the limit, a result that breaks
the target's own rules -- is a crash, and libFuzzer saves the input.

Needs atheris (`pip install atheris`, which builds with clang). The run the
design asks for before each release is ten minutes a target:

    tools/linuxtest.sh --sh 'sh tools/fuzzproxy.sh 600'
"""

from __future__ import annotations

import os
import sys

import atheris

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

with atheris.instrument_imports():
    from hlyn import hosts, proxy
    from hlyn.core import notify


def bounded(parse, data: bytes, cap: int, kind: type) -> object:
    """Call `parse`; allow only a `kind`, "need more" under `cap` bytes, or `Bad`."""
    try:
        found = parse(data)
    except proxy.Bad:
        return None
    if found is None:
        if len(data) >= cap:
            raise AssertionError(f"asked for more after {len(data)} bytes (cap {cap})")
        return None
    assert isinstance(found, kind), (type(found), found)
    return found


def small(data: bytes, step: int) -> tuple[int, bytes]:
    """A limit from the first byte, so the size checks are reached: libFuzzer's
    inputs stay under 4 KiB, well below the real HEAD_MAX and HELLO_MAX."""
    return (1 + data[0] * step, data[1:]) if data else (1, data)


def header(data: bytes) -> None:
    for raw in (data, proxy.SIGNATURE + data):
        found = bounded(proxy.unheader, raw, proxy.HEADER_MAX, tuple)
        if found is not None:
            origin, used = found
            size = int.from_bytes(raw[14:16], "big")
            assert used == 16 + size <= min(len(raw), proxy.HEADER_MAX), (used, raw)
            assert (origin.address is None) == (origin.port is None)
            if origin.port is not None:  # the port the header's bytes hold, for its family
                at = {0x11: 26, 0x21: 50}[raw[13]]
                assert origin.port == int.from_bytes(raw[at:at + 2], "big"), (origin, raw)


def head(data: bytes) -> None:
    limit, data = small(data, 16)
    for raw in (data, b"CONNECT " + data, b"GET http://" + data):
        for cap in (limit, proxy.HEAD_MAX):
            found = bounded(lambda b, cap=cap: proxy.head(b, cap), raw, cap, proxy.Request)
            if found is not None:
                assert 0 < found.port < 65536, found
                # As written (normalised later, by the rules), but never with a
                # space, a line break, a NUL or a byte over 0x7f in it.
                assert found.host and not set(found.host) & set(" \r\n\t\x00"), found
                assert found.host.isascii(), found
                end = raw.find(b"\r\n\r\n")
                assert 0 <= end < cap and found.rest == raw[end + 4:], found


def hello(data: bytes) -> None:
    limit, data = small(data, 16)
    for raw in (data, b"\x16\x03\x01" + data):
        for cap in (limit, proxy.HELLO_MAX):
            most = cap + 5 * (cap // 16384 + 2)  # the limit plus its record headers
            found = bounded(lambda b, cap=cap: proxy.hello(b, cap), raw, most, proxy.Hello)
            if found is not None and found.name is not None:
                assert found.name == hosts.normalize(found.name), found


def sockaddr(data: bytes) -> None:
    import socket

    found = notify.sockaddr(data)  # never raises: None for what it can't read
    if found is None:
        assert len(data) < 2 or len(data) < {socket.AF_INET: 8, socket.AF_INET6: 24}.get(
            int.from_bytes(data[:2], sys.byteorder), 0), data
        return
    assert found.family == int.from_bytes(data[:2], sys.byteorder), found
    # What it read is exactly what the bytes say, field by field.
    if found.family == socket.AF_INET:
        assert (found.ip.packed, found.port) == (data[4:8], int.from_bytes(data[2:4], "big")), found
    elif found.family == socket.AF_INET6:
        assert (found.ip.packed, found.port) == (data[8:24], int.from_bytes(data[2:4], "big")), found
    elif found.family == socket.AF_UNIX:
        body = data[2:]
        if found.abstract is not None:
            assert body[:1] == b"\x00" and found.abstract == body[1:], found
        elif found.path is not None:
            assert os.fsencode(found.path) == body.split(b"\x00", 1)[0] != b"", found
        else:
            assert not body, found
    else:
        assert (found.ip, found.port, found.path, found.abstract) == (None,) * 4, found


TARGETS = {"header": header, "head": head, "hello": hello, "sockaddr": sockaddr}


def seeds(target: str) -> list[bytes]:
    """Well-formed inputs to start from, so the fuzzer mutates real headers,
    requests, hellos and addresses instead of inventing them byte by byte."""
    import contextlib
    import ipaddress
    import socket
    import ssl
    import struct

    from hlyn.wire import header as write

    if target == "header":
        return [write(ipaddress.ip_address("93.184.215.14"), 443),
                write(ipaddress.ip_address("2001:db8::1"), 8443), write()]
    if target == "head":
        return [b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
                b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n",
                b"GET http://a.example/x?y=1 HTTP/1.1\r\nHost: a.example\r\nAccept: */*\r\n\r\n"]
    if target == "hello":
        out = []
        for name in ("api.openai.com", "a.example"):
            context = ssl.create_default_context()
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = context.wrap_bio(incoming, outgoing, server_hostname=name)
            with contextlib.suppress(ssl.SSLWantReadError):  # the hello is written; no answer comes
                tls.do_handshake()
            out.append(outgoing.read())
        return out
    return [struct.pack("=H", socket.AF_INET) + struct.pack("!H", 443) + bytes([93, 184, 215, 14]) + bytes(8),
            struct.pack("=H", socket.AF_INET6) + struct.pack("!HI", 443, 0)
            + ipaddress.ip_address("2001:db8::1").packed + bytes(4),
            struct.pack("=H", socket.AF_UNIX) + b"/run/app/db.sock\x00",
            struct.pack("=H", socket.AF_UNIX) + b"\x00abstract"]


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        print(f"usage: {sys.argv[0]} {{{','.join(TARGETS)}}} [libFuzzer flags]", file=sys.stderr)
        sys.exit(2)
    target = TARGETS[sys.argv[1]]
    corpus = next((item for item in sys.argv[2:] if not item.startswith("-")), None)
    if corpus and os.path.isdir(corpus) and not os.listdir(corpus):
        for number, seed in enumerate(seeds(sys.argv[1])):
            with open(os.path.join(corpus, f"seed-{number}"), "wb") as fh:
                fh.write(seed)
    atheris.Setup([sys.argv[0], *sys.argv[2:]], target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
