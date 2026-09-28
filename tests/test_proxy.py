# SPDX-License-Identifier: Apache-2.0
"""The allowlisting proxy (DESIGN-host-allowlisting.md 5.5).

Matrix rows 9-14 of section 9 against local servers, the gate's PROXY header
and verdict byte, the limits, chaining, the self-sealing helper, and
Hypothesis fuzzing of the three parsers that read untrusted bytes.

"The internet" here is a resolver table and a dialer that maps public-looking
addresses onto local servers, so every test runs offline and the far side
records exactly what reached it. Every test prints what it observed.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

import pytest
from conftest import SRC, enforces
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from hlyn import hosts, proxy
from hlyn.error import Invalid

PUBLIC = "93.184.215.14"  # stands in for a real server; mapped to a local one
OTHER = "151.101.1.1"


def run(coro, limit: float = 30.0):
    return asyncio.run(asyncio.wait_for(coro, limit))


def rules(*entries: str) -> tuple[hosts.Rule, ...]:
    return tuple(hosts.parse(entry) for entry in entries)


class Far:
    """A local server standing in for a destination: records every byte it
    receives, optionally greets first (a server-first protocol), and answers
    each chunk with `reply`."""

    def __init__(self, greet: bytes = b"", reply: bytes = b"") -> None:
        self.greet, self.reply = greet, reply
        self.received = bytearray()
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1") -> Far:
        self._server = await asyncio.start_server(self._serve, host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def _serve(self, reader, writer) -> None:
        self.connections += 1
        if self.greet:
            writer.write(self.greet)
            await writer.drain()
        with contextlib.suppress(OSError):
            while data := await reader.read(65536):
                self.received += data
                if self.reply:
                    writer.write(self.reply)
                    await writer.drain()
        writer.close()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class Net:
    """The fake internet: `names` resolve to addresses; `routes` send an
    address to a local port. Records every address the proxy dialled."""

    def __init__(self, names: dict[str, list[str]], routes: dict[str, int]) -> None:
        self.names, self.routes = names, routes
        self.dialled: list[str] = []
        self.looked: list[str] = []

    async def resolve(self, name: str, port: int):
        self.looked.append(name)
        if name not in self.names:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [ipaddress.ip_address(item) for item in self.names[name]]

    async def dial(self, targets, port: int):
        for target in targets:
            self.dialled.append(str(target))
            local = self.routes.get(str(target))
            if local is not None:
                return await asyncio.open_connection("127.0.0.1", local)
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")


async def start(
    entries: tuple[str, ...], net: Net | None = None, events: list | None = None, **options
) -> proxy.Proxy:
    served = proxy.Proxy(
        rules(*entries),
        report=(events.append if events is not None else None),
        resolve=net.resolve if net else None,
        dial=net.dial if net else None,
        mine=options.pop("mine", lambda: ()),
        **options,
    )
    # Listen as `listen()` does, but check the port against this machine's
    # real addresses: the check dials each one, and a stand-in public
    # address (OWN) would send packets to the internet (tools/capture.sh).
    await served.adopt(proxy.bind(0, lambda port: proxy.taken(port, proxy.interfaces())))
    return served


async def talk(port: int, data: bytes, wait: float = 2.0, host: str = "127.0.0.1") -> bytes:
    """Send `data`, then read until the proxy closes or `wait` passes."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(data)
    await writer.drain()
    got = bytearray()
    end = time.monotonic() + wait
    with contextlib.suppress(asyncio.TimeoutError, OSError):
        while (left := end - time.monotonic()) > 0:
            chunk = await asyncio.wait_for(reader.read(65536), left)
            if not chunk:
                break
            got += chunk
    writer.close()
    return bytes(got)


def arrived(events: list[dict]) -> list[dict]:
    """`events` with the arrival port checked and taken out: every denial
    names the proxy port its connection came in on (design 5.8)."""
    out = []
    for event in events:
        rest = dict(event)
        port = rest.pop("port", None)
        assert isinstance(port, int) and port > 0, f"no arrival port on {event}"
        out.append(rest)
    return out


def status(answer: bytes) -> str:
    return answer.split(b"\r\n", 1)[0].decode("ascii", "replace")


def connect(target: str) -> bytes:
    return f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()


def clienthello(name: str | None) -> bytes:
    """A real ClientHello from this Python's OpenSSL, naming `name`."""
    context = ssl.create_default_context()
    if name is None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=name)
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def forged(names: list[bytes] | None, extra: list[tuple[int, bytes]] = (), split: int = 0) -> bytes:
    """A hand-built ClientHello: SNI entries `names` (None: no SNI extension),
    extra extensions, and the handshake split across records every `split`
    bytes (0: one record)."""
    extensions = b""
    if names is not None:
        entries = b"".join(b"\x00" + struct.pack("!H", len(n)) + n for n in names)
        sni = struct.pack("!H", len(entries)) + entries
        extensions += struct.pack("!HH", 0, len(sni)) + sni
    for kind, body in extra:
        extensions += struct.pack("!HH", kind, len(body)) + body
    body = (
        b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    chunks = [message] if not split else [message[i : i + split] for i in range(0, len(message), split)]
    return b"".join(b"\x16\x03\x01" + struct.pack("!H", len(chunk)) + chunk for chunk in chunks)


# ---------------------------------------------------------------------------
# the parsers, one by one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("address", "port"), [
    ("10.0.0.5", 5432), ("::1", 8443), ("::ffff:127.0.0.1", 9), (None, None),
])
def test_the_gate_header_round_trips(address, port):
    raw = proxy.header(address, port)
    origin, used = proxy.unheader(raw + b"agent bytes")
    print(f"header({address}, {port}) = {raw.hex()} -> {origin}, {used} bytes")
    assert used == len(raw)
    want = None if address is None else ipaddress.ip_address(address)
    assert origin == proxy.Origin(want, port)


def test_the_gate_header_waits_for_every_byte():
    raw = proxy.header("2001:db8::1", 443)
    for cut in range(len(raw)):
        assert proxy.unheader(raw[:cut]) is None, cut
    print(f"every prefix of the {len(raw)}-byte header asks for more")


@pytest.mark.parametrize(("raw", "why"), [
    (b"GET / HTTP/1.1\r\n\r\n", "did not start"),
    (b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", "did not start"),
    (proxy.SIGNATURE + b"\x11\x11\x00\x0c" + bytes(12), "version 1"),
    (proxy.SIGNATURE + b"\x22\x11\x00\x0c" + bytes(12), "command 2"),
    (proxy.SIGNATURE + b"\x21\x12\x00\x0c" + bytes(12), "family 0x12"),
    (proxy.SIGNATURE + b"\x21\x31\x00\xd8" + bytes(216), "family 0x31"),
    (proxy.SIGNATURE + b"\x21\x11\x00\x08" + bytes(8), "too short"),
    (proxy.SIGNATURE + b"\x21\x21\x00\x0c" + bytes(12), "too short"),
    (proxy.SIGNATURE + b"\x21\x11\xff\xff", "over the"),
])
def test_the_gate_header_refuses_anything_else(raw, why):
    with pytest.raises(proxy.Bad) as caught:
        proxy.unheader(raw)
    print(f"{raw[:20]!r}... -> Bad: {caught.value}")
    assert why in str(caught.value)


def test_a_connect_head_parses():
    request = proxy.head(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\nTLS")
    print(request)
    got = (request.method, request.host, request.port, request.rest)
    assert got == ("CONNECT", "api.openai.com", 443, b"TLS")
    assert request.tunnel


def test_a_plain_head_is_rewritten_to_origin_form_without_proxy_headers():
    request = proxy.head(
        b"POST http://Example.com:8080/v1/x?y=1 HTTP/1.1\r\nHost: example.com:8080\r\n"
        b"Proxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\nContent-Length: 2\r\n\r\nhi"
    )
    sent = request.forward()
    print(request, sent, sep="\n")
    assert sent == b"POST /v1/x?y=1 HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 2\r\n\r\n"
    assert request.rest == b"hi"


def test_a_head_waits_for_its_blank_line_and_no_longer_than_its_limit():
    whole = b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n"
    for cut in range(len(whole)):
        assert proxy.head(whole[:cut]) is None, whole[:cut]
    big = b"CONNECT a.example:443 HTTP/1.1\r\nX: " + b"a" * proxy.HEAD_MAX
    with pytest.raises(proxy.Bad) as caught:
        proxy.head(big)
    print(f"every prefix waits; {len(big)} bytes without a blank line -> {caught.value}")


@pytest.mark.parametrize(("raw", "why"), [
    (b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "absolute URI"),
    (b"GET https://a/ HTTP/1.1\r\nHost: a\r\n\r\n", "tunnel it with CONNECT"),
    (b"GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n", "different host"),
    (b"GET http://a/ HTTP/1.1\r\nHost: a:81\r\n\r\n", "different host"),
    (b"GET http://a/ HTTP/1.1\r\n\r\n", "no Host"),
    (b"GET http://a/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "more than one Host"),
    (b"GET http://u@a/ HTTP/1.1\r\nHost: a\r\n\r\n", "user information"),
    (b"CONNECT a HTTP/1.1\r\n\r\n", "host:port"),
    (b"CONNECT a:0 HTTP/1.1\r\n\r\n", "not 1-65535"),
    (b"CONNECT a:99999 HTTP/1.1\r\n\r\n", "not 1-65535"),
    (b"CONNECT a:https HTTP/1.1\r\n\r\n", "not a number"),
    (b"CONNECT ::1:443 HTTP/1.1\r\n\r\n", "brackets"),
    (b"CONNECT a:443 HTTP/2.0\r\n\r\n", "HTTP/1.0 and HTTP/1.1"),
    (b"CONNECT  a:443 HTTP/1.1\r\n\r\n", "METHOD TARGET VERSION"),
    (b"CONNECT a:443 HTTP/1.1\nHost: a\r\n\r\n", "bare CR or LF"),
    (b"CONNECT a:443 HTTP/1.1\r\nX: a\rb\r\n\r\n", "bare CR or LF"),
    (b"CONNECT a\x00:443 HTTP/1.1\r\n\r\n", "NUL"),
    (b"CONNECT a:443 HTTP/1.1\r\nX: \xc3\xa9\r\n\r\n", "over 0x7f"),
    (b"CONNECT a:443 HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", "folded"),
    (b"CONNECT a:443 HTTP/1.1\r\nBad Name: a\r\n\r\n", "NAME: VALUE"),
    (b"CONNECT a:443 HTTP/1.1\r\nX: a\x01\r\n\r\n", "control character"),
])
def test_a_head_is_refused_when_malformed(raw, why):
    with pytest.raises(proxy.Bad) as caught:
        proxy.head(raw)
    print(f"{raw!r} -> Bad: {caught.value}")
    assert why in str(caught.value)


@pytest.mark.parametrize("name", [
    "api.openai.com", "API.OpenAI.com", "a.b.example.com", "xn--bcher-kva.example",
])
def test_the_server_name_is_read_from_a_real_clienthello(name):
    raw = clienthello(name)
    said = proxy.hello(raw)
    print(f"OpenSSL's {len(raw)}-byte ClientHello for {name!r} -> {said}")
    assert said == proxy.Hello(name.lower())


def test_a_clienthello_without_a_name_says_so():
    said = proxy.hello(clienthello(None))
    print(said)
    assert said == proxy.Hello(None)


def test_a_clienthello_waits_for_every_byte_and_spans_records():
    raw = clienthello("api.openai.com")
    for cut in range(len(raw)):
        assert proxy.hello(raw[:cut]) is None, cut
    split = forged([b"api.openai.com"], split=7)
    records = split.count(b"\x16\x03\x01")
    print(f"{len(raw)} prefixes wait; a hello in {records} records -> {proxy.hello(split)}")
    assert proxy.hello(split) == proxy.Hello("api.openai.com")


def test_ech_is_noticed_and_only_the_outer_name_is_read():
    said = proxy.hello(forged([b"public.example"], extra=[(0xFE0D, b"\x00" * 40)]))
    print(said)
    assert said == proxy.Hello("public.example", ech=True)


@pytest.mark.parametrize(("raw", "why"), [
    (forged([b"a.example", b"b.example"]), "exactly one"),
    (forged([]), "exactly one"),
    (forged([b"evil.example\x00.good.example"]), "not a valid host name"),
    (forged([b"b\xc3\xbccher.example"]), "not a valid host name"),
    (forged([b"a_b.example"]), "not a valid host name"),
    (forged([b"a.example"], extra=[(0, b"\x00\x00")]), "twice"),
    (b"\x17\x03\x03\x00\x05hello", "isn't a handshake"),
    (b"\x16\x02\x00\x00\x05hello", "not a TLS record"),
    (b"\x16\x03\x01\x00\x00", "0 bytes"),
    (b"\x16\x03\x01\x40\x01" + bytes(16385), "16385 bytes"),
    (b"\x16\x03\x01\x00\x04\x02\x00\x00\x00", "not a ClientHello"),
    (b"\x16\x03\x01\x00\x04\x01\xff\xff\xff", "over the"),
    (b"\x16\x03\x01\x00\x06\x01\x00\x00\x02\x03\x03", "truncated"),
])
def test_a_clienthello_is_refused_when_malformed(raw, why):
    with pytest.raises(proxy.Bad) as caught:
        proxy.hello(raw)
    print(f"{raw[:24].hex()}... -> Bad: {caught.value}")
    assert why in str(caught.value)


def test_a_server_name_type_other_than_host_name_is_refused():
    entry = b"\x01" + struct.pack("!H", 9) + b"a.example"
    sni = struct.pack("!H", len(entry)) + entry
    raw = forged(None, extra=[(0, sni)])
    with pytest.raises(proxy.Bad) as caught:
        proxy.hello(raw)
    print(caught.value)
    assert "host_name" in str(caught.value)


# ---------------------------------------------------------------------------
# fuzzing (section 9: "the proxy's three parsers are the only code that reads
# untrusted bytes"). Any exception other than Bad, a hang, or an answer of
# "need more" past the limit is a bug.
# ---------------------------------------------------------------------------

FUZZ = settings(max_examples=3000, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _bounded(parse, data: bytes, limit: int):
    try:
        found = parse(data)
    except proxy.Bad:
        return "bad"
    if found is None:
        assert len(data) < limit, f"asked for more after {len(data)} bytes"
        return "more"
    return found


@FUZZ
@given(st.binary(max_size=300))
def test_fuzz_the_gate_header(data):
    _bounded(proxy.unheader, data, proxy.HEADER_MAX)
    _bounded(proxy.unheader, proxy.SIGNATURE + data, proxy.HEADER_MAX)


@FUZZ
@given(st.binary(max_size=600), st.integers(0, 60))
def test_fuzz_the_request_head(data, cut):
    prefix = b"CONNECT a.example:443 HTTP/1.1\r\n"[:cut]
    _bounded(proxy.head, prefix + data, proxy.HEAD_MAX)
    _bounded(proxy.head, b"GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n" + data + b"\r\n\r\n",
             proxy.HEAD_MAX)


@FUZZ
@given(st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x7F), max_size=200))
def test_fuzz_the_request_head_with_ascii_lines(text):
    raw = ("CONNECT " + text + " HTTP/1.1\r\n\r\n").encode()
    found = _bounded(proxy.head, raw, proxy.HEAD_MAX)
    if isinstance(found, proxy.Request):
        assert 0 < found.port < 65536 and found.host and "\r" not in found.host and " " not in found.host


@FUZZ
@given(st.binary(max_size=600))
def test_fuzz_the_clienthello(data):
    _bounded(proxy.hello, data, proxy.HELLO_MAX + 50)
    _bounded(proxy.hello, b"\x16\x03\x01" + data, proxy.HELLO_MAX + 50)


_REAL = clienthello("api.openai.com")


@FUZZ
@given(st.integers(0, len(_REAL) - 1), st.integers(0, 255))
def test_fuzz_a_real_clienthello_with_one_byte_changed(at, value):
    raw = bytearray(_REAL)
    raw[at] = value
    found = _bounded(proxy.hello, bytes(raw), proxy.HELLO_MAX + 50)
    # Whatever a single changed byte does, the name read is either the real
    # one, refused, or a well-formed name -- never something unnormalised.
    if isinstance(found, proxy.Hello) and found.name is not None:
        assert found.name == hosts.normalize(found.name)


@FUZZ
@given(st.lists(st.binary(min_size=0, max_size=70), max_size=3), st.integers(0, 40))
def test_fuzz_forged_server_names(names, split):
    found = _bounded(proxy.hello, forged(names, split=split), proxy.HELLO_MAX + 50)
    if isinstance(found, proxy.Hello):
        assert len(names) == 1 and found.name == hosts.normalize(names[0].decode("latin-1"))


# ---------------------------------------------------------------------------
# row 13: CONNECT to a listed host on a port that isn't listed
# ---------------------------------------------------------------------------


def test_row_13_an_unlisted_port_on_a_listed_host_is_403():
    async def scenario():
        far = await Far().start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        events: list = []
        served = await start(("api.example.com",), net, events)
        answer = await talk(served.ports[0], connect("api.example.com:8443"), wait=1)
        await served.close()
        await far.stop()
        return answer, events, net

    answer, events, net = run(scenario())
    print(status(answer), events, f"dialled={net.dialled} looked={net.looked}", sep="\n")
    assert status(answer) == (
        "HTTP/1.1 403 hlyn: api.example.com:8443 is not in --net (allow with --net api.example.com:8443)"
    )
    assert net.dialled == [] and net.looked == []
    assert arrived(events) == [{"kind": "net", "target": "api.example.com:8443",
                                "allow": "--net api.example.com:8443", "why": "not-listed"}]


def test_a_listed_host_is_tunnelled_and_bytes_flow_both_ways():
    async def scenario():
        far = await Far(reply=b"pong").start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        served = await start(("api.example.com",), net)
        reader, writer = await asyncio.open_connection("127.0.0.1", served.ports[0])
        writer.write(connect("API.Example.COM.:443"))
        line = await reader.readuntil(b"\r\n\r\n")
        writer.write(b"ping")  # not TLS: passes through, the host is allowed
        back = await reader.read(4)
        writer.close()
        await asyncio.sleep(0.1)
        await served.close()
        await far.stop()
        return line, back, bytes(far.received), net

    line, back, received, net = run(scenario())
    print(line, back, received, net.dialled)
    assert line == b"HTTP/1.1 200 Connection established\r\n\r\n"
    assert back == b"pong" and received == b"ping" and net.dialled == [PUBLIC]


def test_the_reason_phrase_reaches_urllib():
    """4.5: 'requests and urllib include the reason phrase in their error'."""
    import threading
    import urllib.request

    box: dict = {}
    ready = threading.Event()

    def serve():
        async def main():
            served = await start(("api.example.com",))
            box["port"] = served.ports[0]
            box["loop"] = asyncio.get_running_loop()
            box["stop"] = asyncio.Event()
            ready.set()
            await box["stop"].wait()
            await served.close()
        asyncio.run(main())

    thread = threading.Thread(target=serve)
    thread.start()
    ready.wait(10)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{box['port']}"})
        )
        with pytest.raises(OSError) as caught:
            opener.open("https://evil.example.net/", timeout=10)
    finally:
        box["loop"].call_soon_threadsafe(box["stop"].set)
        thread.join(10)
    print(f"urllib raised: {caught.value!r}")
    said = "hlyn: evil.example.net:443 is not in --net (allow with --net evil.example.net)"
    assert said in str(caught.value)


# ---------------------------------------------------------------------------
# row 9: addresses written in disguise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [
    "0177.0.0.1:443", "0x7f.1:443", "2130706433:443", "127.1:443", "0x7f000001:443",
])
def test_row_9_a_loose_ipv4_spelling_is_refused(target):
    async def scenario():
        events: list = []
        net = Net({}, {})
        served = await start(("localhost:443", "127.0.0.1:443"), net, events)
        answer = await talk(served.ports[0], connect(target), wait=1)
        await served.close()
        return answer, events, net

    answer, events, net = run(scenario())
    print(target, "->", status(answer), events, net.dialled, net.looked)
    assert status(answer).startswith("HTTP/1.1 403 hlyn: (invalid host name)")
    assert net.dialled == [] and net.looked == []
    assert arrived(events)[0] == {"kind": "net", "target": "(invalid host name)", "allow": None,
                                  "why": "not-listed"}


@pytest.mark.parametrize("spelling", ["[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[0:0:0:0:0:ffff:7f00:1]",
                                      "[64:ff9b::7f00:1]", "[2002:7f00:1::]", "127.0.0.1"])
def test_row_9_a_wrapped_address_is_treated_as_the_address_it_embeds(spelling):
    async def scenario():
        far = await Far(reply=b"ok").start()
        served = await start((f"127.0.0.1:{far.port}",), mine=lambda: ())
        answer = await talk(served.ports[0], connect(f"{spelling}:{far.port}") + b"hi", wait=1)
        await served.close()
        await far.stop()
        return answer, bytes(far.received)

    answer, received = run(scenario())
    print(f"{spelling} -> {status(answer)!r}, the local server got {received!r}")
    assert status(answer) == "HTTP/1.1 200 Connection established" and received == b"hi"


@pytest.mark.parametrize("target", ["[64:ff9b::a9fe:a9fe]:443", "[2002:a9fe:a9fe::]:443",
                                    "[::ffff:169.254.169.254]:443", "169.254.169.254:443"])
def test_row_9_a_wrapped_address_not_listed_is_refused(target):
    async def scenario():
        events: list = []
        net = Net({}, {})
        served = await start(("api.example.com", "10.0.0.0/8:443"), net, events)
        answer = await talk(served.ports[0], connect(target), wait=1)
        await served.close()
        return answer, events, net

    answer, events, net = run(scenario())
    print(target, "->", status(answer), events)
    assert status(answer) == (
        "HTTP/1.1 403 hlyn: 169.254.169.254:443 is not in --net (allow with --net 169.254.169.254)"
    )
    assert net.dialled == []


@pytest.mark.parametrize("target", ["[fe80::1%25en0]:443", "[fe80::1%en0]:443", "a.example%00:443"])
def test_row_9_zone_ids_are_refused(target):
    async def scenario():
        served = await start(("[fe80::1]:443", "a.example"), Net({}, {}))
        answer = await talk(served.ports[0], connect(target), wait=1)
        await served.close()
        return answer

    answer = run(scenario())
    print(target, "->", status(answer))
    assert status(answer).startswith("HTTP/1.1 403 hlyn: (invalid host name)")


# ---------------------------------------------------------------------------
# row 10: wildcards through the proxy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "passes"), [
    ("example.com", False), ("evilexample.com", False), ("example.com.evil.net", False),
    ("a.b.example.com", True), ("A.B.Example.Com.", True),
])
def test_row_10_wildcards(name, passes):
    async def scenario():
        far = await Far().start()
        net = Net({n.lower().rstrip("."): [PUBLIC] for n in (name,)}, {PUBLIC: far.port})
        served = await start(("*.example.com",), net)
        answer = await talk(served.ports[0], connect(f"{name}:443"), wait=0.5)
        await served.close()
        await far.stop()
        return answer, net

    answer, net = run(scenario())
    print(f"*.example.com vs {name!r}: {status(answer)!r}, dialled {net.dialled}")
    if passes:
        assert status(answer) == "HTTP/1.1 200 Connection established" and net.dialled == [PUBLIC]
    else:
        assert status(answer).startswith("HTTP/1.1 403") and net.dialled == [] and net.looked == []


# ---------------------------------------------------------------------------
# row 11: rebinding and private answers
# ---------------------------------------------------------------------------

OWN = "81.2.69.160"  # stands in for a public address on this machine


@pytest.mark.parametrize(("answer_", "kind"), [
    ("127.0.0.1", "a loopback address"),
    ("10.1.2.3", "a private address"),
    ("169.254.169.254", "a link-local address"),
    ("fd00:ec2::254", "a cloud-metadata address"),
    ("168.63.129.16", "a cloud-metadata address"),
    ("100.100.100.200", "a cgnat address"),
    ("::ffff:10.0.0.1", "a private address"),
    ("0.0.0.0", "an unspecified address"),  # noqa: S104 - a resolver answer, not a bind
    (OWN, "this machine's own address"),
])
def test_row_11_a_name_resolving_privately_is_refused(answer_, kind):
    async def scenario():
        events: list = []
        net = Net({"api.example.com": [answer_]}, {})
        served = await start(("api.example.com",), net, events, mine=lambda: (ipaddress.ip_address(OWN),))
        answer = await talk(served.ports[0], connect("api.example.com:443"), wait=1)
        await served.close()
        return answer, events, net

    answer, events, net = run(scenario())
    print(answer_, "->", status(answer), events, sep="\n")
    shown = hosts.unwrap(ipaddress.ip_address(answer_))
    allow = f"--net [{shown}]" if shown.version == 6 else f"--net {shown}"
    assert status(answer) == (
        f"HTTP/1.1 403 hlyn: api.example.com resolves to {kind} ({answer_}); allow it by address: {allow}"
    )
    assert net.dialled == []
    assert events[0]["why"] == "private-address" and events[0]["allow"] == allow


def test_row_11_private_answers_are_dropped_and_only_public_ones_dialled():
    async def scenario():
        far = await Far().start()
        answers = ["10.0.0.1", "169.254.169.254", PUBLIC, "127.0.0.1"]
        net = Net({"api.example.com": answers}, {PUBLIC: far.port})
        served = await start(("api.example.com",), net)
        answer = await talk(served.ports[0], connect("api.example.com:443"), wait=0.5)
        await served.close()
        await far.stop()
        return answer, net

    answer, net = run(scenario())
    print(status(answer), "dialled:", net.dialled)
    assert status(answer) == "HTTP/1.1 200 Connection established" and net.dialled == [PUBLIC]


def test_row_11_each_connection_resolves_once_and_uses_the_address_it_checked():
    """Smokescreen's rule (4.3.6): the second lookup can rebind, but only the
    second connection sees it, and it is checked again."""
    async def scenario():
        far = await Far().start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        served = await start(("api.example.com",), net)
        first = await talk(served.ports[0], connect("api.example.com:443"), wait=0.3)
        net.names["api.example.com"] = ["127.0.0.1"]
        second = await talk(served.ports[0], connect("api.example.com:443"), wait=0.3)
        await served.close()
        await far.stop()
        return first, second, net

    first, second, net = run(scenario())
    print(status(first), status(second), f"looked={net.looked} dialled={net.dialled}", sep="\n")
    assert status(first).endswith("200 Connection established")
    assert status(second).startswith("HTTP/1.1 403 hlyn: api.example.com resolves to a loopback address")
    assert net.looked == ["api.example.com", "api.example.com"] and net.dialled == [PUBLIC]


def test_a_name_that_does_not_resolve_is_502_resolve_failed():
    async def scenario():
        events: list = []
        served = await start(("gone.example.com",), Net({}, {}), events)
        answer = await talk(served.ports[0], connect("gone.example.com:443"), wait=1)
        await served.close()
        return answer, events

    answer, events = run(scenario())
    print(status(answer), events)
    assert status(answer).startswith("HTTP/1.1 502 hlyn: can't resolve gone.example.com:443")
    assert events[0]["why"] == "resolve-failed"


def test_localhost_is_never_looked_up_and_reaches_loopback():
    async def scenario():
        far = await Far().start()
        net = Net({}, {})
        served = await start((f"localhost:{far.port}",))
        answer = await talk(served.ports[0], connect(f"localhost:{far.port}") + b"db", wait=0.5)
        await served.close()
        await far.stop()
        return answer, bytes(far.received), net

    answer, received, net = run(scenario())
    print(status(answer), received, net.looked)
    assert status(answer).endswith("200 Connection established") and received == b"db" and net.looked == []


def test_happy_eyeballs_moves_on_when_the_first_address_refuses():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 on this machine")

    async def scenario():
        try:
            far = await Far().start("::1")
        except OSError:
            pytest.skip("::1 is not available here")
        served = await start((f"localhost:{far.port}",))
        began = time.monotonic()
        answer = await talk(served.ports[0], connect(f"localhost:{far.port}") + b"v6", wait=0.5)
        took = time.monotonic() - began
        await served.close()
        await far.stop()
        return answer, bytes(far.received), took

    answer, received, took = run(scenario())
    print(f"127.0.0.1 refused, ::1 listens: {status(answer)!r}, server got {received!r}, {took:.2f} s")
    assert status(answer).endswith("200 Connection established") and received == b"v6"


def test_a_listed_address_with_nothing_listening_is_502():
    async def scenario():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        served = await start((f"127.0.0.1:{dead}",))
        answer = await talk(served.ports[0], connect(f"127.0.0.1:{dead}"), wait=1)
        await served.close()
        return answer

    answer = run(scenario())
    print(status(answer))
    assert status(answer).startswith("HTTP/1.1 502 hlyn: can't connect to 127.0.0.1:")


# ---------------------------------------------------------------------------
# row 12: the TLS name must be the CONNECT host
# ---------------------------------------------------------------------------


def _tunnel(first: bytes, target: str = "api.example.com:443", far_greet: bytes = b""):
    async def scenario():
        far = await Far(greet=far_greet).start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port, "127.0.0.1": far.port})
        events: list = []
        served = await start(("api.example.com", f"127.0.0.1:{far.port}"), net, events,
                             limits=proxy.Limits(peek=0.3))
        target_ = target.replace("FAR", str(far.port))
        answer = await talk(served.ports[0], connect(target_) + first, wait=1)
        await asyncio.sleep(0.1)
        await served.close()
        await far.stop()
        return answer, bytes(far.received), events

    return run(scenario())


def test_row_12_the_same_name_in_tls_passes_through_untouched():
    hello_ = clienthello("api.example.com")
    answer, received, events = _tunnel(hello_)
    print(status(answer), f"server got {len(received)} bytes", events)
    assert received == hello_ and events == []


@pytest.mark.parametrize(("label", "first", "detail"), [
    ("another name", clienthello("evil.example.net"), "TLS names evil.example.net"),
    ("no name", clienthello(None), "TLS names (no name)"),
    ("ECH, another outer name", forged([b"cloudflare-ech.com"], extra=[(0xFE0D, bytes(40))]),
     "TLS names cloudflare-ech.com (ECH outer name)"),
    ("two names", forged([b"api.example.com", b"evil.example.net"]), "unreadable ClientHello"),
    ("a truncated hello, then silence", clienthello("api.example.com")[:40], "unreadable ClientHello"),
])
def test_row_12_a_different_or_missing_tls_name_closes_the_tunnel(label, first, detail):
    answer, received, events = _tunnel(first)
    print(f"{label}: {status(answer)!r}; server got {received!r}; {events}")
    assert status(answer).endswith("200 Connection established")
    assert answer.endswith(b"\r\n\r\n"), "nothing may come back after the 200"
    assert received == b""
    assert events[0]["why"] == "sni-mismatch" and detail in events[0]["detail"]


def test_row_12_ech_with_the_same_outer_name_passes_as_documented():
    """Residual 2 (section 6): the inner name can't be seen without MITM."""
    first = forged([b"api.example.com"], extra=[(0xFE0D, bytes(40))])
    answer, received, events = _tunnel(first)
    print(status(answer), len(received), events)
    assert received == first and events == []


def test_row_12_an_address_target_with_a_tls_name_is_refused_and_without_one_passes():
    named = clienthello("api.example.com")
    answer, received, events = _tunnel(named, target="127.0.0.1:FAR")
    print("address + SNI:", status(answer), received[:10], events)
    assert received == b"" and events[0]["why"] == "sni-mismatch"
    assert events[0]["target"].startswith("127.0.0.1:")
    bare = clienthello(None)
    answer, received, events = _tunnel(bare, target="127.0.0.1:FAR")
    print("address, no SNI:", status(answer), len(received), events)
    assert received == bare and events == []


def test_row_12_non_tls_bytes_and_server_first_protocols_pass():
    answer, received, events = _tunnel(b"EHLO me\r\n")
    print("client-first plain bytes:", received, events)
    assert received == b"EHLO me\r\n" and events == []
    answer, received, events = _tunnel(b"", far_greet=b"220 smtp ready\r\n")
    print("server-first:", answer.split(b"\r\n\r\n", 1)[1], events)
    assert answer.split(b"\r\n\r\n", 1)[1] == b"220 smtp ready\r\n" and events == []


# ---------------------------------------------------------------------------
# row 14: plain HTTP is pinned to its first host
# ---------------------------------------------------------------------------


def test_row_14_a_second_request_for_another_host_goes_to_the_pinned_host():
    async def scenario():
        pinned = await Far(reply=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").start()
        other = await Far().start()
        net = Net({"api.example.com": [PUBLIC], "evil.example.net": [OTHER]},
                  {PUBLIC: pinned.port, OTHER: other.port})
        served = await start(("api.example.com:80",), net)
        _, writer = await asyncio.open_connection("127.0.0.1", served.ports[0])
        writer.write(b"GET http://api.example.com/one HTTP/1.1\r\nHost: api.example.com\r\n"
                     b"Proxy-Connection: keep-alive\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.write(b"GET http://evil.example.net/two HTTP/1.1\r\nHost: evil.example.net\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        await served.close()
        await pinned.stop()
        await other.stop()
        return bytes(pinned.received), bytes(other.received), other.connections, net

    to_pinned, to_other, other_connections, net = run(scenario())
    print(f"pinned server got:\n{to_pinned.decode()}\nother server got {to_other!r} "
          f"({other_connections} connections); dialled {net.dialled}")
    assert to_pinned.startswith(b"GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
    assert b"evil.example.net/two" in to_pinned
    assert to_other == b"" and other_connections == 0 and net.dialled == [PUBLIC]


def test_row_14_plain_http_to_an_unlisted_host_is_403_and_a_mismatched_host_400():
    async def scenario():
        served = await start(("api.example.com:80",), Net({}, {}))
        port = served.ports[0]
        ask = b"GET http://evil.example.net/ HTTP/1.1\r\nHost: evil.example.net\r\n\r\n"
        unlisted = await talk(port, ask, 1)
        mixed = await talk(port, b"GET http://api.example.com/ HTTP/1.1\r\nHost: evil.example.net\r\n\r\n", 1)
        await served.close()
        return unlisted, mixed

    unlisted, mixed = run(scenario())
    print(status(unlisted), status(mixed), sep="\n")
    assert status(unlisted) == (
        "HTTP/1.1 403 hlyn: evil.example.net:80 is not in --net (allow with --net evil.example.net:80)"
    )
    assert status(mixed) == (
        "HTTP/1.1 400 hlyn: bad request to the proxy: the Host header names a different host from the URI"
    )


def test_tcp_53_is_refused_as_dns():
    async def scenario():
        events: list = []
        served = await start(("api.example.com",), Net({}, {}), events)
        answer = await talk(served.ports[0], connect("1.1.1.1:53"), wait=1)
        await served.close()
        return answer, events

    answer, events = run(scenario())
    print(status(answer), events)
    assert "proxy resolves names" in status(answer) and events[0]["why"] == "dns"


# ---------------------------------------------------------------------------
# the gate's header and verdict (Linux mode, exercised here on any platform)
# ---------------------------------------------------------------------------


def _gate(prefix: bytes, entries=(), wait=1.0, limits=None):
    async def scenario():
        far = await Far(reply=b"db-reply").start()
        events: list = []
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        served = await start(tuple(e.replace("FAR", str(far.port)) for e in entries) or ("api.example.com",),
                             net, events, gate=True, limits=limits or proxy.Limits())
        data = prefix.replace(b"FAR", str(far.port).encode())
        answer = await talk(served.ports[0], data, wait=wait)
        await served.close()
        await far.stop()
        return answer, bytes(far.received), events, far.port, served

    return run(scenario())


def test_gate_mode_closes_a_connection_without_the_header():
    answer, received, _, _, _ = _gate(connect("api.example.com:443"))
    print(f"no header -> answer {answer!r}")
    assert answer == b"" and received == b""


def test_gate_mode_serves_connect_when_the_header_names_the_proxy():
    async def scenario():
        far = await Far().start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        served = await start(("api.example.com",), net, gate=True)
        port = served.ports[0]
        answers = []
        for dialled in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            ask = proxy.header(dialled, port) + connect("api.example.com:443")
            answers.append(await talk(port, ask, 0.5))
        await served.close()
        await far.stop()
        return answers

    for answer in run(scenario()):
        print(status(answer))
        assert status(answer).endswith("200 Connection established")


def test_gate_mode_direct_to_a_listed_address_answers_ok_then_forwards():
    async def scenario():
        far = await Far(reply=b"db-reply").start()
        served = await start((f"localhost:{far.port}",), gate=True)
        reader, writer = await asyncio.open_connection("127.0.0.1", served.ports[0])
        writer.write(proxy.header("127.0.0.1", far.port))
        verdict = await reader.readexactly(1)
        writer.write(b"SELECT 1")
        reply = await reader.read(8)
        writer.close()
        await served.close()
        await far.stop()
        return verdict, reply, bytes(far.received)

    verdict, reply, received = run(scenario())
    print(f"verdict {verdict!r}, reply {reply!r}, server got {received!r}")
    assert verdict == b"\x00" and reply == b"db-reply" and received == b"SELECT 1"


def test_gate_mode_direct_to_an_unlisted_address_answers_eacces():
    answer, received, events, _, _ = _gate(proxy.header(PUBLIC, 443) + b"secret")
    print(f"verdict {answer!r}, server got {received!r}, events {events}")
    assert answer == bytes((errno.EACCES,)) and received == b""
    assert arrived(events) == [{"kind": "net", "target": f"{PUBLIC}:443", "allow": f"--net {PUBLIC}",
                                "why": "direct"}]


def test_gate_mode_direct_to_port_53_is_reported_as_dns():
    answer, _, events, _, _ = _gate(proxy.header("8.8.8.8", 53))
    print(answer, events)
    assert answer == bytes((errno.EACCES,)) and events[0]["why"] == "dns"


def test_gate_mode_direct_to_a_listed_address_with_nothing_listening_answers_econnrefused():
    async def scenario():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        served = await start((f"127.0.0.1:{dead}",), gate=True)
        answer = await talk(served.ports[0], proxy.header("127.0.0.1", dead), 2)
        await served.close()
        return answer

    answer = run(scenario())
    print(f"verdict {answer!r} (ECONNREFUSED is {errno.ECONNREFUSED})")
    assert answer == bytes((errno.ECONNREFUSED,))


def test_gate_mode_direct_uses_the_embedded_address_of_a_mapped_one():
    async def scenario():
        far = await Far().start()
        served = await start((f"127.0.0.1:{far.port}",), gate=True)
        answer = await talk(served.ports[0], proxy.header("::ffff:127.0.0.1", far.port) + b"x", 0.5)
        await served.close()
        await far.stop()
        return answer, bytes(far.received)

    answer, received = run(scenario())
    print(answer, received)
    assert answer == b"\x00" and received == b"x"


def test_gate_mode_unknown_destination_serves_only_proxy_requests():
    """Reduced mode (5.3): CONNECT works; a program that just talks is closed
    and reported as `direct`."""
    answer, received, events, _, _ = _gate(proxy.header() + connect("api.example.com:443"), wait=0.5)
    print("unknown + CONNECT:", status(answer))
    assert status(answer).endswith("200 Connection established")
    answer, received, events, _, _ = _gate(proxy.header(), wait=1.5, limits=proxy.Limits(wait=0.5))
    print("unknown + silence:", answer, events)
    assert answer == b"" and arrived(events) == [{"kind": "net", "target": "(unknown address)", "allow": None,
                                         "why": "direct", "mode": "reduced"}]
    answer, received, events, _, _ = _gate(proxy.header() + b"\x16\x03\x01\x00\x05hello", wait=1)
    print("unknown + raw TLS:", answer, events)
    assert answer == b"" and received == b"" and events[0]["why"] == "direct"


def test_gate_mode_a_forged_header_is_closed_without_an_answer():
    for bad in (b"PROXY TCP4 1.1.1.1 2.2.2.2 1 443\r\n", proxy.SIGNATURE + b"\x21\x12\x00\x0c" + bytes(12)):
        answer, received, _, _, _ = _gate(bad)
        print(bad[:20], "->", answer)
        assert answer == b"" and received == b""


# ---------------------------------------------------------------------------
# limits (5.5, "Limits")
# ---------------------------------------------------------------------------


def test_a_head_over_the_limit_is_400():
    async def scenario():
        served = await start(("api.example.com",), Net({}, {}))
        answer = await talk(served.ports[0], b"CONNECT api.example.com:443 HTTP/1.1\r\nX: " + b"a" * 9000, 2)
        await served.close()
        return answer

    answer = run(scenario())
    print(status(answer))
    assert status(answer) == "HTTP/1.1 400 hlyn: bad request to the proxy: request head over 8192 bytes"


def test_a_slow_head_is_cut_off_at_the_wait_limit():
    async def scenario():
        served = await start(("api.example.com",), Net({}, {}), limits=proxy.Limits(wait=0.5))
        reader, writer = await asyncio.open_connection("127.0.0.1", served.ports[0])
        began = time.monotonic()
        writer.write(b"CONNECT api.exa")
        got = await asyncio.wait_for(reader.read(100), 5)
        took = time.monotonic() - began
        writer.close()
        await served.close()
        return got, took

    got, took = run(scenario())
    print(f"closed after {took:.2f} s with {got!r}")
    assert got == b"" and 0.4 < took < 2.5


def test_connections_over_the_cap_are_closed_and_reported():
    async def scenario():
        events: list = []
        served = await start(("api.example.com",), Net({}, {}), events, limits=proxy.Limits(clients=1))
        _, held = await asyncio.open_connection("127.0.0.1", served.ports[0])
        await asyncio.sleep(0.1)
        second = await talk(served.ports[0], b"CONNECT", 1)
        held.close()
        await served.close()
        return second, events

    second, events = run(scenario())
    print(second, events)
    assert second == b"" and events[0]["why"] == "busy"


def test_an_idle_tunnel_is_closed():
    async def scenario():
        far = await Far().start()
        net = Net({"api.example.com": [PUBLIC]}, {PUBLIC: far.port})
        served = await start(("api.example.com",), net, limits=proxy.Limits(idle=0.5, peek=0.1))
        reader, writer = await asyncio.open_connection("127.0.0.1", served.ports[0])
        writer.write(connect("api.example.com:443"))
        await reader.readuntil(b"\r\n\r\n")
        began = time.monotonic()
        end = await asyncio.wait_for(reader.read(10), 10)
        took = time.monotonic() - began
        writer.close()
        await served.close()
        await far.stop()
        return end, took

    end, took = run(scenario())
    print(f"idle tunnel closed after {took:.2f} s ({end!r})")
    assert end == b"" and took < 7


def test_listen_skips_a_port_that_is_taken_elsewhere_and_refuses_a_fixed_one():
    """5.2 step 1: on macOS `localhost:P` also matches this machine's own
    addresses, so a port something listens on there is skipped. `_taken` is
    what checks that (next test); here it says yes once."""
    async def scenario():
        served = proxy.Proxy(rules("api.example.com"))
        tried: list[int] = []

        def taken(port: int) -> bool:
            tried.append(port)
            return len(tried) == 1

        served._taken = taken  # type: ignore[method-assign]
        chosen = await served.listen()
        await served.close()
        fixed = proxy.Proxy(rules("api.example.com"))
        fixed._taken = lambda port: True  # type: ignore[method-assign]
        with pytest.raises(OSError) as caught:
            await fixed.listen(chosen)
        return tried, chosen, caught.value

    tried, chosen, error = run(scenario())
    print(f"tried {tried}, listening on {chosen}; a fixed taken port -> {error}")
    assert len(tried) == 2 and chosen == tried[1] != tried[0]
    assert "in use on another local address" in str(error)


def test_taken_finds_a_listener_on_an_own_address():
    addresses = [
        a for a in proxy.interfaces() if not a.is_loopback and not a.is_link_local and a.version == 4
    ]
    if not addresses:
        pytest.skip("no non-loopback IPv4 address on this machine")
    with socket.socket() as squatter:
        squatter.bind((str(addresses[0]), 0))
        squatter.listen()
        port = squatter.getsockname()[1]
        served = proxy.Proxy(rules("api.example.com"))
        found = served._taken(port)
        print(f"listener on {addresses[0]}:{port} -> taken={found}")
        assert found
    assert not served._taken(port)


def test_interfaces_lists_this_machines_addresses():
    found = proxy.interfaces()
    print(found)
    assert ipaddress.ip_address("127.0.0.1") in found


# ---------------------------------------------------------------------------
# chaining through the user's own proxy
# ---------------------------------------------------------------------------


class Corporate(Far):
    """A proxy that answers every CONNECT with `answer` and then echoes."""

    def __init__(self, answer: bytes = b"HTTP/1.1 200 OK\r\n\r\n") -> None:
        super().__init__()
        self.answer = answer
        self.heads: list[bytes] = []

    async def _serve(self, reader, writer) -> None:
        self.heads.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(self.answer)
        await writer.drain()
        with contextlib.suppress(OSError):
            while data := await reader.read(65536):
                self.received += data
        writer.close()


def test_chaining_sends_connect_with_credentials_upstream():
    async def scenario():
        corp = await Corporate().start()
        chain = proxy.upstream({"HTTPS_PROXY": f"http://me%40corp:p%3Ass@127.0.0.1:{corp.port}"})
        net = Net({}, {})
        served = await start(("api.example.com",), net, upstream=chain)
        answer = await talk(served.ports[0], connect("api.example.com:443") + b"x", 0.5)
        refused = await talk(served.ports[0], connect("evil.example.net:443"), 0.5)
        await served.close()
        await corp.stop()
        return answer, refused, corp, net

    answer, refused, corp, net = run(scenario())
    print(status(answer), status(refused), corp.heads, net.looked, sep="\n")
    assert status(answer).endswith("200 Connection established")
    assert corp.heads == [b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n"
                          b"Proxy-Authorization: Basic bWVAY29ycDpwOnNz\r\n\r\n"]
    assert status(refused).startswith("HTTP/1.1 403") and net.looked == []


def test_chaining_passes_on_the_upstreams_refusal():
    async def scenario():
        corp = await Corporate(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").start()
        served = await start(("api.example.com",), Net({}, {}),
                             upstream=proxy.Upstream("127.0.0.1", corp.port))
        answer = await talk(served.ports[0], connect("api.example.com:443"), 1)
        await served.close()
        await corp.stop()
        return answer

    answer = run(scenario())
    print(status(answer))
    assert "refused api.example.com:443: HTTP/1.1 407" in status(answer)


def test_no_proxy_entries_go_direct_with_the_address_checks():
    async def scenario():
        corp = await Corporate().start()
        far = await Far().start()
        net = Net({"api.internal.example": [PUBLIC]}, {PUBLIC: far.port})
        chain = proxy.upstream(
            {"HTTPS_PROXY": f"127.0.0.1:{corp.port}", "NO_PROXY": "localhost, .internal.example"}
        )
        served = await start(("api.internal.example",), net, upstream=chain)
        answer = await talk(served.ports[0], connect("api.internal.example:443"), 0.5)
        await served.close()
        await corp.stop()
        await far.stop()
        return answer, corp.heads, net

    answer, heads, net = run(scenario())
    print(status(answer), heads, net.dialled)
    assert status(answer).endswith("200 Connection established") and heads == [] and net.dialled == [PUBLIC]


@pytest.mark.parametrize(("env", "want"), [
    ({}, None),
    ({"https_proxy": "http://p.corp:3128"}, proxy.Upstream("p.corp", 3128)),
    ({"HTTP_PROXY": "p.corp"}, proxy.Upstream("p.corp", 8080)),
    ({"ALL_PROXY": "http://[::1]:9"}, proxy.Upstream("::1", 9)),
    ({"HTTPS_PROXY": "http://a:b@p:1", "no_proxy": "x.com,*"},
     proxy.Upstream("p", 1, "YTpi", ("x.com", "*"))),
])
def test_upstream_reads_the_users_environment(env, want):
    got = proxy.upstream(env)
    print(env, "->", got)
    assert got == want


@pytest.mark.parametrize(("url", "said"), [
    ("socks5://p:1080", "only http:// proxies"), ("https://p:443", "only http:// proxies"),
    ("http://p:99999", "bad port"), ("http://:8080", "no host"),
])
def test_upstream_refuses_what_it_cannot_chain(url, said):
    with pytest.raises(Invalid) as caught:
        proxy.upstream({"HTTPS_PROXY": url})
    print(caught.value)
    assert said in str(caught.value)


@pytest.mark.parametrize(("skip", "host", "bypass"), [
    (("example.com",), "example.com", True), (("example.com",), "a.example.com", True),
    ((".example.com",), "a.example.com", True), (("example.com",), "evilexample.com", False),
    (("example.com",), "example.com.evil.net", False), (("10.0.0.0/8",), "10.1.2.3", True),
    (("*",), "anything", True),
])
def test_no_proxy_matches_label_by_label(skip, host, bypass):
    got = proxy.Upstream("p", 1, skip=skip).bypass(host)
    print(skip, host, got)
    assert got is bypass


# ---------------------------------------------------------------------------
# the helper: python -m hlyn.proxy seals itself before it serves
# ---------------------------------------------------------------------------


def _confined(pid: int) -> str:
    if sys.platform == "darwin":
        import ctypes

        libc = ctypes.CDLL(None)
        return "sandboxed" if libc.sandbox_check(pid, None, 0) == 1 else "not sandboxed"
    with open(f"/proc/{pid}/status") as fh:
        lines = {line.split(":")[0]: line.split(":", 1)[1].strip() for line in fh}
    return f"NoNewPrivs={lines['NoNewPrivs']} Seccomp={lines['Seccomp']}"


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_the_helper_seals_itself_serves_and_exits_with_its_caller():
    async def far_server():
        return await Far(reply=b"pong").start()

    loop = asyncio.new_event_loop()
    far = loop.run_until_complete(far_server())
    env = {**os.environ, "PYTHONPATH": SRC}
    helper = subprocess.Popen(
        [sys.executable, "-m", "hlyn.proxy", "--json", "--net", f"localhost:{far.port}"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd="/",
    )
    try:
        line = helper.stdout.readline()
        if not line:
            helper.wait(10)
            pytest.fail(f"the helper never became ready: {helper.stderr.read().decode()}")
        ready = json.loads(line)
        print("ready:", ready)
        assert isinstance(ready["own"], int) and ready["own"] > 0, "own addresses unreadable once sealed"
        confined = _confined(helper.pid)
        print("confinement:", confined)
        assert confined in ("sandboxed", "NoNewPrivs=1 Seccomp=2")

        async def use():
            return await talk(ready["port"], connect(f"localhost:{far.port}") + b"ping", 0.5), \
                   await talk(ready["port"], connect("evil.example.net:443"), 0.5)

        through, refused = loop.run_until_complete(use())
        print(status(through), status(refused), sep="\n")
        assert status(through).endswith("200 Connection established") and through.endswith(b"pong")
        assert status(refused).startswith("HTTP/1.1 403 hlyn: evil.example.net:443")

        began = time.monotonic()
        helper.stdin.close()
        code = helper.wait(10)
        print(f"stdin closed -> exit {code} after {time.monotonic() - began:.2f} s")
        assert code == 0
        events = helper.stderr.read().decode()
        print("events:", events)
        assert json.loads(events.splitlines()[0])["why"] == "not-listed"
    finally:
        helper.kill()
        helper.wait()
        loop.run_until_complete(far.stop())
        loop.close()


@pytest.mark.parametrize(("args", "said"), [
    ([], "name at least one host"),
    (["--net", "https://api.openai.com"], "Give the host name"),
    (["--net", "a.example", "--upstream", "socks5://p:1"], "give an http:// URL"),
    (["--net", "a.example", "--idle", "0"], "must be above 0"),
])
def test_the_helper_refuses_bad_arguments_before_listening(args, said):
    done = subprocess.run([sys.executable, "-m", "hlyn.proxy", *args], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": SRC}, timeout=30, check=False)
    print(done.returncode, done.stdout, done.stderr)
    assert done.returncode == 2 and said in done.stderr and done.stdout == ""


def test_a_failed_address_reread_keeps_the_last_set():
    calls = []

    def mine():
        calls.append(1)
        if len(calls) > 1:
            raise OSError(errno.EPERM, "getifaddrs refused")
        return (ipaddress.ip_address(OWN),)

    served = proxy.Proxy(rules("api.example.com"), mine=mine)
    first = served._addresses()
    served._own = (time.monotonic() - 10, served._own[1])  # due for a re-read
    second = served._addresses()
    print(f"first read {first}; the re-read failed and kept {second}")
    assert first == second == (ipaddress.ip_address(OWN),) and len(calls) == 2


def test_event_lines_stay_whole_json_under_the_pipe_limit():
    read, write = os.pipe()
    try:
        send = proxy._writer(write, machine=True)
        long = "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + ".example"
        send({"kind": "net", "target": f"{long}:443", "allow": f"--net {long}", "why": "not-listed",
              "detail": "x" * 400})
        send({"kind": "net", "target": "short.example:443", "allow": "--net short.example", "why": "dns"})
        lines = os.read(read, 65536).decode().splitlines()
    finally:
        os.close(read)
        os.close(write)
    for line in lines:
        print(len(line), line[:120])
        assert len(line) < 512
    first, second = (json.loads(line) for line in lines)
    assert first["why"] == "not-listed" and "detail" not in first
    assert second == {"kind": "net", "target": "short.example:443", "allow": "--net short.example",
                      "why": "dns"}


# ---------------------------------------------------------------------------
# record mode: hlyn watch's proxy, for a program running unconfined
# ---------------------------------------------------------------------------


def test_record_mode_lets_every_host_through_and_reports_each_once():
    async def scenario():
        far = await Far(reply=b"pong").start()
        events: list = []
        net = Net({"api.example.com": [PUBLIC], "db.corp": ["10.0.0.5"]},
                  {PUBLIC: far.port, "10.0.0.5": far.port})
        served = await start((), net, events, record=True)
        answers = []
        for target in ("api.example.com:443", "api.example.com:443", "db.corp:5432", "203.0.113.9:8443"):
            answers.append(status(await talk(served.ports[0], connect(target) + b"ping", wait=0.5)))
        await served.close()
        await far.stop()
        return answers, events, net

    answers, events, net = run(scenario())
    print(answers, events, net.dialled, sep="\n")
    # Unconfined, so nothing is refused: not an unlisted host, not a name that
    # resolves privately (a watched program must behave as without hlyn).
    assert answers[:3] == ["HTTP/1.1 200 Connection established"] * 3
    assert "10.0.0.5" in net.dialled
    seen = [event["target"] for event in events if event.get("kind") == "seen"]
    assert seen == ["api.example.com:443", "db.corp:5432", "203.0.113.9:8443"]  # once each


def test_record_mode_still_refuses_a_name_it_cant_parse():
    async def scenario():
        events: list = []
        served = await start((), Net({}, {}), events, record=True)
        answer = await talk(served.ports[0], connect("bad_name!.com:443"), wait=0.5)
        await served.close()
        return answer, events

    answer, events = run(scenario())
    print(status(answer), events)
    assert status(answer).startswith("HTTP/1.1 4")
    assert not [event for event in events if event.get("kind") == "seen"]


def test_record_and_net_do_not_mix():
    done = subprocess.run([sys.executable, "-m", "hlyn.proxy", "--record", "--net", "a.example.com"],
                          capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC), check=False)
    print(done.returncode, done.stderr)
    assert done.returncode == 2 and "--record lets every host through: leave out --net" in done.stderr
