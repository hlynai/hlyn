# SPDX-License-Identifier: Apache-2.0
"""Unix datagram sockets while the network is limited (residual 3, closed 2026-09-29).

A datagram socket can name where each message goes in sendmsg()'s msg_name,
inside a struct seccomp can't read, and nothing unprivileged checks that name
before Landlock ABI 9 (Linux 7.1). Measured on 6.12 before this fix: under
`net=False` and `[443]` the gate refused connect() and sendto() to a socket
outside the write grants, and sendmsg(), a datagram socketpair's end and
AF_UNIX SOCK_RAW (which the kernel makes SOCK_DGRAM) all delivered anyway.

So while the gate checks unix sockets on such a kernel, only stream and
seqpacket unix sockets can be made (seccomp.UNIX_KINDS). From ABI 9 the kernel
checks each send's path and datagram sockets are left alone; with the whole
network open nothing changes. Each test prints what the confined program saw
and what a datagram listener outside every grant received.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile

import pytest
from conftest import SRC, boot, enforces, jail

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Landlock and the gate are Linux's"),
    pytest.mark.skipif(sys.platform == "linux" and not enforces(), reason="this kernel cannot seal"),
]


def _refusing() -> bool:
    """Whether this machine refuses unix datagram sockets while the network is
    limited: a kernel before Landlock ABI 9 with a gate to check unix sockets."""
    from hlyn.core import landlock, notify

    return landlock.abi() < 9 and notify.ready()


REFUSING = _refusing()

# The confined program. __OUTSIDE__ is a datagram socket outside every grant;
# __INSIDE__ a datagram socket and __SEQ__ a seqpacket listener in the write grant.
AGENT = """
import ctypes, errno, os, platform, socket
def attempt(name, fn):
    try:
        got = fn()
        print(name + ":", "OK" if got is None else got, flush=True)
    except OSError as exc:
        print(name + ":", errno.errorcode.get(exc.errno, exc.errno), flush=True)
libc = ctypes.CDLL(None, use_errno=True)
PAIR = {"x86_64": 53, "aarch64": 199}[platform.machine()]
def raw_pair(domain, kind):
    fds = (ctypes.c_int * 2)()
    args = [ctypes.c_long(domain), ctypes.c_long(kind), ctypes.c_long(0)]
    if libc.syscall(ctypes.c_long(PAIR), *args, fds) < 0:
        raise OSError(ctypes.get_errno(), "socketpair")
    os.close(fds[0]); os.close(fds[1])
def made(kind):
    socket.socket(socket.AF_UNIX, kind).close()
def named(sock, text):
    sock.sendmsg([text.encode()], [], 0, __OUTSIDE__)
def dgram_send():
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        named(s, "sendmsg")
def raw_send():
    with socket.socket(socket.AF_UNIX, socket.SOCK_RAW) as s:
        named(s, "raw")
def pair_send():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    named(a, "socketpair")
def seqpacket_pair():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    named(a, "seqpacket")  # the kernel ignores the name: it goes to b
    return b.recv(32).decode()
def stream_pair():
    a, b = socket.socketpair()
    a.sendall(b"stream")
    return b.recv(32).decode()
def seqpacket_granted():
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.connect(__SEQ__)
        return s.recv(32).decode()
def dgram_granted():
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(__INSIDE__)
        s.send(b"granted")
attempt("socket dgram", lambda: made(socket.SOCK_DGRAM))
attempt("socket dgram flags", lambda: made(socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK))
attempt("socket raw", lambda: made(socket.SOCK_RAW))
attempt("socketpair dgram", lambda: raw_pair(socket.AF_UNIX, socket.SOCK_DGRAM))
attempt("socketpair raw", lambda: raw_pair(socket.AF_UNIX, socket.SOCK_RAW))
attempt("socketpair high bits", lambda: raw_pair((1 << 32) | socket.AF_UNIX, socket.SOCK_DGRAM))
attempt("sendmsg outside", dgram_send)
attempt("raw sendmsg outside", raw_send)
attempt("socketpair sendmsg outside", pair_send)
attempt("seqpacket pair", seqpacket_pair)
attempt("stream pair", stream_pair)
attempt("seqpacket granted", seqpacket_granted)
attempt("dgram granted", dgram_granted)
"""


class Place:
    """A datagram socket outside every grant, and a write-granted folder
    holding a datagram socket and a seqpacket listener."""

    def __init__(self) -> None:
        self.box = tempfile.mkdtemp(prefix="hlyn-dg-")
        self.other = tempfile.mkdtemp(prefix="hlyn-dg-other-")
        self.outside = self._dgram(f"{self.other}/log.sock")
        self.inside = self._dgram(f"{self.box}/app.sock")
        self.seq = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.seq.bind(f"{self.box}/seq.sock")
        self.seq.listen(8)
        self.seq.settimeout(10)
        self.script = f"{self.box}/agent.py"
        self.code = (AGENT.replace("__OUTSIDE__", repr(f"{self.other}/log.sock"))
                     .replace("__INSIDE__", repr(f"{self.box}/app.sock"))
                     .replace("__SEQ__", repr(f"{self.box}/seq.sock")))
        with open(self.script, "w") as fh:
            fh.write(self.code)
        import threading

        def serve() -> None:
            try:
                conn, _ = self.seq.accept()
                conn.send(b"seq")
                conn.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()

    @staticmethod
    def _dgram(path: str) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(path)
        sock.setblocking(False)
        return sock

    @staticmethod
    def heard(sock: socket.socket) -> list[str]:
        out = []
        while True:
            try:
                out.append(sock.recv(64).decode())
            except OSError:
                return out

    def report(self, out: str) -> tuple[dict[str, str], list[str], list[str]]:
        got = dict(line.split(": ", 1) for line in out.splitlines()
                   if ": " in line and not line.startswith(" "))
        outside, inside = self.heard(self.outside), self.heard(self.inside)
        print("agent saw:", got)
        print("the datagram socket outside every grant received:", outside)
        print("the datagram socket in the write grant received:", inside)
        return got, outside, inside


@pytest.fixture
def place():
    served = Place()
    yield served
    for sock in (served.outside, served.inside, served.seq):
        sock.close()


DATAGRAM = ("socket dgram", "socket dgram flags", "socket raw", "socketpair dgram", "socketpair raw",
            "socketpair high bits")
SENDS = ("sendmsg outside", "raw sendmsg outside", "socketpair sendmsg outside")


def limited(got: dict[str, str], outside: list[str], inside: list[str]) -> None:
    """What a limited network allows: nothing reaches the socket outside the
    grants; stream and seqpacket sockets work, the name on a seqpacket send
    ignored; datagram sockets refused before ABI 9, checked by path from it."""
    assert outside == [], "a datagram reached a socket outside every grant"
    assert got.get("seqpacket pair") == "seqpacket", got
    assert got.get("stream pair") == "stream", got
    assert got.get("seqpacket granted") == "seq", got
    if REFUSING:
        for name in (*DATAGRAM, *SENDS, "dgram granted"):
            assert got.get(name) == "EPERM", (name, got)
        assert inside == []
    else:  # ABI 9: made freely, each send checked by Landlock against the grants
        for name in DATAGRAM:
            assert got.get(name) == "OK", (name, got)
        for name in SENDS:
            assert got.get(name) == "EACCES", (name, got)
        assert got.get("dgram granted") == "OK" and inside == ["granted"], got


MODES = {"off": False, "ports": [443], "hosts": ["example.com"]}


@pytest.mark.parametrize("mode", MODES)
def test_hlyn_run_fn(place, mode):
    done = boot(f"""
import hlyn
def fn():
    exec(compile({place.code!r}, "agent", "exec"), {{}})
hlyn.run(fn, read=[{place.box!r}], write=[{place.box!r}], net={MODES[mode]!r}, log=False)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    limited(*place.report(done.stdout))


def test_an_open_network_leaves_datagram_sockets_alone(place):
    done = boot(f"""
import hlyn
def fn():
    exec(compile({place.code!r}, "agent", "exec"), {{}})
hlyn.run(fn, read=[{place.box!r}], write=[{place.box!r}], net=True, log=False)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    got, outside, inside = place.report(done.stdout)
    for name in (*DATAGRAM, *SENDS, "dgram granted"):
        assert got.get(name) == "OK", (name, got)
    assert sorted(outside) == ["raw", "sendmsg", "socketpair"]
    assert inside == ["granted"]


@pytest.mark.parametrize("mode", ["off", "ports"])
def test_hlyn_run_and_its_report(place, mode):
    cmd = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--read", place.box, "--write", place.box,
           *(["--net", "443"] if mode == "ports" else []), "--", sys.executable, place.script]
    done = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC),
                          timeout=120, check=False)
    print(done.stdout, done.stderr, sep="\n")
    limited(*place.report(done.stdout))
    if REFUSING:
        # The report says what was refused and names the flag that allows it.
        assert "a unix datagram socket (system log, sd_notify)" in done.stderr
        assert "--net-any" in done.stderr


@pytest.mark.parametrize("mode", ["off", "hosts"])
def test_hlyn_on(place, mode):
    done = boot(f"""
import hlyn
hlyn.on(read=[{place.box!r}], write=[{place.box!r}], net={MODES[mode]!r}, log=False)
exec(compile({place.code!r}, "agent", "exec"), {{}})
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    limited(*place.report(done.stdout))


@pytest.mark.skipif(not REFUSING, reason="from Landlock ABI 9 an open datagram socket is checked by path")
def test_hlyn_on_refuses_to_seal_while_a_datagram_socket_is_open(place):
    """A socket opened before sealing would keep the reach new ones are
    refused. The refusal names the descriptor and the fix; once it is closed
    the seal goes ahead."""
    done = boot(f"""
import logging.handlers, socket, hlyn
from hlyn.error import Unsupported
log = logging.handlers.SysLogHandler(address={place.outside.getsockname()!r})
print("syslog handler socket:", log.socket.type.name, "fd", log.socket.fileno())
try:
    hlyn.on(write=[{place.box!r}], log=False)
    print("sealed with it open")
except Unsupported as exc:
    print("refused:", exc)
log.close()
hlyn.on(write=[{place.box!r}], log=False)
print("sealed after closing it")
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    print("new datagram socket: OK")
except OSError as exc:
    print("new datagram socket:", exc.errno)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    assert "syslog handler socket: SOCK_DGRAM" in done.stdout
    assert "refused: 1 unix datagram socket(s) are already open (fd " in done.stdout
    assert "handler.close()" in done.stdout and "net=True" in done.stdout
    assert "sealed with it open" not in done.stdout
    assert "sealed after closing it" in done.stdout
    assert "new datagram socket: 1" in done.stdout  # EPERM


# Every unix socket type, straight through the filter with the rule on: only
# stream (1) and seqpacket (5) are made; every other value gets the filter's
# EPERM, not the kernel's ESOCKTNOSUPPORT, with and without the flag bits.
TYPES = """
import ctypes, errno, os, platform, socket
libc = ctypes.CDLL(None, use_errno=True)
NR = {"socket": {"x86_64": 41, "aarch64": 198}, "socketpair": {"x86_64": 53, "aarch64": 199}}
for call in ("socket", "socketpair"):
    nr = NR[call][platform.machine()]
    for flags in (0, socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK):
        seen = {}
        for kind in range(16):
            fds = (ctypes.c_int * 2)()
            args = [ctypes.c_long(socket.AF_UNIX), ctypes.c_long(kind | flags), ctypes.c_long(0)]
            rc = libc.syscall(ctypes.c_long(nr), *args, *([fds] if call == "socketpair" else []))
            if rc < 0:
                seen[kind] = errno.errorcode[ctypes.get_errno()]
            else:
                seen[kind] = "made"
                for fd in ([rc] if call == "socket" else [fds[0], fds[1]]):
                    os.close(fd)
        print(call, "flags" if flags else "plain", seen)
"""


@pytest.mark.parametrize("rule", [True, False], ids=["rule", "no-rule"])
def test_only_stream_and_seqpacket_unix_sockets_are_made(rule):
    done = jail(TYPES, policy="Policy(net=True)",
                seal=f"(lambda policy: seccomp.load(policy, datagrams={rule}))")
    print(done.stdout, done.stderr[-800:])
    lines = [line for line in done.stdout.splitlines() if line.startswith("socket")]
    assert len(lines) == 4, done.stdout
    for line in lines:
        seen = eval(line.split(" ", 2)[2])  # noqa: S307 - this test's own child printed a dict
        assert seen[1] == "made" and seen[5] == "made", line
        if rule:
            assert all(seen[kind] == "EPERM" for kind in range(16) if kind not in (1, 5)), line
        else:  # the kernel's own answers: SOCK_DGRAM and SOCK_RAW (made a datagram socket) exist
            assert seen[2] == "made" and seen[3] == "made", line
