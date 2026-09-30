# SPDX-License-Identifier: Apache-2.0
"""The Linux gate's decisions (DESIGN-host-allowlisting.md 5.3, layer 3).

A child seals itself for hosts and hands its notification descriptor to this
test, which runs the real `guard.Guard` on it. A fake proxy stands in for
hlyn's: it records the PROXY v2 header of every connection the gate opens,
answers the verdict byte for direct ones, and keeps what the agent sent. So
each test shows both sides: what the agent saw, and what reached the proxy.

Matrix rows (section 9): 1 (raw connect to a non-listed IP), 2 (same-port
listener on another address), 3 (the race harness), 22 (resolver, D-Bus and
runtime sockets, by symlink and relative path), 23 (unix datagram to a path),
26 (direct connects: EISCONN, ECONNREFUSED), and reduced mode.
"""

from __future__ import annotations

import collections
import contextlib
import errno
import ipaddress
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time

import pytest
from conftest import ROOT, SRC, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="the gate's notifications are Linux-only"),
    pytest.mark.skipif(sys.platform == "linux" and not enforces(), reason="this kernel cannot seal"),
]

AGENT = textwrap.dedent(f"""
    import ctypes, errno, os, socket, sys
    sys.path.insert(0, {SRC!r})
    from hlyn.policy import Policy
    from hlyn.core import landlock, seccomp
    chan = socket.socket(fileno=int(sys.argv[1]))
    PRELOAD
    policy = Policy(net=NET, write=WRITE, read=READ)
    landlock.load(policy)
    fd = seccomp.load(policy, watch=WATCH, datagrams=DATAGRAMS)
    socket.send_fds(chan, [b"fd"], [fd])
    os.close(fd)
    assert chan.recv(1) == b"k"
    chan.close()
    def attempt(name, fn):
        try:
            got = fn()
            print(name, "=>", "OK" if got is None else got, flush=True)
        except OSError as exc:
            print(name, "=>", errno.errorcode.get(exc.errno, exc.errno), flush=True)
""")


KEEP = 10_000  # connections the test proxy keeps whole


class Events(list):
    """The gate's events: every one counted, the first KEEP kept."""

    total = 0

    def tell(self, event: dict) -> None:
        self.total += 1
        if len(self) < KEEP:
            self.append(event)


class Proxy:
    """A stand-in for hlyn's proxy in gate mode: records headers, answers
    verdicts (`verdict[(address, port)]`, default 0), keeps what arrives."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        from hlyn import proxy

        self.unheader = proxy.unheader
        self.sock = socket.socket()
        self.sock.bind((host, 0))
        self.sock.listen(4096)
        self.port = self.sock.getsockname()[1]
        # Every connection's origin is counted; the first KEEP are kept whole.
        # A 10-million-try race run kept them all and ran out of memory.
        self.seen: list[tuple[str | None, int | None, bytes]] = []
        self.origins: collections.Counter[tuple[str | None, int | None]] = collections.Counter()
        self.verdict: dict[tuple[str, int], int] = {}
        self.done = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self.done:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        buf = b""
        try:
            while True:
                parsed = self.unheader(buf)
                if parsed is not None:
                    break
                more = conn.recv(256)
                if not more:
                    return
                buf += more
            origin, used = parsed
            rest = buf[used:]
            address = None if origin.address is None else str(origin.address)
            if address is not None and not (address in ("127.0.0.1", "::1") and origin.port == self.port):
                conn.sendall(bytes((self.verdict.get((address, origin.port), 0),)))
            try:
                while len(rest) < 64:
                    more = conn.recv(64)
                    if not more:
                        break
                    rest += more
            except OSError:
                pass
            self.origins[address, origin.port] += 1
            if len(self.seen) < KEEP:
                self.seen.append((address, origin.port, rest))
        except OSError:
            return
        finally:
            conn.close()

    def close(self) -> None:
        self.done = True
        self.thread.join(2)
        self.sock.close()


def gated(body: str, *, net: list[str] | bool, write: list[str] = (), read: list[str] = (), proxy: Proxy,
          reduced: bool = False, preload: str = "", timeout: float = 60, env: dict | None = None,
          mode: str = "hosts", datagrams: bool = False):
    """Run `body` sealed for `net`; the real Guard answers. Returns the
    child's output and the events the gate reported.

    `mode` "off" or "ports" seals as `linux.load` does without hosts on a
    kernel before Landlock ABI 9 (`net` is then False or a list of ports).
    `datagrams` refuses unix datagram sockets, as `linux.load` does whenever
    a gate checks unix sockets before ABI 9. `events.continued` counts the
    calls the gate let run, by system call number."""
    from hlyn.core import guard, notify
    from hlyn.hosts import parse

    ours, theirs = socket.socketpair()
    code = (AGENT.replace("WATCH", repr(mode != "hosts")).replace("DATAGRAMS", repr(datagrams))
            .replace("NET", repr(net)).replace("WRITE", repr(list(write)))
            .replace("READ", repr([SRC, *read])).replace("PRELOAD", preload) + textwrap.dedent(body))
    child = subprocess.Popen([sys.executable, "-c", code, str(theirs.fileno())], pass_fds=[theirs.fileno()],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=None if env is None else {**os.environ, **env})
    theirs.close()
    ours.settimeout(timeout)
    try:
        _, fds, _, _ = socket.recv_fds(ours, 16, 1)
    except (OSError, ValueError):
        fds = []
    if not fds:
        out, err = child.communicate(timeout=timeout)
        pytest.fail(f"the child never handed over a descriptor:\n{out}\n{err}")
    ours.send(b"k")
    events = Events()
    hosts = mode == "hosts"
    config = guard.Config(port=proxy.port if hosts else 0,
                          rules=tuple(parse(item) for item in net) if hosts else (),
                          writes=tuple(os.path.realpath(item) for item in write), reduced=reduced, mode=mode,
                          ports=tuple(net) if mode == "ports" else ())
    gate = guard.Guard(fds[0], config, tell=events.tell)
    # Every answer that lets the agent's own call run, counted by system call.
    events.continued = collections.Counter()
    answer = notify.answer

    def counted(notice, call, **how):
        if how.get("go"):
            events.continued[call.nr] += 1
        return answer(notice, call, **how)

    notify.answer = counted
    thread = threading.Thread(target=gate.serve, daemon=True)
    thread.start()
    try:
        out, err = child.communicate(timeout=timeout)
        thread.join(timeout)
    finally:
        notify.answer = answer
    os.close(fds[0])
    ours.close()
    time.sleep(0.2)  # let the fake proxy record the last connection
    print(out, err[-2000:])
    print("gate answered", gate.served, "calls; let run:", dict(events.continued), ";", events.total,
          "events:", events[:6],
          "..." if len(events) > 6 else "")
    print("proxy saw:", proxy.seen[:10], "..." if len(proxy.seen) > 10 else "")
    return out, events


def lines(out: str) -> dict[str, str]:
    return dict(line.split(" => ", 1) for line in out.splitlines() if " => " in line)


@pytest.fixture
def proxy():
    served = Proxy()
    yield served
    served.close()


def test_a_proxy_aware_connect_is_swapped_into_the_proxy_and_looks_connected(proxy):
    out, _ = gated(f"""
        s = socket.socket()
        attempt("connect to the proxy", lambda: s.connect(("127.0.0.1", {proxy.port})))
        attempt("peer", lambda: repr(s.getpeername()))
        s.sendall(b"GET-like bytes")
        attempt("connect again", lambda: s.connect(("127.0.0.1", {proxy.port})))
        s.close()
    """, net=["example.com"], proxy=proxy)
    got = lines(out)
    assert got["connect to the proxy"] == "OK"
    assert got["peer"] == repr(("127.0.0.1", proxy.port))
    assert got["connect again"] == "EISCONN"
    assert ("127.0.0.1", proxy.port, b"GET-like bytes") in proxy.seen


def test_a_non_blocking_socket_stays_non_blocking_and_close_on_exec_is_kept(proxy):
    out, _ = gated(f"""
        import fcntl
        s = socket.socket(); s.setblocking(False)
        attempt("non-blocking connect", lambda: str(s.connect_ex(("127.0.0.1", {proxy.port}))))
        flags = lambda which: fcntl.fcntl(s.fileno(), which)
        attempt("still non-blocking", lambda: str(bool(flags(fcntl.F_GETFL) & os.O_NONBLOCK)))
        attempt("close-on-exec", lambda: str(bool(flags(fcntl.F_GETFD) & fcntl.FD_CLOEXEC)))
        attempt("second connect", lambda: str(s.connect_ex(("127.0.0.1", {proxy.port}))))
        t = socket.socket(); t.set_inheritable(True)
        t.connect(("127.0.0.1", {proxy.port}))
        attempt("inheritable kept", lambda: str(t.get_inheritable()))
    """, net=["example.com"], proxy=proxy)
    got = lines(out)
    assert got["non-blocking connect"] == "0"
    assert got["still non-blocking"] == "True"
    assert got["close-on-exec"] == "True"
    assert got["second connect"] == str(errno.EISCONN)
    assert got["inheritable kept"] == "True"


def test_row_1_and_2_any_other_address_is_refused_and_nothing_reaches_it(proxy):
    """Row 1: a raw connect to a non-listed IP. Row 2: a listener on the
    proxy's own port at another loopback address (nono GHSA-6hww-cch7-pfrh)."""
    same = socket.socket()
    same.bind(("127.0.0.2", proxy.port))
    same.listen(4)
    same.settimeout(0.5)
    out, events = gated(f"""
        attempt("public address", lambda: socket.socket().connect(("93.184.215.14", 443)))
        attempt("same port, 127.0.0.2", lambda: socket.socket().connect(("127.0.0.2", {proxy.port})))
        attempt("DNS over TCP", lambda: socket.socket().connect(("1.1.1.1", 53)))
    """, net=["example.com"], proxy=proxy)
    try:
        same.accept()
        reached = True
    except OSError:
        reached = False
    got = lines(out)
    print("same-port listener reached:", reached)
    assert not reached
    assert got["public address"] == "EACCES" and got["same port, 127.0.0.2"] == "EACCES"
    assert got["DNS over TCP"] == "EACCES"
    assert proxy.seen == []
    whys = [(event["why"], event["target"], event["allow"]) for event in events]
    assert ("direct", "93.184.215.14:443", "--net 93.184.215.14") in whys
    assert ("dns", "1.1.1.1:53", None) in whys  # no flag: the proxy looks up names, DNS never helps


def test_row_26_a_listed_address_waits_for_the_proxys_verdict(proxy):
    """A program that ignores the proxy and dials a listed address directly
    gets what the proxy got: 0, or its errno (ECONNREFUSED for a database
    that isn't up yet)."""
    proxy.verdict[("127.0.0.1", 5433)] = errno.ECONNREFUSED
    out, _ = gated("""
        s = socket.socket()
        attempt("listed, up", lambda: s.connect(("127.0.0.1", 5432)))
        s.sendall(b"db bytes")
        attempt("listed, down", lambda: socket.socket().connect(("127.0.0.1", 5433)))
        attempt("listed, by localhost range", lambda: socket.socket().connect(("10.20.3.4", 8080)))
    """, net=["localhost:5432", "localhost:5433", "10.20.0.0/16:8080"], proxy=proxy)
    got = lines(out)
    assert got["listed, up"] == "OK"
    assert got["listed, down"] == "ECONNREFUSED"
    assert got["listed, by localhost range"] == "OK"
    assert ("127.0.0.1", 5432, b"db bytes") in proxy.seen
    assert any(seen[:2] == ("10.20.3.4", 8080) for seen in proxy.seen)


@pytest.mark.skipif(os.uname().machine not in ("aarch64", "arm64"), reason="pointer tags are arm64's")
def test_a_tagged_sockaddr_pointer_is_read_where_the_kernel_reads_it(proxy):
    """On arm64 a program may carry a tag in a pointer's top byte (MTE and
    HWASan builds do, once they opt in with PR_SET_TAGGED_ADDR_CTRL), and
    the kernel ignores it. The gate reads the agent's sockaddr from
    /proc/PID/mem, so it clears the tag too (`notify.UNTAG`). The kernel
    already ignores a tag in that offset (remote page lookups untag, since
    Linux 6.4), except one with the top bit set -- HWASan's tags use the
    whole byte -- which makes the offset negative, so pread refuses it and
    the connect would fail. 0x0b is an MTE-style tag; 0xa5 has the top bit."""
    out, events = gated(f"""
        libc = ctypes.CDLL(None, use_errno=True)
        # PR_SET_TAGGED_ADDR_CTRL (55), PR_TAGGED_ADDR_ENABLE (1)
        attempt("tagged pointers enabled", lambda: str(libc.prctl(55, 1, 0, 0, 0)))
        def dial(port, tag, send=b""):
            s = socket.socket()
            addr = (ctypes.c_ubyte * 16)()
            addr[0:8] = (2).to_bytes(2, "little") + port.to_bytes(2, "big") + bytes([127, 0, 0, 1])
            where = ctypes.addressof(addr) | (tag << 56)
            if libc.connect(s.fileno(), ctypes.c_void_p(where), 16) != 0:
                raise OSError(ctypes.get_errno(), "connect")
            if send:
                s.sendall(send)
            s.close()
        for tag in (0, 0x0B, 0xA5):
            attempt(f"tag {{tag:#x}}: the proxy", lambda: dial({proxy.port}, tag, b"to proxy %d" % tag))
            attempt(f"tag {{tag:#x}}: listed localhost:5432", lambda: dial(5432, tag, b"to db %d" % tag))
            attempt(f"tag {{tag:#x}}: unlisted localhost:5999", lambda: dial(5999, tag))
    """, net=["example.com", "localhost:5432"], proxy=proxy)
    got = lines(out)
    if got["tagged pointers enabled"] != "0":
        pytest.skip("this kernel doesn't offer the tagged-address ABI")
    for tag in ("0x0", "0xb", "0xa5"):
        assert got[f"tag {tag}: the proxy"] == "OK"
        assert got[f"tag {tag}: listed localhost:5432"] == "OK"
        assert got[f"tag {tag}: unlisted localhost:5999"] == "EACCES"
    for sent in (11, 165):
        assert ("127.0.0.1", proxy.port, b"to proxy %d" % sent) in proxy.seen
        assert ("127.0.0.1", 5432, b"to db %d" % sent) in proxy.seen
    assert any(event.get("target") == "127.0.0.1:5999" for event in events)


def test_row_22_unix_sockets_need_a_write_grant_and_the_refused_list_always_wins(proxy):
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    other = tempfile.mkdtemp(prefix="hlyn-guard-other-")
    listeners = []
    for path in (f"{box}/db.sock", f"{box}/docker.sock", f"{other}/private.sock"):
        server = socket.socket(socket.AF_UNIX)
        server.bind(path)
        server.listen(4)
        listeners.append(server)
    os.symlink(f"{box}/docker.sock", f"{box}/innocent")
    os.symlink(f"{other}/private.sock", f"{box}/link-out")
    out, events = gated(f"""
        os.chdir({box!r})
        dial = lambda path: socket.socket(socket.AF_UNIX).connect(path)
        attempt("granted folder", lambda: dial({box + '/db.sock'!r}))
        attempt("granted, relative", lambda: dial("db.sock"))
        attempt("runtime socket in a granted folder", lambda: dial("docker.sock"))
        attempt("symlink to the runtime socket", lambda: dial("innocent"))
        attempt("symlink out of the grant", lambda: dial("link-out"))
        attempt("not granted", lambda: dial({other + '/private.sock'!r}))
        attempt("nscd", lambda: dial("/var/run/nscd/socket"))
        attempt("resolved", lambda: dial("/run/systemd/resolve/io.systemd.Resolve"))
        attempt("system bus", lambda: dial("/run/dbus/system_bus_socket"))
    """, net=["example.com"], write=[box], read=[box, other], proxy=proxy)
    for server in listeners:
        server.close()
    got = lines(out)
    assert got["granted folder"] == "OK" and got["granted, relative"] == "OK"
    for refused in ("runtime socket in a granted folder", "symlink to the runtime socket",
                    "symlink out of the grant", "not granted"):
        assert got[refused] == "EACCES", (refused, got[refused])
    # Resolver and bus sockets: refused where they exist; where nothing is
    # there, the kernel's own ENOENT, so glibc's nscd probe on every lookup
    # isn't reported as a refusal. Never reached either way.
    for name, path in (("nscd", "/var/run/nscd/socket"),
                       ("resolved", "/run/systemd/resolve/io.systemd.Resolve"),
                       ("system bus", "/run/dbus/system_bus_socket")):
        want = "EACCES" if os.path.lexists(path) else "ENOENT"
        print(f"{name}: {path} exists: {os.path.lexists(path)}, got {got[name]}")
        assert got[name] == want, (name, got[name])
    allows = {event["target"]: event["allow"] for event in events}
    assert allows[os.path.realpath(f"{other}/private.sock")] == f"--write {os.path.realpath(other)}"
    assert allows[os.path.realpath(f"{box}/docker.sock")] == "--net-any"


def test_row_23_a_unix_datagram_goes_by_connect_never_by_a_path_in_sendto(proxy):
    """A datagram socket connected to a granted path is swapped like a stream
    one, and its sends arrive. A `sendto` that names a path is refused: the
    kernel would resolve the path again after the gate's check, which a
    racing thread or a folder swap wins (5.3), and glibc's syslog, Python's
    SysLogHandler and the like connect first."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sink.bind(f"{box}/log")
    out, events = gated(f"""
        d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        attempt("connect granted", lambda: d.connect({box + '/log'!r}))
        attempt("send", lambda: str(d.send(b"hello")))
        attempt("type kept", lambda: str(d.type == socket.SOCK_DGRAM))
        e = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        attempt("sendto granted", lambda: str(e.sendto(b"x", {box + '/log'!r})))
        attempt("sendto /dev/log", lambda: str(e.sendto(b"x", "/dev/log")))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy)
    sink.settimeout(1)
    heard = sink.recv(100)
    print("granted sink got:", heard)
    got = lines(out)
    assert got["connect granted"] == "OK" and got["send"] == "5" and got["type kept"] == "True"
    assert heard == b"hello"
    assert got["sendto granted"] == "EACCES" and got["sendto /dev/log"] == "EACCES"
    sent = [event for event in events if event["why"] == "unix-send"]
    print("reported:", sent)
    assert sent and sent[0]["target"] == os.path.realpath(f"{box}/log")


def test_unix_connects_get_the_kernels_own_answers(proxy):
    """Swapped or not, the agent sees what the kernel would say: a stream
    socket connects once (EISCONN after), nothing listening is ECONNREFUSED,
    a missing path is ENOENT, and the peer is the listener's address."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    server = socket.socket(socket.AF_UNIX)
    server.bind(f"{box}/db.sock")
    server.listen(4)
    dead = socket.socket(socket.AF_UNIX)
    dead.bind(f"{box}/dead.sock")  # bound, never listening
    out, _ = gated(f"""
        s = socket.socket(socket.AF_UNIX)
        attempt("connect", lambda: s.connect({box + '/db.sock'!r}))
        attempt("peer", lambda: s.getpeername())
        attempt("connect again", lambda: s.connect({box + '/db.sock'!r}))
        s.sendall(b"ping")
        attempt("nothing listening", lambda: socket.socket(socket.AF_UNIX).connect({box + '/dead.sock'!r}))
        attempt("missing", lambda: socket.socket(socket.AF_UNIX).connect({box + '/none.sock'!r}))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy)
    conn, _ = server.accept()
    conn.settimeout(2)
    heard = conn.recv(10)
    print("server heard:", heard)
    got = lines(out)
    assert got["connect"] == "OK" and got["peer"] == f"{box}/db.sock"
    assert got["connect again"] == "EISCONN"
    assert heard == b"ping"
    assert got["nothing listening"] == "ECONNREFUSED"
    assert got["missing"] == "ENOENT"
    server.close()
    dead.close()


def test_a_unix_socket_bound_before_connecting_is_refused_and_says_why(proxy):
    """The gate connects a new socket of its own and swaps it in; a socket the
    agent had bound would lose its address, so it is refused instead."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(f"{box}/srv")
    out, events = gated(f"""
        c = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        c.bind({box + '/client'!r})
        attempt("bound, then connect", lambda: c.connect({box + '/srv'!r}))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy)
    got = lines(out)
    assert got["bound, then connect"] == "EACCES"
    bound = [event for event in events if event["why"] == "unix-bound"]
    print("reported:", bound)
    assert bound and bound[0]["target"] == os.path.realpath(f"{box}/srv")
    server.close()


def test_a_folder_swapped_for_a_symlink_never_reaches_another_socket(proxy):
    """CVE-2026-79994's pattern: the gate checks a path, then the folder in it
    is swapped for a symlink to somewhere else before the connect runs. The
    gate pins the socket file it checked and connects to that object, so the
    other socket is never reached, whoever wins the race. One thread swaps
    the folder (renameat2 RENAME_EXCHANGE) while the main thread connects."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    other = tempfile.mkdtemp(prefix="hlyn-guard-other-")
    os.mkdir(f"{box}/ws")
    good = socket.socket(socket.AF_UNIX)
    good.bind(f"{box}/ws/s.sock")
    good.listen(4096)
    evil = socket.socket(socket.AF_UNIX)
    evil.bind(f"{other}/s.sock")
    evil.listen(4096)
    evil.setblocking(False)
    os.symlink(other, f"{box}/link")
    out, _ = gated(f"""
        import threading
        libc = ctypes.CDLL(None, use_errno=True)
        stop = False
        def swap():
            while not stop:
                libc.renameat2(-100, {box + '/ws'!r}.encode(), -100, {box + '/link'!r}.encode(), 2)
        t = threading.Thread(target=swap); t.start()
        counts = {{}}
        for _ in range(3000):
            c = socket.socket(socket.AF_UNIX)
            try:
                c.connect({box + '/ws/s.sock'!r})
                counts["connected"] = counts.get("connected", 0) + 1
            except OSError as exc:
                name = errno.errorcode.get(exc.errno, str(exc.errno))
                counts[name] = counts.get(name, 0) + 1
            c.close()
        stop = True; t.join()
        attempt("outcomes", lambda: " ".join(f"{{k}}={{v}}" for k, v in sorted(counts.items())))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy, timeout=300)
    reached = 0
    while True:
        try:
            evil.accept()[0].close()
            reached += 1
        except OSError:
            break
    print(f"the other socket was reached {reached} times")
    got = lines(out)
    assert "connected=" in got["outcomes"], "the swap never let a connect through: nothing was tested"
    assert reached == 0
    good.close()
    evil.close()


def test_a_hard_link_to_a_refused_socket_is_refused_by_what_it_is(proxy, docker_home):
    """A refused socket linked into a granted folder under an innocent name:
    the path matches nothing, the object is docker.sock. The gate compares the
    pinned object with the refused sockets that exist here, by inode."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-", dir=str(docker_home))
    sock = docker_home / ".docker" / "run" / "docker.sock"
    os.link(sock, f"{box}/innocent.sock")
    out, events = gated(f"""
        link = {box + '/innocent.sock'!r}
        attempt("hard link to docker.sock", lambda: socket.socket(socket.AF_UNIX).connect(link))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy)
    got = lines(out)
    assert got["hard link to docker.sock"] == "EACCES"
    print("reported:", events)
    assert any(event["allow"] == "--net-any" for event in events)


@pytest.mark.parametrize("untag", ["native", "x86_64"])
def test_the_gate_answers_any_arguments_and_keeps_serving(proxy, monkeypatch, untag):
    """Every register of a trapped call is the agent's to choose. Whatever it
    puts there -- a pointer past the top of memory, a length of 2^64-1, a
    descriptor with its upper bits set -- the gate must answer that call (an
    errno, as the kernel would give) and go on answering the next ones: a
    gate that dies leaves the agent waiting forever, or running on without
    its supervisor. "x86_64" reads memory with that architecture's mask (no
    tag bits cleared), since the gate code is otherwise the same on both."""
    from hlyn.core import notify

    if untag == "x86_64":
        monkeypatch.setattr(notify, "UNTAG", (1 << 64) - 1)
    out, _ = gated(f"""
        import itertools
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        arm = os.uname().machine in ("aarch64", "arm64")
        CONNECT, SENDTO = (203, 206) if arm else (42, 44)
        def raw(nr, *args):
            rc = libc.syscall(ctypes.c_long(nr), *(ctypes.c_long(a - (1 << 64) if a >= 1 << 63 else a)
                                                     for a in args))
            if rc < 0:
                raise OSError(ctypes.get_errno(), "syscall")
            return str(rc)
        s = socket.socket()
        unlisted = (2).to_bytes(2, "little") + (5999).to_bytes(2, "big") + bytes([127, 0, 0, 1]) + bytes(8)
        good = (ctypes.c_ubyte * 16)(*unlisted)
        junk = (ctypes.c_ubyte * 128)(*range(128))
        pointers = {{"null": 0, "one": 1, "2^47": 1 << 47, "2^56-1": (1 << 56) - 1, "2^63-1": (1 << 63) - 1,
                    "2^63": 1 << 63, "2^64-1": (1 << 64) - 1, "junk bytes": ctypes.addressof(junk),
                    "unlisted address": ctypes.addressof(good)}}
        sizes = {{"0": 0, "1": 1, "7": 7, "16": 16, "2^31": 1 << 31, "2^32-1": (1 << 32) - 1,
                 "2^32+16": (1 << 32) + 16, "2^64-1": (1 << 64) - 1}}
        fds = {{"socket": s.fileno(), "socket, upper bits": (1 << 32) | s.fileno(), "-1": (1 << 64) - 1,
               "2^31-1": (1 << 31) - 1, "stdin": 0}}
        answers = set()
        for (pn, pv), (sn, sv), (fn, fv) in itertools.product(pointers.items(), sizes.items(), fds.items()):
            for nr, args in ((CONNECT, (fv, pv, sv)), (SENDTO, (fv, 0, 0, 0, pv, sv))):
                try:
                    raw(nr, *args)
                    answers.add("OK")
                except OSError as exc:
                    answers.add(errno.errorcode.get(exc.errno, str(exc.errno)))
        attempt("answers given", lambda: " ".join(sorted(answers)))
        attempt("still served: connect to the proxy",
                lambda: socket.socket().connect(("127.0.0.1", {proxy.port})))
        attempt("still refused: unlisted address", lambda: socket.socket().connect(("127.0.0.1", 5999)))
    """, net=["example.com"], proxy=proxy)
    got = lines(out)
    assert got["still served: connect to the proxy"] == "OK"
    assert got["still refused: unlisted address"] == "EACCES"
    # Each an errno the kernel itself gives for such arguments, and the
    # unlisted address refused as always; EPIPE is a send on an unconnected
    # TCP socket, which the gate lets the kernel answer.
    assert set(got["answers given"].split()) <= {"EACCES", "EAFNOSUPPORT", "EBADF", "EFAULT", "EINVAL",
                                                  "ENOTSOCK", "EPIPE"}
    assert "EACCES" in got["answers given"].split()


def test_a_bug_in_the_gate_refuses_that_call_and_is_reported(proxy, monkeypatch):
    """Defence in depth for the test above: any exception while deciding one
    call -- here a parser that raises -- refuses that call (EACCES), says so
    in the report, and the gate goes on serving the next."""
    from hlyn.core import notify
    from hlyn.policy import Policy
    from hlyn.report import Denial, Report

    real = notify.sockaddr
    broken = {"once": True}

    def sockaddr(data: bytes):
        if broken.pop("once", False):
            raise ValueError("a parser bug")
        return real(data)

    monkeypatch.setattr(notify, "sockaddr", sockaddr)
    out, events = gated(f"""
        attempt("the call the bug hit", lambda: socket.socket().connect(("127.0.0.1", {proxy.port})))
        attempt("the next call", lambda: socket.socket().connect(("127.0.0.1", {proxy.port})))
    """, net=["example.com"], proxy=proxy)
    got = lines(out)
    assert got["the call the bug hit"] == "EACCES" and got["the next call"] == "OK"
    error = next(event for event in events if event["why"] == "gate-error")
    entry = Report(Policy(net=["example.com"])).add(
        Denial("net", error["target"], op=error["why"], source="gate"))
    print(error, "\n", entry)
    assert error["target"] == "ValueError"
    assert entry.target == "a connection the gate couldn't check" and entry.allow is None
    assert "This is a bug in hlyn" in entry.note


def test_reduced_mode_swaps_tcp_as_unknown_and_refuses_unix(proxy):
    """When the gate can't read the agent's memory (Yama; 5.3), every TCP
    connect goes to the proxy with a LOCAL header, and unix is refused."""
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    out, _ = gated(f"""
        s = socket.socket()
        attempt("tcp anywhere", lambda: s.connect(("93.184.215.14", 443)))
        s.sendall(b"CONNECT example.com:443")
        attempt("unix, granted", lambda: socket.socket(socket.AF_UNIX).connect({box + '/x.sock'!r}))
    """, net=["example.com"], write=[box], proxy=proxy, reduced=True)
    got = lines(out)
    assert got["tcp anywhere"] == "OK"
    assert got["unix, granted"] == "EACCES"
    assert (None, None, b"CONNECT example.com:443") in proxy.seen


CONNECT_NR = {"aarch64": 203, "arm64": 203, "x86_64": 42}.get(os.uname().machine)
SENDTO_NR = {"aarch64": 206, "arm64": 206, "x86_64": 44}.get(os.uname().machine)

# Every connect() the gate used to let run, each with the answer the kernel
# gives it (measured by letting it run: FINDINGS.md, "The gate lets no
# connect run"). Raw sockaddrs, so nothing in Python's socket module stands
# between the agent and the call.
EVERY_ROW = """
    import struct
    libc = ctypes.CDLL(None, use_errno=True)
    def raw(fd, data):
        buf = ctypes.create_string_buffer(data, max(len(data), 1))
        if libc.connect(fd, buf, len(data)) != 0:
            raise OSError(ctypes.get_errno(), "connect")
    UNSPEC = bytes(16)
    nl = lambda family, pid, groups: struct.pack("=HHII", family, 0, pid, groups)
    u = socket.socket(socket.AF_UNIX)
    attempt("unix stream, AF_UNSPEC", lambda: raw(u.fileno(), UNSPEC))
    attempt("unix stream, unnamed", lambda: raw(u.fileno(), struct.pack("=H", 1)))
    q = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    attempt("unix seqpacket, AF_UNSPEC", lambda: raw(q.fileno(), UNSPEC))
    attempt("unix seqpacket, unnamed", lambda: raw(q.fileno(), struct.pack("=H", 1)))
    own = socket.socket(socket.AF_UNIX); own.bind("\\0hlyn-guard-own-%d" % os.getpid()); own.listen(1)
    attempt("unix abstract, the agent's own listener",
            lambda: socket.socket(socket.AF_UNIX).connect("\\0hlyn-guard-own-%d" % os.getpid()))
    n = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    attempt("netlink, the kernel", lambda: raw(n.fileno(), nl(16, 0, 0)))
    attempt("netlink, AF_UNSPEC", lambda: raw(n.fileno(), bytes(12)))
    attempt("netlink, another socket", lambda: raw(n.fileno(), nl(16, 4242, 0)))
    attempt("netlink, a group", lambda: raw(n.fileno(), nl(16, 0, 1)))
    attempt("netlink, too short", lambda: raw(n.fileno(), struct.pack("=HH", 16, 0)))
    attempt("netlink, another family", lambda: raw(n.fileno(), nl(2, 0, 0)))
    attempt("interfaces through netlink", lambda: str(len(socket.if_nameindex()) > 0))
"""

TCP_ROWS = """
    t = socket.socket()
    attempt("tcp, AF_UNSPEC before connecting", lambda: raw(t.fileno(), UNSPEC))
    attempt("tcp, connect", lambda: t.connect(("127.0.0.1", PORT)))
    t.sendall(b"first")
    attempt("tcp, AF_UNSPEC when connected", lambda: raw(t.fileno(), UNSPEC))
    attempt("tcp, peer after", lambda: repr(t.getpeername()))
    attempt("tcp, connect again", lambda: t.connect(("127.0.0.1", PORT)))
    t.sendall(b"second")
    attempt("tcp, AF_UNSPEC too short", lambda: raw(t.fileno(), UNSPEC[:2]))
    w = socket.socket(); w.connect(("127.0.0.1", PORT))
    attempt("tcp, sendto naming another address", lambda: str(w.sendto(b"sent-to", ("203.0.113.1", 9))))
"""

# What the kernel answers each row with (the measured answers above), except
# where the gate's answer is stricter on purpose.
KERNEL = {
    "unix stream, AF_UNSPEC": "EINVAL", "unix stream, unnamed": "EINVAL",
    "unix seqpacket, AF_UNSPEC": "EINVAL", "unix seqpacket, unnamed": "EINVAL",
    "netlink, the kernel": "OK", "netlink, AF_UNSPEC": "OK",
    "netlink, too short": "EINVAL", "netlink, another family": "EINVAL",
    "interfaces through netlink": "True",
    "tcp, AF_UNSPEC before connecting": "OK", "tcp, connect": "OK", "tcp, AF_UNSPEC when connected": "OK",
    "tcp, peer after": "ENOTCONN", "tcp, connect again": "OK", "tcp, AF_UNSPEC too short": "EINVAL",
    "tcp, sendto naming another address": "7",
}
STRICTER = {
    # Before Landlock ABI 9 an abstract name can't be let run (the kernel
    # reads the address again, and nothing then checks a path), and the gate
    # can't connect it for the agent without losing Landlock's scope.
    "unix abstract, the agent's own listener": "EACCES",
    # What a process without CAP_NET_ADMIN is told; the gate can't set
    # another destination on the agent's socket without running the call.
    "netlink, another socket": "EPERM", "netlink, a group": "EPERM",
}


@pytest.mark.skipif(CONNECT_NR is None, reason="system call numbers for aarch64 and x86_64 only")
@pytest.mark.parametrize("mode", ["hosts", "off"])
def test_the_gate_lets_no_connect_run_before_abi_9(proxy, mode):
    """The kernel reads a let-run call's address, and finds its descriptor,
    again after the gate answers (seccomp_unotify(2)), so every connect() the
    gate lets run could end as a connect to a socket file, which nothing but
    the gate checks before Linux 7.1. So no connect() runs: the gate gives
    the kernel's own answer, swaps, or refuses. Sends still run: on every
    socket the agent can hold here, a send's address reaches no socket file
    (the kernel ignores it, or refuses it; unix datagram sockets can't be
    made). Host mode, and the network off (no IP sockets: TCP rows skipped)."""
    body = EVERY_ROW + (TCP_ROWS.replace("PORT", str(proxy.port)) if mode == "hosts" else "")
    out, events = gated(body, net=["example.com"] if mode == "hosts" else False, proxy=proxy,
                        mode=mode, datagrams=True)
    got = lines(out)
    want = {row: answer for row, answer in {**KERNEL, **STRICTER}.items()
            if mode == "hosts" or not row.startswith("tcp")}
    for row, answer in want.items():
        print(f"{row}: {got.get(row)} (want {answer})")
    assert {row: got.get(row) for row in want} == want
    print("let run:", dict(events.continued))
    assert events.continued[CONNECT_NR] == 0
    assert events.continued[SENDTO_NR] >= 1  # the count works: glibc's netlink request is a send
    if mode == "hosts":
        sent = [seen[2] for seen in proxy.seen if seen[:2] == ("127.0.0.1", proxy.port)]
        print("proxy got:", sent)
        assert sorted(sent) == [b"first", b"second", b"sent-to"]
    refused = [event for event in events if event["why"] == "unix-abstract"]
    print("reported:", refused)
    assert refused and refused[0]["allow"] == "--net-any"


PORTS_ROWS = """
    import select
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    attempt("tcp, listed port", lambda: s.connect(("127.0.0.1", PORT_OK)))
    attempt("tcp, the agent's own socket after",
            lambda: repr((s.getpeername() == ("127.0.0.1", PORT_OK),
                          s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0,
                          s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0)))
    s.sendall(b"ports-mode")
    attempt("tcp, connect again", lambda: s.connect(("127.0.0.1", PORT_OK)))
    attempt("tcp, unlisted port", lambda: socket.socket().connect(("127.0.0.1", PORT_NO)))
    attempt("tcp, listed, nothing listening", lambda: socket.socket().connect(("127.0.0.1", PORT_DEAD)))
    n = socket.socket(); n.setblocking(False)
    attempt("tcp, non-blocking", lambda: errno.errorcode.get(n.connect_ex(("127.0.0.1", PORT_OK)), "0"))
    attempt("tcp, non-blocking, then", lambda: repr((bool(select.select([], [n], [], 5)[1]),
                                                     n.getpeername() == ("127.0.0.1", PORT_OK))))
    attempt("tcp, still non-blocking", lambda: str(n.getblocking()))
    attempt("tcp, AF_UNSPEC", lambda: raw(s.fileno(), UNSPEC))
    attempt("tcp, AF_UNSPEC too short", lambda: raw(s.fileno(), UNSPEC[:2]))
    v4 = socket.socket()
    attempt("tcp, another family", lambda: raw(v4.fileno(), struct.pack("=H", socket.AF_INET6)
                                               + struct.pack("!H", PORT_OK) + bytes(20)))
    attempt("tcp6, unlisted port", lambda: socket.socket(socket.AF_INET6).connect(("::1", PORT_NO)))
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attempt("udp, any port", lambda: u.connect(("127.0.0.1", PORT_NO)))
    attempt("udp, send", lambda: str(u.send(b"x")))
"""

PORTS_WANT = {
    "tcp, listed port": "OK", "tcp, the agent's own socket after": "(True, True, True)",
    "tcp, connect again": "EISCONN", "tcp, unlisted port": "EACCES",
    "tcp, listed, nothing listening": "ECONNREFUSED", "tcp, non-blocking": "EINPROGRESS",
    "tcp, non-blocking, then": "(True, True)", "tcp, still non-blocking": "False",
    "tcp, AF_UNSPEC": "OK", "tcp, AF_UNSPEC too short": "EINVAL", "tcp, another family": "EINVAL",
    "tcp6, unlisted port": "EACCES", "udp, any port": "OK", "udp, send": "1",
}


@pytest.mark.skipif(CONNECT_NR is None, reason="system call numbers for aarch64 and x86_64 only")
@pytest.mark.parametrize("grab", ["works", "refused"])
def test_ports_mode_connects_on_the_agents_own_socket(proxy, monkeypatch, grab):
    """Ports mode before Landlock ABI 9: the gate takes a copy of the
    agent's socket (pidfd_getfd), checks the port as Landlock does, and
    connects the copy, so no connect runs; the socket keeps its options
    and flags (ports mode refuses bind, so none is bound). "refused":
    pidfd_getfd refused (Docker's
    default profile), so each call runs and the kernel and Landlock answer:
    the reference the gate's own answers must match row for row."""
    from hlyn.core import notify

    if grab == "works" and not notify.grabbable():
        pytest.skip("pidfd_getfd is refused here (a stock docker run): the gate lets the call run instead")
    if grab == "refused":
        def refused(pid, fd):
            raise PermissionError(errno.EPERM, "pidfd_getfd refused")
        monkeypatch.setattr(notify, "grab", refused)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    unlisted = socket.socket()
    unlisted.bind(("127.0.0.1", 0))
    unlisted.listen(8)
    unlisted.settimeout(0.5)
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))  # bound, never listening: ECONNREFUSED
    ports = {"PORT_OK": listener.getsockname()[1], "PORT_NO": unlisted.getsockname()[1],
             "PORT_DEAD": dead.getsockname()[1]}
    body = EVERY_ROW + PORTS_ROWS
    for name, port in ports.items():
        body = body.replace(name, str(port))
    out, events = gated(body, net=[ports["PORT_OK"], ports["PORT_DEAD"]], proxy=proxy, mode="ports",
                        datagrams=True)
    listener.settimeout(2)
    conn, _ = listener.accept()
    conn.settimeout(2)
    heard = conn.recv(64)
    try:
        unlisted.accept()
        reached = True
    except OSError:
        reached = False
    print(f"listener heard {heard!r}; unlisted port reached: {reached}")
    for item in (listener, unlisted, dead, conn):
        item.close()
    got = lines(out)
    want = {**PORTS_WANT, **{row: answer for row, answer in {**KERNEL, **STRICTER}.items()
                             if not row.startswith("tcp")}}
    for row, answer in want.items():
        print(f"{row}: {got.get(row)} (want {answer})")
    assert {row: got.get(row) for row in want} == want
    assert heard == b"ports-mode" and not reached
    print("let run:", dict(events.continued))
    if grab == "works":
        assert events.continued[CONNECT_NR] == 0
    else:
        assert events.continued[CONNECT_NR] >= 10  # every IP connect ran, as before
    assert events.continued[SENDTO_NR] >= 1


RACE = os.path.join(ROOT, "tools", "hostlab", "race.c")


# Long runs (REMAINING part 1 #16): HLYN_RACE tries (default 3,000), and
# HLYN_RACE_SANITIZE=address or thread to build the racing program with
# AddressSanitizer or ThreadSanitizer, which changes its timing and checks
# its own memory and threads while it races.
TRIES = int(os.environ.get("HLYN_RACE", "3000"))
SANITIZE = os.environ.get("HLYN_RACE_SANITIZE", "")


def _race_library() -> str:
    out = os.path.join(tempfile.mkdtemp(prefix="hlyn-race-"), "race.so")
    flags = ["-O2"] if not SANITIZE else ["-O1", "-g", f"-fsanitize={SANITIZE}", "-fno-omit-frame-pointer"]
    done = subprocess.run(["cc", *flags, "-shared", "-fPIC", "-pthread", "-o", out, RACE],
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        pytest.skip(f"no C compiler for the race harness: {done.stderr[-300:]}")
    return out


def _runtime() -> dict[str, str]:
    """The environment that loads a sanitizer's runtime first, as it must be
    when the sanitized library is loaded into a Python that isn't."""
    if not SANITIZE:
        return {}
    name = {"address": "libasan.so", "thread": "libtsan.so"}[SANITIZE]
    found = subprocess.run(["cc", f"-print-file-name={name}"], capture_output=True, text=True,
                           check=True).stdout.strip()
    return {"LD_PRELOAD": os.path.realpath(found), "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1",
            "TSAN_OPTIONS": "report_signal_unsafe=0:halt_on_error=1:"
                            f"suppressions={os.path.join(ROOT, 'tools', 'hostlab', 'race.tsan')}"}


@pytest.mark.skipif(not any(os.access(os.path.join(p, "cc"), os.X_OK)
                            for p in os.environ.get("PATH", "").split(":")), reason="needs cc")
def test_row_3_racing_the_address_never_connects_tcp_anywhere_but_the_proxy(proxy):
    """Threads rewrite the sockaddr while connect() waits for the gate, between
    the proxy and a listener on the same port at 127.0.0.2. The gate never
    lets a TCP connect run, so that listener must get nothing."""
    library = _race_library()
    iterations = TRIES
    evil = socket.socket()
    evil.bind(("127.0.0.2", proxy.port))
    evil.listen(4096)
    evil.setblocking(False)
    good = int(ipaddress.IPv4Address("127.0.0.1")).to_bytes(4, "big")
    bad = int(ipaddress.IPv4Address("127.0.0.2")).to_bytes(4, "big")
    port = socket.htons(proxy.port)
    out, events = gated(f"""
        out = (ctypes.c_int * 3)()
        began = __import__("time").monotonic()
        race.race_tcp(ctypes.c_uint32(int.from_bytes({good!r}, "little")), ctypes.c_uint16({port}),
                      ctypes.c_uint32(int.from_bytes({bad!r}, "little")), ctypes.c_uint16({port}),
                      {iterations}, 4, out)
        took = __import__("time").monotonic() - began
        print("connected", out[0], "refused", out[1], "other", out[2], f"in {{took:.1f}} s", flush=True)
    """, net=["example.com"], proxy=proxy, preload=f"race = ctypes.CDLL({library!r})",
       timeout=max(600, iterations / 50), env=_runtime())
    print(f"{iterations} tries, sanitizer: {SANITIZE or 'none'}")
    reached = 0
    while True:
        try:
            evil.accept()[0].close()
            reached += 1
        except OSError:
            break
    print(f"the listener at 127.0.0.2:{proxy.port} accepted {reached} connections")
    counts = out.split()
    connected, refused = int(counts[1]), int(counts[3])
    assert reached == 0
    assert connected + refused == iterations, out
    assert events.total == refused, (events.total, refused)  # each refusal left a record
    assert connected > 0 and refused > 0, "the flipping never landed on both addresses"
    print("origins the proxy was told:", dict(proxy.origins))
    assert set(proxy.origins) == {("127.0.0.1", proxy.port)}, proxy.origins


@pytest.mark.skipif(not any(os.access(os.path.join(p, "cc"), os.X_OK)
                            for p in os.environ.get("PATH", "").split(":")), reason="needs cc")
@pytest.mark.parametrize("where", ["inside", "outside"])
def test_row_3_unix_race(proxy, where):
    """Racing threads flip a unix connect's path between an allowed socket and
    a refused one (docker.sock). The gate connects the socket file it checked
    itself and swaps the connection in, so the agent's own call never runs
    and the race is won zero times, on every kernel. Before 2026-09-28 the
    gate let the call run and this was won 611-756 times in 3,000.

    `inside`: the refused socket sits in the write-granted folder;
    `outside`: in a folder no grant covers. Both check that the flipping
    lands on both paths, so the check itself was exercised."""
    from hlyn.core import landlock

    library = _race_library()
    box = tempfile.mkdtemp(prefix="hlyn-race-")
    other = box if where == "inside" else tempfile.mkdtemp(prefix="hlyn-race-other-")
    allowed, refused = f"{box}/ok.sock", f"{other}/docker.sock"
    servers = []
    for path in (allowed, refused):
        server = socket.socket(socket.AF_UNIX)
        server.bind(path)
        server.listen(4096)
        server.setblocking(False)
        servers.append(server)
    served = threading.Event()

    def drain() -> None:  # the allowed listener's queue never fills
        while not served.is_set():
            ready, _, _ = __import__("select").select([servers[0]], [], [], 0.2)
            if ready:
                with contextlib.suppress(OSError):
                    servers[0].accept()[0].close()

    drainer = threading.Thread(target=drain, daemon=True)
    drainer.start()
    out, events = gated(f"""
        out = (ctypes.c_int * 3)()
        began = __import__("time").monotonic()
        race.race_unix({allowed.encode()!r}, {refused.encode()!r}, {TRIES}, 4, out)
        took = __import__("time").monotonic() - began
        print("connected", out[0], "refused", out[1], "other", out[2], f"in {{took:.1f}} s", flush=True)
        errors = (ctypes.c_int * 256)()
        race.race_errors(errors, 256)
        names = __import__("errno").errorcode
        print("other by errno", {{names.get(n, n): errors[n] for n in range(256) if errors[n]}},
              "total", sum(errors), flush=True)
    """, net=["example.com"], write=[box], proxy=proxy, preload=f"race = ctypes.CDLL({library!r})",
       timeout=max(600, TRIES / 50), env=_runtime())
    served.set()
    drainer.join()
    won = 0
    while True:
        try:
            servers[1].accept()[0].close()
            won += 1
        except OSError:
            break
    abi = landlock.abi()
    print(f"Landlock ABI {abi}, sanitizer {SANITIZE or 'none'}, refused socket {where} the grant: "
          f"races won {won} of {TRIES} "
          f"(reached {refused}); must be 0")
    counts = out.split()
    assert int(counts[1]) > 0 and int(counts[3]) > 0
    assert events.total == int(counts[3]), (events.total, out)  # each refusal left a record
    assert int(out.split("total ")[1].split()[0]) == int(counts[5]), out  # every "other" has its errno
    assert won == 0


# ---------------------------------------------------------------------------
# a write grant that holds a refused socket (5.3's residual inside a grant)
# ---------------------------------------------------------------------------


@pytest.fixture
def docker_home(tmp_path, monkeypatch):
    """A home folder holding a real ~/.docker/run/docker.sock."""
    run = tmp_path / ".docker" / "run"
    run.mkdir(parents=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(run / "docker.sock"))
    monkeypatch.setenv("HOME", str(tmp_path))
    yield tmp_path
    server.close()


def test_granted_names_refused_sockets_only_under_a_write_grant(docker_home, tmp_path):
    from hlyn.core.guard import granted

    sock = os.path.realpath(docker_home / ".docker" / "run" / "docker.sock")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cases = {
        "the folder holding it": ((str(docker_home / ".docker"),), [sock]),
        "a folder beside it": ((str(elsewhere),), []),
        "write=True": (True, "contains"),
        "no writes": ((), []),
    }
    for name, (writes, want) in cases.items():
        got = granted(writes)
        print(f"{name:24} -> {got}")
        if want == "contains":
            assert sock in got
        else:
            assert got == want, name


def test_hlyn_show_warns_when_a_write_grant_holds_a_refused_socket_nothing_checks(docker_home, monkeypatch):
    """With hosts, or before Linux 7.1 with any limited network, the gate
    refuses docker.sock even inside a write grant, race-free: no warning.
    From 7.1, ports and net=False have no gate, and Landlock allows every
    socket in a write-granted folder: then `show` and the seal warn."""
    env = dict(os.environ, PYTHONPATH=SRC, HOME=str(docker_home))
    folder = str(docker_home / ".docker")
    for net in ("pypi.org", "443"):
        done = subprocess.run([sys.executable, "-m", "hlyn.cli", "show", "--net", net, "--write", folder],
                              capture_output=True, text=True, env=env, check=False)
        print(f"--net {net}:", repr(done.stderr))
        assert done.returncode == 0
        assert "docker.sock" not in done.stderr
    from hlyn import jail
    from hlyn.core import landlock
    from hlyn.policy import Policy

    monkeypatch.setattr(landlock, "abi", lambda: 9)
    said = jail.reaches(Policy(net=[443], write=[folder]))
    print("on a 7.1 kernel, ports:", said)
    assert any(f"--write {folder} covers {os.path.realpath(folder)}/run/docker.sock" in line
               and "Grant a narrower folder unless you mean it." in line for line in said)
    assert jail.reaches(Policy(net=["pypi.org"], write=[folder])) == []
