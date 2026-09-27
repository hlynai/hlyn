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
    fd = seccomp.load(policy)
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
        self.seen: list[tuple[str | None, int | None, bytes]] = []
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
            self.seen.append((address, origin.port, rest))
        except OSError:
            return
        finally:
            conn.close()

    def close(self) -> None:
        self.done = True
        self.thread.join(2)
        self.sock.close()


def gated(body: str, *, net: list[str], write: list[str] = (), read: list[str] = (), proxy: Proxy,
          reduced: bool = False, preload: str = "", timeout: float = 60):
    """Run `body` sealed for `net`; the real Guard answers. Returns the
    child's output and the events the gate reported."""
    from hlyn.core import guard
    from hlyn.hosts import parse

    ours, theirs = socket.socketpair()
    code = (AGENT.replace("NET", repr(net)).replace("WRITE", repr(list(write)))
            .replace("READ", repr([SRC, *read])).replace("PRELOAD", preload) + textwrap.dedent(body))
    child = subprocess.Popen([sys.executable, "-c", code, str(theirs.fileno())], pass_fds=[theirs.fileno()],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
    events: list[dict] = []
    config = guard.Config(port=proxy.port, rules=tuple(parse(item) for item in net),
                          writes=tuple(os.path.realpath(item) for item in write), reduced=reduced)
    gate = guard.Guard(fds[0], config, tell=events.append)
    thread = threading.Thread(target=gate.serve, daemon=True)
    thread.start()
    out, err = child.communicate(timeout=timeout)
    thread.join(timeout)
    os.close(fds[0])
    ours.close()
    time.sleep(0.2)  # let the fake proxy record the last connection
    print(out, err[-2000:])
    print("gate answered", gate.served, "calls;", len(events), "events:", events[:6],
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


def test_row_23_a_unix_datagram_to_a_path_is_checked_like_a_connect(proxy):
    box = tempfile.mkdtemp(prefix="hlyn-guard-")
    sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sink.bind(f"{box}/log")
    out, _ = gated(f"""
        d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        attempt("sendto granted", lambda: str(d.sendto(b"hello", {box + '/log'!r})))
        attempt("sendto /dev/log", lambda: str(d.sendto(b"x", "/dev/log")))
    """, net=["example.com"], write=[box], read=[box], proxy=proxy)
    sink.settimeout(1)
    print("granted sink got:", sink.recv(100))
    got = lines(out)
    assert got["sendto granted"] == "5"
    assert got["sendto /dev/log"] == "EACCES"


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


RACE = os.path.join(ROOT, "tools", "hostlab", "race.c")


def _race_library() -> str:
    out = os.path.join(tempfile.mkdtemp(prefix="hlyn-race-"), "race.so")
    done = subprocess.run(["cc", "-O2", "-shared", "-fPIC", "-pthread", "-o", out, RACE],
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        pytest.skip(f"no C compiler for the race harness: {done.stderr[-300:]}")
    return out


@pytest.mark.skipif(not any(os.access(os.path.join(p, "cc"), os.X_OK)
                            for p in os.environ.get("PATH", "").split(":")), reason="needs cc")
def test_row_3_racing_the_address_never_connects_tcp_anywhere_but_the_proxy(proxy):
    """Threads rewrite the sockaddr while connect() waits for the gate, between
    the proxy and a listener on the same port at 127.0.0.2. The gate never
    lets a TCP connect run, so that listener must get nothing."""
    library = _race_library()
    iterations = int(os.environ.get("HLYN_RACE", "3000"))
    evil = socket.socket()
    evil.bind(("127.0.0.2", proxy.port))
    evil.listen(4096)
    evil.setblocking(False)
    good = int(ipaddress.IPv4Address("127.0.0.1")).to_bytes(4, "big")
    bad = int(ipaddress.IPv4Address("127.0.0.2")).to_bytes(4, "big")
    port = socket.htons(proxy.port)
    out, _ = gated(f"""
        out = (ctypes.c_int * 3)()
        began = __import__("time").monotonic()
        race.race_tcp(ctypes.c_uint32(int.from_bytes({good!r}, "little")), ctypes.c_uint16({port}),
                      ctypes.c_uint32(int.from_bytes({bad!r}, "little")), ctypes.c_uint16({port}),
                      {iterations}, 4, out)
        took = __import__("time").monotonic() - began
        print("connected", out[0], "refused", out[1], "other", out[2], f"in {{took:.1f}} s", flush=True)
    """, net=["example.com"], proxy=proxy, preload=f"race = ctypes.CDLL({library!r})", timeout=600)
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
    assert connected > 0 and refused > 0, "the flipping never landed on both addresses"
    assert all(seen[0] == "127.0.0.1" and seen[1] == proxy.port for seen in proxy.seen)


@pytest.mark.skipif(not any(os.access(os.path.join(p, "cc"), os.X_OK)
                            for p in os.environ.get("PATH", "").split(":")), reason="needs cc")
@pytest.mark.parametrize("where", ["inside", "outside"])
def test_row_3_unix_race(proxy, where):
    """The gate lets an allowed unix connect run, so a racing thread can turn
    it into a refused path after the check (5.3's residual).

    `inside`: the refused socket (docker.sock) sits in the write-granted
    folder. Landlock allows that whole folder, so no kernel closes this;
    measured, not asserted zero. `outside`: it sits in a folder no grant
    covers, the usual case (the resolver, D-Bus, the container runtime).
    From Landlock ABI 9 (Linux 7.1+) the kernel refuses it after the gate's
    check, so the race must be won zero times there (phase 6); before that
    it is measured. Both check that the check itself works."""
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
    out, _ = gated(f"""
        out = (ctypes.c_int * 3)()
        race.race_unix({allowed.encode()!r}, {refused.encode()!r}, 3000, 4, out)
        print("connected", out[0], "refused", out[1], "other", out[2], flush=True)
    """, net=["example.com"], write=[box], proxy=proxy, preload=f"race = ctypes.CDLL({library!r})",
       timeout=600)
    won = 0
    while True:
        try:
            servers[1].accept()[0].close()
            won += 1
        except OSError:
            break
    abi = landlock.abi()
    closed = where == "outside" and abi >= 9
    print(f"Landlock ABI {abi}, refused socket {where} the grant: races won {won} of 3000 "
          f"(reached {refused}); {'must be 0' if closed else 'measured'}")
    counts = out.split()
    assert int(counts[1]) > 0 and int(counts[3]) > 0
    if closed:
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


def test_hlyn_show_warns_when_a_write_grant_holds_a_refused_socket(docker_home):
    env = dict(os.environ, PYTHONPATH=SRC, HOME=str(docker_home))
    folder = str(docker_home / ".docker")
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "show", "--net", "pypi.org", "--write", folder],
                          capture_output=True, text=True, env=env, check=False)
    print(done.stderr)
    assert done.returncode == 0
    assert f"hlyn: --write {folder} covers {os.path.realpath(folder)}/run/docker.sock" in done.stderr
    assert "Grant a narrower folder unless you mean it." in done.stderr
    ports = subprocess.run([sys.executable, "-m", "hlyn.cli", "show", "--net", "443", "--write", folder],
                           capture_output=True, text=True, env=env, check=False)
    print("with ports:", repr(ports.stderr))
    assert "docker.sock" not in ports.stderr  # the gate's list is host mode's
