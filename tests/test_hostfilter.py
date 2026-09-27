"""Host mode's kernel layers on Linux (DESIGN-host-allowlisting.md 5.3, layers 1 and 2).

A child seals itself with a policy that names hosts -- Landlock with no TCP
port allowed, and the seccomp filter with the socket allowlist and the notify
rules -- and hands its notification descriptor to this test process, which
answers the way a test needs: refuse, let the call run, or record it. The
gate's own decisions are tested in test_guard.py; this file checks what the
kernel does before and after the gate.

Matrix rows (section 9): 4 (UDP, raw, SCTP, MPTCP sockets), 5 (Fast Open),
24 (other families), 21 (a second listener), and layer 1: a TCP connect the
kernel runs is refused whatever its address. Every test prints what the
sealed program saw.
"""

from __future__ import annotations

import errno
import os
import select
import socket
import subprocess
import sys
import textwrap
import threading

import pytest
from conftest import SRC, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="seccomp and Landlock are Linux facilities"),
    pytest.mark.skipif(sys.platform == "linux" and not enforces(), reason="this kernel cannot seal"),
]

AGENT = textwrap.dedent(f"""
    import os, socket, sys
    sys.path.insert(0, {SRC!r})
    from hlyn.policy import Policy
    from hlyn.core import landlock, seccomp
    chan = socket.socket(fileno=int(sys.argv[1]))
    policy = Policy(net=["example.com", "localhost:5432"], exec=EXEC, read=[{SRC!r}])
    landlock.load(policy)
    fd = seccomp.load(policy)
    socket.send_fds(chan, [b"fd"], [fd])
    os.close(fd)
    assert chan.recv(1) == b"k"
    chan.close()
""")


def sealed(
    body: str, answer=None, timeout: float = 20, exec: bool = False
) -> tuple[subprocess.CompletedProcess, list]:
    """Run `body` in a child sealed for hosts; answer its notifications with
    `answer(call) -> dict(error=..)|dict(go=True)` (default: EACCES). Returns
    the child's result and the calls the gate saw."""
    from hlyn.core import notify

    ours, theirs = socket.socketpair()
    code = AGENT.replace("EXEC", repr(exec)) + textwrap.dedent(body)
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(theirs.fileno())],
        pass_fds=[theirs.fileno()], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    theirs.close()
    seen: list = []
    ours.settimeout(timeout)
    try:
        _, fds, _, _ = socket.recv_fds(ours, 16, 1)
    except (OSError, ValueError):
        fds = []
    if not fds:
        out, err = child.communicate(timeout=timeout)
        pytest.fail(f"the child never handed over a descriptor:\n{out}\n{err}")
    fd = fds[0]
    ours.send(b"k")
    notice = notify.Notice(fd)

    def serve() -> None:
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        while True:
            events = poll.poll(timeout * 1000)
            if not events or events[0][1] & (select.POLLHUP | select.POLLERR):
                return
            call = notify.receive(notice)
            if call is None:
                continue
            seen.append(call)
            how = answer(call) if answer else {"error": errno.EACCES}
            notify.answer(notice, call, **how)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    out, err = child.communicate(timeout=timeout)
    thread.join(timeout)
    notice.close()
    os.close(fd)
    ours.close()
    done = subprocess.CompletedProcess(child.args, child.returncode, out, err)
    print(out, err[-1500:])
    return done, seen


def test_ip_sockets_must_be_tcp_and_other_families_are_refused():
    """Rows 4 and 24: UDP, raw and seqpacket IP sockets are refused; SCTP,
    MPTCP and any other protocol get the answer of a kernel without them;
    TCP, unix and route netlink stay. A non-TCP IP socket goes to the gate,
    which refuses it (EPERM, as here) and reports it; every other refusal is
    the filter's own."""
    done, seen = sealed(answer=lambda call: {"error": errno.EPERM}, body="""
        import ctypes, errno
        libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
        tries = {
            "tcp": (2, 1, 0), "tcp proto 6": (2, 1, 6), "tcp nonblock": (2, 1 | 0o4000, 0),
            "udp": (2, 2, 0), "udp6": (10, 2, 0), "raw": (2, 3, 255), "seqpacket": (2, 5, 0),
            "sctp": (2, 1, 132), "mptcp": (2, 1, 262), "smc": (2, 1, 256), "proto 1": (2, 1, 1),
            "unix stream": (1, 1, 0), "unix dgram": (1, 2, 0), "netlink route": (16, 3, 0),
            "netlink audit": (16, 3, 9), "packet": (17, 3, 0), "rds": (21, 5, 0), "tipc": (30, 2, 0),
            "alg": (38, 5, 0), "xdp": (44, 3, 0),
        }
        for name, (family, kind, proto) in tries.items():
            try:
                socket.socket(family, kind, proto).close()
                print(name, "OK")
            except OSError as exc:
                print(name, errno.errorcode[exc.errno])
        # A protocol with upper bits set: the kernel reads only the low 32
        # (6, TCP), the filter compares the whole register.
        long = ctypes.c_long  # a bare int would reach syscall() as a 32-bit C int
        rc = libc.syscall(long(41), long(2), long(1), long((1 << 32) | 6))
        print("tcp proto (1<<32)|6", "OK" if rc >= 0 else errno.errorcode[ctypes.get_errno()])
    """)
    got = dict(line.rsplit(" ", 1) for line in done.stdout.splitlines())
    assert done.returncode == 0, done.stderr
    for ok in ("tcp", "tcp proto 6", "tcp nonblock", "unix stream", "unix dgram", "netlink route"):
        assert got[ok] == "OK", (ok, got[ok])
    for refused in ("udp", "seqpacket"):
        assert got[refused] == "EPERM", (refused, got[refused])
    # A raw socket with protocol 255 matches both the type rule (EPERM) and
    # the protocol rule (EPROTONOSUPPORT); both refuse, either may answer.
    assert got["raw"] in ("EPERM", "EPROTONOSUPPORT")
    assert got["udp6"] in ("EPERM", "EAFNOSUPPORT")  # no IPv6 at all on some machines
    for gone in ("sctp", "mptcp", "smc", "proto 1", "tcp proto (1<<32)|6"):
        assert got[gone] == "EPROTONOSUPPORT", (gone, got[gone])
    for family in ("netlink audit", "packet", "rds", "tipc", "alg", "xdp"):
        assert got[family] == "EPERM", (family, got[family])
    from hlyn.core import seccomp

    asked = [(call.args[0], call.args[1] & 0xF) for call in seen]
    print("the gate was asked about (family, type):", asked)
    assert all(nr == seccomp._nr("socket") for nr in (call.nr for call in seen))
    # The filter asks before the kernel checks the family, so udp6 comes
    # here even on a machine without IPv6.
    for family, kind in ((2, 2), (10, 2), (2, 5)):  # udp, udp6, seqpacket
        assert (family, kind) in asked, (family, kind)


def test_fast_open_is_refused_even_with_an_address_and_never_reaches_the_gate():
    """Row 5. Measured: a notify rule and an EPERM rule that both match can
    end with the notify rule winning; the rules are disjoint, so a Fast Open
    send with an address is refused by the filter itself."""
    done, seen = sealed("""
        import errno
        s = socket.socket()
        for name, send in (
            ("sendto(MSG_FASTOPEN, address)", lambda: s.sendto(b"x", 0x20000000, ("127.0.0.1", 9))),
            ("sendmsg(MSG_FASTOPEN, address)", lambda: s.sendmsg([b"x"], [], 0x20000000, ("127.0.0.1", 9))),
        ):
            try:
                send()
                print(name, "SENT")
            except OSError as exc:
                print(name, errno.errorcode[exc.errno])
    """)
    assert "sendto(MSG_FASTOPEN, address) EPERM" in done.stdout
    assert "sendmsg(MSG_FASTOPEN, address) EPERM" in done.stdout
    print("gate saw:", seen)
    assert seen == []


def test_every_connect_and_every_addressed_sendto_goes_to_the_gate():
    """Layer 3's input: connect() of any family, and sendto() naming an
    address. A send with no address never leaves the kernel."""
    done, seen = sealed("""
        import errno
        def attempt(name, fn):
            try:
                fn(); print(name, "OK")
            except OSError as exc:
                print(name, errno.errorcode[exc.errno])
        attempt("tcp connect", lambda: socket.socket().connect(("93.184.215.14", 443)))
        attempt("unix connect", lambda: socket.socket(socket.AF_UNIX).connect("/run/nothing.sock"))
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        attempt("send, no address", lambda: a.send(b"x"))
        datagram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        attempt("sendto a path", lambda: datagram.sendto(b"x", "/dev/log"))
    """)
    from hlyn.core import seccomp

    names = {seccomp._nr("connect"): "connect", seccomp._nr("sendto"): "sendto"}
    print("gate saw:", [names.get(call.nr, call.nr) for call in seen])
    assert "tcp connect EACCES" in done.stdout and "unix connect EACCES" in done.stdout
    assert "send, no address OK" in done.stdout and "sendto a path EACCES" in done.stdout
    assert [names.get(call.nr) for call in seen] == ["connect", "connect", "sendto"]


def test_a_tcp_connect_the_kernel_runs_is_refused_by_landlock_whatever_its_port():
    """Layer 1: Landlock allows no TCP port, so even a connect the gate lets
    run (which it never does for TCP) is refused, and so is bind. Covers the
    same-port bypass (row 2): nothing is open for another server to share."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(1)
    port = server.getsockname()[1]
    done, seen = sealed(f"""
        import errno
        for name, fn in (
            ("connect to a listener, let run", lambda: socket.socket().connect(("127.0.0.1", {port}))),
            ("connect to the listed port 5432, let run",
             lambda: socket.socket().connect(("127.0.0.1", 5432))),
            ("bind a port", lambda: socket.socket().bind(("127.0.0.1", 0))),
        ):
            try:
                fn(); print(name, "OK")
            except OSError as exc:
                print(name, errno.errorcode[exc.errno])
    """, answer=lambda call: {"go": True})
    try:
        conn, _ = server.accept()
        got = conn.recv(10)
        print("listener got a connection:", got)
        reached = True
    except OSError:
        reached = False
    print("listener reached:", reached, "| gate saw", len(seen), "calls")
    assert not reached
    assert "connect to a listener, let run EACCES" in done.stdout
    assert "connect to the listed port 5432, let run EACCES" in done.stdout
    assert "bind a port EACCES" in done.stdout


NESTED = textwrap.dedent(f"""
    import sys; sys.path.insert(0, {SRC!r})
    from hlyn.core import seccomp
    from hlyn.policy import Policy
    from hlyn.error import Unsupported
    print("busy()", seccomp.busy(), flush=True)
    try:
        seccomp.load(Policy(net=["example.com"]))
        print("load: sealed")
    except Unsupported as exc:
        print("load:", exc)
""")


def test_a_second_listener_is_refused_with_the_reason_and_what_to_use_instead():
    """Row 21: Linux allows one seccomp listener per filter chain. hlyn asks
    before sealing (`busy()`), and `load` names the fix if it gets EBUSY."""
    done, _ = sealed(f"""
        import subprocess
        subprocess.run([sys.executable, "-c", {NESTED!r}], check=False)
    """, exec=True)
    from hlyn.core import seccomp

    print("outside any listener, busy():", seccomp.busy())
    assert not seccomp.busy()
    assert "busy() True" in done.stdout
    assert "load: can't restrict hosts here" in done.stdout
    assert "Use ports (--net 443) or net=False" in done.stdout
