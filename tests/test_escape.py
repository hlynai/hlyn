# SPDX-License-Identifier: Apache-2.0
"""Escapes that worked, and must never work again.

Every test here corresponds to a hole that was real: written against a green
suite, found by attacking the thing rather than by testing it. They are kept
apart from the other escape tests because their value is historical as much as
technical -- each one is a shape of mistake the rest of the suite did not
catch, and the shape is the reusable part.

Two of them share a cause worth naming: a boundary that is enforced *somewhere*
was assumed to be enforced *everywhere*. `exec=True` was enforced per path and
not over the whole tree it resolved to; Landlock was enforced on the thread
that asked and not on the ones already running. A test that only ever checks
the intended case cannot see either.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot

pytestmark = pytest.mark.linux


if sys.platform != "linux":
    pytest.skip("Landlock is Linux-only", allow_module_level=True)


# ---------------------------------------------------------------------------
# `exec=True` and `write=True` used to grant read over the whole filesystem
# ---------------------------------------------------------------------------
#
# `_paths(True)` resolves a blanket grant to a rule on `/`, and the exec and
# write masks both carried ReadFile. So asking to run programs, or to write
# anywhere, silently made every file on the machine readable and every `read`
# list decorative. `hlyn.on("coder")` -- the first example in the README --
# could read /etc/shadow.


def test_allowing_any_program_does_not_grant_reading_everything():
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except PermissionError:
            print("refused")
        except OSError as exc:
            # Not a refusal. A missing file would otherwise read as one.
            print("INCONCLUSIVE", type(exc).__name__)
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_allowing_writing_anywhere_does_not_grant_reading_everything():
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], write=True, log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except PermissionError:
            print("refused")
        except OSError as exc:
            # Not a refusal. A missing file would otherwise read as one.
            print("INCONCLUSIVE", type(exc).__name__)
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_the_coder_preset_confines_the_filesystem():
    """The README's headline example. It read /etc/shadow."""
    done = boot(
        """
        import os, hlyn
        os.makedirs("/tmp/work", exist_ok=True)
        os.chdir("/tmp/work")
        hlyn.on("coder", log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except PermissionError:
            print("refused")
        except OSError as exc:
            # Not a refusal. A missing file would otherwise read as one.
            print("INCONCLUSIVE", type(exc).__name__)
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_allowing_any_program_still_runs_programs():
    """The other half. A fix that made exec=True unusable would be no fix."""
    done = boot(
        """
        import subprocess, hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        got = subprocess.run(["/bin/echo", "ran"], capture_output=True)
        print("ran" if got.returncode == 0 else f"BROKE rc={got.returncode}")
        """
    )
    assert "ran" in done.stdout, done.stdout + done.stderr


def test_a_named_program_is_readable_because_the_policy_says_so():
    """Naming a program in `exec` adds it to `read`, which is where it belongs.

    That is what makes dropping ReadFile from the exec mask a fix rather than a
    trade: the grant still exists, bounded and visible in `hlyn show`, instead
    of arriving invisibly over `/`.
    """
    done = boot(
        """
        import subprocess, hlyn
        open("/tmp/granted.txt", "w").write("hello")
        hlyn.on(read=["/tmp"], exec=["/bin/cat"], log=False)
        got = subprocess.run(["/bin/cat", "/tmp/granted.txt"], capture_output=True)
        print(f"cat rc={got.returncode} out={got.stdout!r}")
        """
    )
    assert "cat rc=0" in done.stdout, done.stdout + done.stderr
    assert "hello" in done.stdout, done.stdout


# ---------------------------------------------------------------------------
# threads that existed before the seal
# ---------------------------------------------------------------------------
#
# `landlock_restrict_self` applies to the calling thread, and credentials on
# Linux are per-task, so a thread already running keeps the access it had.
# seccomp has TSYNC and covers every thread; Landlock has no equivalent, so
# the filesystem and the port rules simply did not apply to it.


def test_sealing_a_process_with_another_thread_is_refused():
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        try:
            hlyn.on(read=["/tmp"], log=False)
            print("SEALED ANYWAY")
        except hlyn.Unsupported as exc:
            print("refused:", exc)
        """
    )
    assert "refused:" in done.stdout, done.stdout + done.stderr
    assert "threads" in done.stdout


def test_the_refusal_says_how_to_fix_it():
    """A refusal nobody can act on gets worked around rather than heeded."""
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        try:
            hlyn.on(log=False)
        except hlyn.Unsupported as exc:
            print(str(exc))
        """
    )
    assert "hlyn.run" in done.stdout, done.stdout
    assert "before anything starts a thread" in done.stdout, done.stdout


def test_a_single_threaded_process_still_seals():
    """The check must not fire on the ordinary case."""
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], log=False)
        print("sealed")
        """
    )
    assert "sealed" in done.stdout, done.stdout + done.stderr


def test_run_still_works_from_a_threaded_parent():
    """The documented way out: fork drops every thread but the caller's."""
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        def work():
            try:
                open("/etc/shadow").read()
                return "ESCAPED"
            except PermissionError:
                return "refused"
            except OSError as exc:
                return "INCONCLUSIVE " + type(exc).__name__
        print(hlyn.run(work, read=["/tmp"], log=False))
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_threads_started_after_sealing_are_confined():
    """The case that already worked, kept so a fix cannot trade one for the other."""
    done = boot(
        """
        import threading, hlyn
        hlyn.on(read=["/tmp"], log=False)
        out = []
        def work():
            try:
                open("/etc/shadow").read()
                out.append("ESCAPED")
            except PermissionError:
                out.append("refused")
            except OSError as exc:
                out.append("INCONCLUSIVE " + type(exc).__name__)
        t = threading.Thread(target=work)
        t.start()
        t.join()
        print(out[0])
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


# ---------------------------------------------------------------------------
# closing the network used to close local IPC with it
# ---------------------------------------------------------------------------
#
# `connect`, `bind`, `sendto` and friends carry no address family, so refusing
# them by syscall number to close the network refused them on AF_UNIX too. The
# old test only *created* an AF_UNIX socket and so never noticed; anything that
# actually used one -- multiprocessing, a local database, SysLogHandler -- was
# broken by `net=False`.


def test_a_unix_socket_still_connects_when_the_network_is_closed():
    done = boot(
        """
        import os, socket, time, hlyn
        os.makedirs("/tmp/ipc", exist_ok=True)
        s = "/tmp/ipc/s.sock"
        if os.path.exists(s): os.unlink(s)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(s); srv.listen(1)
        if os.fork() == 0:
            try:
                srv.settimeout(8); conn, _ = srv.accept(); conn.send(b"ok"); time.sleep(1)
            except Exception: pass
            os._exit(0)
        srv.close(); time.sleep(0.3)
        hlyn.on(read=["/tmp/ipc"], write=["/tmp/ipc"], net=False, log=False)
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.settimeout(5)
        try:
            c.connect(s); print("connected", c.recv(4), flush=True)
        except OSError as exc:
            print("BROKEN", type(exc).__name__, flush=True)
        os._exit(0)
        """
    )
    assert "connected" in done.stdout, done.stdout + done.stderr


def test_tcp_is_still_refused_when_the_network_is_closed():
    """The other half: local IPC working must not have reopened the network."""
    done = boot(
        """
        import socket, hlyn
        hlyn.on(read=["/tmp"], net=False, log=False)
        try:
            socket.socket().connect(("127.0.0.1", 80))
            print("ESCAPED")
        except PermissionError:
            print("refused")
        except OSError as exc:
            # ConnectionRefusedError means nothing was listening, which proves
            # nothing about the policy. Only PermissionError is the policy.
            print("INCONCLUSIVE", type(exc).__name__)
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr
    assert "ESCAPED" not in done.stdout


def test_looking_for_open_sockets_does_not_close_them():
    """The check for live connections used to close every socket it inspected.

    `socket.socket(fileno=...)` takes ownership of the descriptor, so the
    throwaway wrapper `wired` built to ask one question closed the socket on
    the way out -- AF_UNIX included, which is never reported and so was closed
    with nothing said. `net=False` is the default policy, so this ran on every
    plain `hlyn.on()`: the same local IPC breakage the syscall filter was fixed
    for, arriving one layer up. Freed descriptor numbers are then handed to the
    next `open`, which is the part that is worse than a broken socket.
    """
    done = boot(
        """
        import socket
        from hlyn.core.linux import wired

        near, far = socket.socketpair()      # AF_UNIX: never reported
        out = socket.socket()                # AF_INET: reported
        found = wired()

        print("reported", out.fileno() in found)
        try:
            near.send(b"x"); print("unix alive")
        except OSError as exc:
            print("UNIX CLOSED", type(exc).__name__)
        try:
            out.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE); print("inet alive")
        except OSError as exc:
            print("INET CLOSED", type(exc).__name__)
        """
    )
    assert "reported True" in done.stdout, f"wired() stopped finding sockets: {done.stdout}"
    assert "unix alive" in done.stdout, done.stdout + done.stderr
    assert "inet alive" in done.stdout, done.stdout + done.stderr


def test_sealing_with_a_network_socket_already_open_is_refused():
    """An open connection survives sealing: writing to it is an ordinary write.

    Nothing in the filter can tell that descriptor from a file, so the only
    honest answer is to refuse before the boundary is claimed.
    """
    done = boot(
        """
        import socket, hlyn
        s = socket.socket(); s.settimeout(1)
        try: s.connect(("127.0.0.1", 9))
        except OSError: pass
        try:
            hlyn.on(read=["/tmp"], net=False, log=False)
            print("SEALED ANYWAY")
        except hlyn.Unsupported as exc:
            print("refused:", exc)
        """
    )
    assert "refused:" in done.stdout, done.stdout + done.stderr
    assert "already open" in done.stdout


def test_a_socket_open_is_fine_when_the_network_is_not_closed():
    """The check must only fire when the policy actually claims a closed network."""
    done = boot(
        """
        import socket, hlyn
        s = socket.socket()
        hlyn.on(read=["/tmp"], net=True, log=False)
        print("sealed")
        """
    )
    assert "sealed" in done.stdout, done.stdout + done.stderr


def test_a_child_cannot_shed_the_boundary():
    """fork, exec, and a new session all inherit the domain."""
    done = boot(
        """
        import os, subprocess, sys, hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        code = ("try:\\n open('/etc/shadow').read(); print('ESCAPED')\\n"
                "except PermissionError: print('refused')\\n"
                "except OSError as e: print('INCONCLUSIVE', type(e).__name__)\\n")
        for argv in ([sys.executable, "-c", code],
                     ["/usr/bin/setsid", sys.executable, "-c", code]):
            got = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            print(argv[0].split("/")[-1], got.stdout.strip())
        """
    )
    assert "ESCAPED" not in done.stdout, done.stdout + done.stderr
    assert done.stdout.count("refused") == 2, done.stdout + done.stderr


# ---------------------------------------------------------------------------
# TCP Fast Open got past named ports
# ---------------------------------------------------------------------------
#
# Landlock's port rules check connect(). A send with MSG_FASTOPEN opens the
# connection itself, and Landlock only sees that from Linux 7.2 and 6.18.54
# (commit 33cb713db016). With `--net 443`, a Fast Open send reached a port the
# policy never named and delivered its data, while the report said the port
# was blocked. The test that only ever called connect() could not see it.

FAST_OPEN = """
    import os, socket, sys, hlyn
    r, w = os.pipe()
    if os.fork() == 0:
        # The listener, outside the environment: it reports whether anything arrived.
        lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lst.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 16)
        lst.bind(("127.0.0.1", 0)); lst.listen(4)
        os.write(w, str(lst.getsockname()[1]).encode()); os.close(w)
        lst.settimeout(3)
        try:
            conn, _ = lst.accept(); conn.settimeout(1)
            print("LISTENER GOT", conn.recv(64), flush=True)
        except OSError:
            print("listener got nothing", flush=True)
        os._exit(0)
    os.close(w); port = int(os.read(r, 16)); os.close(r)
    hlyn.on(read=["/tmp"], net=[443], log=False)
    dst = ("127.0.0.1", port)
    try:
        SEND
        print("SENT", flush=True)
    except PermissionError:
        print("refused", flush=True)
    except OSError as exc:
        print("INCONCLUSIVE", type(exc).__name__, exc, flush=True)
    os.wait()
"""


@pytest.mark.parametrize("send", [
    'socket.socket().sendto(b"leak", socket.MSG_FASTOPEN, dst)',
    'socket.socket().sendmsg([b"leak"], [], socket.MSG_FASTOPEN, dst)',
])
def test_tcp_fast_open_cannot_reach_a_port_the_policy_does_not_name(send):
    done = boot(FAST_OPEN.replace("SEND", send))
    assert "refused" in done.stdout, done.stdout + done.stderr
    assert "listener got nothing" in done.stdout, done.stdout + done.stderr
    assert "LISTENER GOT" not in done.stdout


def test_ordinary_sends_still_work_with_named_ports():
    """The refusal is on the Fast Open flag, not on sending: UDP and TCP sends are untouched."""
    done = boot(
        """
        import socket, hlyn
        hlyn.on(read=["/tmp"], net=[443], log=False)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("udp", u.sendto(b"x", ("127.0.0.1", 9)), flush=True)
        a, b = socket.socketpair()
        print("stream", a.send(b"x"), b.recv(1), flush=True)
        """
    )
    assert "udp 1" in done.stdout, done.stdout + done.stderr
    assert "stream 1 b'x'" in done.stdout, done.stdout + done.stderr


def test_mptcp_falls_back_to_tcp_with_named_ports():
    """MPTCP shares the Fast Open flaw. It is answered as a kernel without MPTCP would,
    so clients fall back to plain TCP, which Landlock checks."""
    done = boot(
        """
        import errno, socket, hlyn
        hlyn.on(read=["/tmp"], net=[443], log=False)
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
            print("CREATED")
        except OSError as exc:
            print("refused", errno.errorcode.get(exc.errno))
        """
    )
    assert "refused EPROTONOSUPPORT" in done.stdout, done.stdout + done.stderr


HIGH_BITS = """
    import ctypes, os, socket, hlyn
    from hlyn.core import seccomp
    libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
    r, w = os.pipe()
    if os.fork() == 0:
        # A UDP listener outside the environment: it reports whether anything arrived.
        lst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        lst.bind(("127.0.0.1", 0))
        os.write(w, str(lst.getsockname()[1]).encode()); os.close(w)
        lst.settimeout(3)
        try:
            print("LISTENER GOT", lst.recv(64), flush=True)
        except OSError:
            print("listener got nothing", flush=True)
        os._exit(0)
    os.close(w); port = int(os.read(r, 16)); os.close(r)
    nr = seccomp._nr("socket")
    hlyn.on(log=False)  # net=False
    fd = libc.syscall(ctypes.c_long(nr), ctypes.c_long((1 << 32) | socket.AF_INET),
                      ctypes.c_long(socket.SOCK_DGRAM), ctypes.c_long(0))
    if fd < 0:
        print("refused", os.strerror(ctypes.get_errno()), flush=True)
    else:
        print("CREATED fd", fd, flush=True)
        socket.socket(fileno=fd).sendto(b"leak", ("127.0.0.1", port))
    os.wait()
"""


def test_a_socket_family_with_high_bits_set_cannot_open_the_network():
    """The kernel reads socket()'s family as an int; the filter compared the whole
    register, so (1 << 32) | AF_INET made a UDP socket under net=False and sent
    from it (Landlock doesn't cover UDP on 6.12). Found 2026-09-27."""
    done = boot(HIGH_BITS)
    print(done.stdout, done.stderr[-500:])
    assert "refused Operation not permitted" in done.stdout, done.stdout + done.stderr
    assert "listener got nothing" in done.stdout, done.stdout + done.stderr
    assert "LISTENER GOT" not in done.stdout


FOREIGN = """
    import ctypes, mmap, os, platform, signal, hlyn
    hlyn.on(log=False)
    pid = os.fork()
    if pid == 0:
        CALL
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        print("KILLED by", signal.Signals(os.WTERMSIG(status)).name, flush=True)
    else:
        print("RAN, exit", os.WEXITSTATUS(status), flush=True)
"""

# mov eax, 26 (ia32 ptrace); xor ebx, ebx (PTRACE_TRACEME); int 0x80; ret
IA32 = """
buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
buf.write(bytes.fromhex("b81a00000031dbcd80c3"))
addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
ctypes.CFUNCTYPE(ctypes.c_long)(addr)()
"""
X32 = """
libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
libc.syscall(ctypes.c_long(0x40000000 | 521), ctypes.c_long(0))  # x32 ptrace(PTRACE_TRACEME)
"""
x86_64 = pytest.mark.skipif(
    __import__("platform").machine() not in ("x86_64", "amd64"),
    reason="ia32 and x32 are x86_64 syscall ABIs; run on real x86_64 (gap 8.4)",
)


@x86_64
@pytest.mark.parametrize("call", [IA32, X32], ids=["ia32 int 0x80", "x32"])
def test_a_refused_syscall_through_a_foreign_abi_never_runs(call):
    """Gap 8.4: nono GHSA-vhq2-h2q7-8mmc was an ia32 bypass. The filter is built for
    x86_64 (plus x32), so an int 0x80 call must hit the bad-architecture kill and an
    x32 ptrace the x32 copy of the rule. Simulated in tools/hostlab/bpfsim.py."""
    done = boot(FOREIGN.replace("CALL", call.replace("\n", "\n        ")))
    print(done.stdout, done.stderr[-500:])
    assert "KILLED by SIGSYS" in done.stdout, done.stdout + done.stderr
