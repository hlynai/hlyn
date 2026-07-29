"""Syscall filtering, exercised against a real kernel.

Every test here that attempts an escape must fail the build if the escape
succeeds. A test that merely asserts "the filter loaded" proves nothing: the
question is whether the door is shut, and the only way to know is to push on it.
"""

from __future__ import annotations

import sys

import pytest

from conftest import jail, killed

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="seccomp is a Linux kernel facility"
)


# A raw syscall, bypassing any libc wrapper that might refuse on its own and
# make a blocked syscall look blocked when it never reached the kernel.
RAW = """
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def call(nr, *args):
    return libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
"""


# ---------------------------------------------------------------------------
# the filter must not break the interpreter it is protecting
# ---------------------------------------------------------------------------


def test_python_survives_the_filter():
    done = jail(
        """
        import json, ssl, socket, threading, subprocess, sqlite3, hashlib, uuid
        import tempfile, os, random, base64, asyncio
        with tempfile.NamedTemporaryFile("w+") as fh:
            fh.write("ok"); fh.flush(); fh.seek(0); assert fh.read() == "ok"
        assert hashlib.sha256(b"x").hexdigest()
        assert len(os.urandom(16)) == 16
        done = []
        t = threading.Thread(target=lambda: done.append(1)); t.start(); t.join()
        assert done == [1]
        print("ALIVE")
        """
    )
    assert done.returncode == 0, f"the filter broke Python:\n{done.stderr}"
    assert "ALIVE" in done.stdout


def test_threads_start_under_the_filter():
    # Thread creation goes through clone. The namespace-flag rules must not
    # catch an ordinary pthread, or every threaded agent dies on startup.
    done = jail(
        """
        import threading
        out = []
        ts = [threading.Thread(target=lambda i=i: out.append(i)) for i in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        assert sorted(out) == list(range(8)), out
        print("THREADS OK")
        """
    )
    assert done.returncode == 0, f"threading broke:\n{done.stderr}"
    assert "THREADS OK" in done.stdout


# ---------------------------------------------------------------------------
# the escapes
# ---------------------------------------------------------------------------


def test_io_uring_is_shut():
    # The one that matters most. io_uring submits work through a shared ring
    # instead of syscalls, so if this is reachable the entire filter is
    # decorative and every other test here is meaningless.
    done = jail(
        RAW + "\ncall(nr, 1, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('io_uring_setup')",
    )
    assert killed(done), f"io_uring was reachable: rc={done.returncode} {done.stdout}"


def test_io_uring_enter_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('io_uring_enter')",
    )
    assert killed(done), f"io_uring_enter was reachable: rc={done.returncode}"


def test_ptrace_is_shut():
    # Without this, one agent reads another agent's memory and the per-agent
    # isolation claim is false.
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('ptrace')",
    )
    assert killed(done), f"ptrace was reachable: rc={done.returncode}"


def test_process_vm_readv_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('process_vm_readv')",
    )
    assert killed(done), f"process_vm_readv was reachable: rc={done.returncode}"


def test_unshare_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0x10000000)\nprint('ESCAPED')",
        before="nr = seccomp._nr('unshare')",
    )
    assert killed(done), f"unshare was reachable: rc={done.returncode}"


def test_setns_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('setns')",
    )
    assert killed(done), f"setns was reachable: rc={done.returncode}"


def test_new_user_namespace_via_clone_is_shut():
    # unshare is not the only door to a namespace; clone takes the same flags.
    done = jail(
        RAW + "\ncall(nr, 0x10000000, 0, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('clone')",
    )
    assert killed(done), f"clone(CLONE_NEWUSER) was reachable: rc={done.returncode}"


def test_mount_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('mount')",
    )
    assert killed(done), f"mount was reachable: rc={done.returncode}"


def test_bpf_is_shut():
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('bpf')",
    )
    assert killed(done), f"bpf was reachable: rc={done.returncode}"


def test_open_by_handle_at_is_shut():
    # Opening by handle sidesteps path resolution, which is precisely the thing
    # Landlock checks.
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('open_by_handle_at')",
    )
    assert killed(done), f"open_by_handle_at was reachable: rc={done.returncode}"


def test_a_blocked_syscall_from_a_thread_is_shut():
    # TSYNC: without it the filter binds to the calling thread only, and an
    # agent escapes by doing its work on a second thread.
    # Written flush-left: this block is appended to RAW, which is already
    # flush-left, so a common-prefix dedent would strip nothing and the
    # interpreter would die of IndentationError before reaching the syscall.
    done = jail(
        RAW
        + "\n"
        + "import threading\n"
        + "def go():\n"
        + "    call(nr, 0, 0, 0, 0)\n"
        + "t = threading.Thread(target=go); t.start(); t.join()\n"
        + "print('ESCAPED')\n",
        before="nr = seccomp._nr('ptrace')",
    )
    assert killed(done), f"the filter did not cover threads: rc={done.returncode}"


# ---------------------------------------------------------------------------
# policy-driven denials
# ---------------------------------------------------------------------------


def test_network_is_refused_when_closed():
    done = jail(
        """
        import socket
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=False)",
    )
    assert done.returncode == 0, f"a TCP socket was created with net=False: {done.stdout}"
    assert "REFUSED" in done.stdout


def test_ipv6_is_refused_when_closed():
    done = jail(
        """
        import socket
        try:
            socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=False)",
    )
    assert done.returncode == 0, f"an IPv6 socket was created with net=False: {done.stdout}"


def test_denial_is_a_clean_error_not_a_kill():
    # A refused network call should leave the agent able to report what
    # happened, so the failure is legible instead of a mysterious death.
    done = jail(
        """
        import socket
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except PermissionError as exc:
            print("errno", exc.errno); raise SystemExit(0)
        raise SystemExit(1)
        """,
        policy="Policy(net=False)",
    )
    assert done.returncode == 0
    assert "errno 1" in done.stdout  # EPERM


def test_network_is_available_when_open():
    # The filter must be selective. If net=True still refused sockets, the
    # denial above would prove nothing.
    done = jail(
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()
        print("OPEN")
        """,
        policy="Policy(net=True)",
    )
    assert done.returncode == 0, f"net=True still refused a socket:\n{done.stderr}"
    assert "OPEN" in done.stdout


def test_unix_sockets_survive_a_closed_network():
    # AF_UNIX never leaves the machine. Refusing it would break multiprocessing
    # and much of the stdlib for no security gain.
    done = jail(
        """
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.close()
        print("UNIX OK")
        """,
        policy="Policy(net=False)",
    )
    assert done.returncode == 0, f"AF_UNIX was refused:\n{done.stderr}"


def test_exec_is_refused_when_closed():
    done = jail(
        """
        import os
        try:
            os.execv("/bin/sh", ["/bin/sh", "-c", "echo ESCAPED"])
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        raise SystemExit(1)
        """,
        policy="Policy(exec=False)",
    )
    assert done.returncode == 0, f"exec succeeded with exec=False: {done.stdout}"
    assert "ESCAPED" not in done.stdout


def test_subprocess_is_refused_when_exec_is_closed():
    done = jail(
        """
        import subprocess
        try:
            subprocess.run(["/bin/echo", "ESCAPED"], capture_output=True)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        raise SystemExit(1)
        """,
        policy="Policy(exec=False)",
    )
    assert done.returncode == 0, f"subprocess ran with exec=False: {done.stdout}"
    assert "ESCAPED" not in done.stdout


# ---------------------------------------------------------------------------
# the list itself
# ---------------------------------------------------------------------------


def test_shut_list_resolves_on_this_architecture():
    # A typo in a syscall name is silently skipped by design, since some
    # syscalls genuinely do not exist per architecture. That tolerance would
    # also hide a misspelling and leave a door open, so the load-bearing names
    # are pinned here.
    from hlyn.core import seccomp

    must = [
        "io_uring_setup", "io_uring_enter", "io_uring_register", "ptrace",
        "process_vm_readv", "process_vm_writev", "mount", "umount2", "unshare",
        "setns", "bpf", "perf_event_open", "init_module", "finit_module",
        "open_by_handle_at", "name_to_handle_at", "pivot_root", "chroot",
        "userfaultfd", "keyctl", "add_key", "request_key", "kexec_load",
    ]
    missing = [name for name in must if seccomp._nr(name) == seccomp.BAD]
    assert not missing, f"these syscalls did not resolve, so they are not blocked: {missing}"


def test_every_shut_syscall_has_a_reason():
    from hlyn.core import seccomp

    for name in seccomp.SHUT:
        assert seccomp.why(name), f"{name} is blocked without a stated reason"
