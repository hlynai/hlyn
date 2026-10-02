# SPDX-License-Identifier: Apache-2.0
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


def test_io_uring_is_refused_as_missing():
    # The one that matters most. io_uring submits work through a shared ring
    # instead of syscalls, so if this is reachable the entire filter is
    # decorative. It is refused the way a kernel without io_uring refuses it
    # (ENOSYS), not by killing: libuv, and so Node and npm, try it at startup
    # and fall back when it fails (FINDINGS.md, "Checking the eight
    # decisions"). All three calls, and the program goes on.
    done = jail(
        RAW
        + """
import errno
for name, nr, args in calls:
    rc = call(nr, *args)
    print(name, rc, errno.errorcode.get(ctypes.get_errno()))
print("WENT ON")
""",
        before=(
            "calls = [(n, seccomp._nr(n), a) for n, a in (('io_uring_setup', (8, 0)), "
            "('io_uring_enter', (0, 1, 0, 0)), ('io_uring_register', (0, 0, 0, 0)))]"
        ),
    )
    print(done.stdout, done.stderr)
    assert not killed(done), "io_uring killed the process instead of failing like a missing call"
    for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
        assert f"{name} -1 ENOSYS" in done.stdout, f"{name} was not refused as missing"
    assert "WENT ON" in done.stdout


def test_a_program_that_probes_io_uring_falls_back():
    # What libuv does: ask for a ring, and on any failure use plain calls.
    done = jail(
        RAW
        + """
ring = call(nr, 8, ctypes.addressof(ctypes.create_string_buffer(120)))
print("ring", ring)
if ring < 0:
    import os
    with open(os.__file__) as fh:  # the runtime is always readable
        print("fell back, read", len(fh.read()) > 0)
""",
        before="nr = seccomp._nr('io_uring_setup')",
    )
    print(done.stdout, done.stderr)
    assert "ring -1" in done.stdout and "fell back, read True" in done.stdout


def test_sysv_ipc_is_refused_not_killed():
    # SysV objects are named by a number, so Landlock never sees them, and a
    # confined program read another process's segment and queue (FINDINGS.md,
    # "a confined program reaches SysV shared memory"). All twelve calls are
    # refused with EPERM and the program goes on. The arguments are ones the
    # kernel itself answers with EINVAL or ENOENT, never EPERM: the unconfined
    # run shows that, so an EPERM here can only be the filter.
    code = RAW + """
import errno
for name, nr in calls:
    rc = call(nr, -1, 0, 0, 0, 0)
    print(name, rc, errno.errorcode.get(ctypes.get_errno()))
print("WENT ON")
"""
    before = "calls = [(n, seccomp._nr(n)) for n in seccomp.SHARED]"
    control = jail(code, before=before, seal="")
    done = jail(code, before=before)
    print("unconfined:\n" + control.stdout + control.stderr)
    print("confined:\n" + done.stdout + done.stderr)
    from hlyn.core import seccomp

    assert len(seccomp.SHARED) == 12
    for name in seccomp.SHARED:
        assert f"{name} -1 EPERM" not in control.stdout, f"{name}: the kernel says EPERM by itself"
        assert f"{name} -1 EPERM" in done.stdout, f"{name} was not refused"
    assert not killed(done) and "WENT ON" in done.stdout


def test_typing_into_the_terminal_is_refused():
    # TIOCSTI pushes bytes into a terminal's input, where the user's shell
    # reads them after the agent exits. The terminal here is a fresh pty made
    # the process's own controlling terminal (TIOCSTI needs that), in raw mode
    # so a single byte is readable. The second request has high bits set,
    # which the kernel ignores (CVE-2019-10063). Unconfined, both land.
    code = RAW + """
import errno, os
for request in (0x5412, 0xdead00005412):
    byte = ctypes.c_char(b'Z')
    rc = call(nr, term, request, ctypes.addressof(byte))
    print(hex(request), rc, errno.errorcode.get(ctypes.get_errno()) if rc < 0 else 'accepted')
os.set_blocking(term, False)
try:
    print('input now', os.read(term, 16))
except BlockingIOError:
    print('input now empty')
"""
    before = """
import os, tty
os.setsid()
mine, theirs = os.openpty()
term = os.open(os.ttyname(theirs), os.O_RDWR)  # the controlling terminal now
tty.setraw(term)
nr = seccomp._nr('ioctl')
"""
    control = jail(code, before=before, seal="")
    done = jail(code, before=before)
    print("unconfined:\n" + control.stdout + control.stderr)
    print("confined:\n" + done.stdout + done.stderr)
    # Newer kernels (Ubuntu's 6.17 on GitHub's runner, measured) refuse TIOCSTI to an
    # unprivileged process by themselves, with EIO (`dev.tty.legacy_tiocsti` = 0).
    # Then the control can't show a landing, but hlyn's own answer is still told
    # apart from the kernel's: EPERM comes from the filter, EIO from the kernel.
    if "0x5412 -1 EIO" in control.stdout:
        assert "0xdead00005412 -1 EIO" in control.stdout and "input now empty" in control.stdout
    else:
        assert "0x5412 0 accepted" in control.stdout and "input now b'ZZ'" in control.stdout
    assert "0x5412 -1 EPERM" in done.stdout
    assert "0xdead00005412 -1 EPERM" in done.stdout
    assert "input now empty" in done.stdout and not killed(done)


def test_a_syscall_from_the_wrong_architecture_kills_the_whole_process():
    # libseccomp's default for a call made through another architecture's
    # convention (ia32's int 0x80 on x86_64) is KILL_THREAD, which seccomp(2)
    # says "is likely to leave the process in a permanently inconsistent and
    # possibly corrupt state". hlyn asks for KILL_PROCESS. Read from the
    # compiled filter, since only an x86_64 kernel with ia32 support can make
    # the call (test_escape.py's foreign-ABI test does, there).
    import struct

    from hlyn.core import seccomp
    from hlyn.policy import Policy

    code = seccomp.program(Policy())
    rets = {k for op, _, _, k in struct.iter_unpack("=HBBI", code) if op == 0x06}
    print("return values in the filter:", sorted(hex(k) for k in rets))
    assert seccomp.KILL in rets
    assert 0x00000000 not in rets, "some path in the filter kills only the thread (KILL_THREAD)"


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


# ---------------------------------------------------------------------------
# routes around Landlock rather than through it
# ---------------------------------------------------------------------------
#
# Landlock decides whether a path may be opened. Everything below reaches a
# file, a program, or the outside world without resolving a path at all, so
# Landlock never sees it and only the syscall filter can refuse it.


def test_stealing_a_descriptor_from_another_process_is_shut():
    # pidfd_getfd lifts an already-open descriptor out of another process.
    # Landlock governs opening a path, not using a descriptor that is already
    # open, so a sibling holding a secret file open would hand over the whole
    # filesystem boundary without a path ever being resolved.
    done = jail(
        RAW + "\ncall(nr, 0, 0, 0)\nprint('ESCAPED')",
        before="nr = seccomp._nr('pidfd_getfd')",
    )
    assert killed(done), f"pidfd_getfd was reachable: rc={done.returncode}"


def test_running_a_program_with_no_path_is_shut():
    # The fileless exec: write a program into anonymous memory, then run it
    # straight from the descriptor. There is no path, so an exec allowlist --
    # which Landlock enforces per path -- has nothing to match against.
    done = jail(
        RAW + """
import os
fd = os.memfd_create("payload")
os.write(fd, open("/bin/true", "rb").read())
call(nr, fd, empty, 0, 0, 0x1000)
print('ESCAPED')
""",
        before=(
            "nr = seccomp._nr('execveat')\n"
            "import ctypes\n"
            "empty = ctypes.cast(ctypes.create_string_buffer(b''), ctypes.c_void_p).value"
        ),
        policy="Policy(exec=['/bin/true'])",
    )
    assert killed(done), f"a program with no path ran: rc={done.returncode} {done.stdout}"


def test_ordinary_execveat_still_works():
    # The block is on one flag, not on the syscall. Refusing execveat outright
    # would break every launcher that uses it in its ordinary form, so the same
    # syscall is called here with a real path and no AT_EMPTY_PATH, and must
    # run the program.
    done = jail(
        RAW + """
import ctypes, os
path = ctypes.create_string_buffer(b"/bin/true")
argv = (ctypes.c_char_p * 2)(ctypes.cast(path, ctypes.c_char_p), None)
envp = (ctypes.c_char_p * 1)(None)
AT_FDCWD = -100

pid = os.fork()
if pid == 0:
    call(nr, AT_FDCWD, ctypes.addressof(path),
         ctypes.addressof(argv), ctypes.addressof(envp), 0)
    os._exit(3)  # only reached if execveat refused to run it
_, status = os.waitpid(pid, 0)
print("RAN" if status == 0 else f"REFUSED {status}")
""",
        before="nr = seccomp._nr('execveat')",
        policy="Policy(exec=['/bin/true'], read=['/bin'])",
    )
    assert "RAN" in done.stdout, f"an ordinary execveat was refused: {done.stdout} {done.stderr}"


@pytest.mark.parametrize(("domain", "what"), [(40, "vsock"), (31, "bluetooth")])
def test_a_domain_outside_the_network_policy_is_shut(domain, what):
    # AF_VSOCK talks to the host rather than to the network, so `net` does not
    # describe it; AF_BLUETOOTH likewise. Both are refused whatever `net` says.
    #
    # The socket is created once before sealing. Without that, a kernel that
    # refuses the domain for its own reasons -- no vsock device, no bluetooth
    # stack -- makes this test pass while proving nothing, which is exactly
    # what it did before the check was added.
    done = jail(
        f"""
        if not open_before:
            print("UNAVAILABLE"); raise SystemExit(0)
        try:
            socket.socket({domain}, socket.SOCK_STREAM)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        before=f"""
import socket
try:
    socket.socket({domain}, socket.SOCK_STREAM).close()
    open_before = True
except OSError:
    open_before = False
""",
        policy="Policy(net=True)",
    )
    if "UNAVAILABLE" in done.stdout:
        pytest.skip(f"this kernel has no {what} support, so there is nothing to refuse")
    assert "REFUSED" in done.stdout, f"{what} was reachable: {done.stdout}"


# Every family `net` doesn't describe, plus values past the last one Linux
# defines and a valid family hidden under garbage in the upper 32 bits (the
# filter compares the whole register; the kernel reads only the low half).
FAMILIES = """
import ctypes, errno, socket
ours = []
for domain in [d for d in range(46) if d not in (1, 2, 10, 16)] + [46, 255, (1 << 32) | 2, (1 << 32) | 29]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET, socket.SOCK_RAW):
        fd = call(NR, domain, kind, 0)
        err = ctypes.get_errno()
        if fd >= 0:
            import os; os.close(fd)
            print(f"family {domain:#x} type {kind}: CREATED")
            break
        if err != errno.EPERM:
            print(f"family {domain:#x} type {kind}: {errno.errorcode[err]}")
            break
    else:
        ours.append(domain)
print("EPERM from the filter for", len(ours), "families:", [hex(d) for d in ours])
"""


@pytest.mark.parametrize("net", ["False", "[443]", "True"])
def test_every_family_net_does_not_describe_is_refused(net):
    # Gap 8.7: a denylist refused IP, packet, VSOCK and Bluetooth and left RDS,
    # TIPC, XDP, ALG, CAN, PF_KEY and the rest to the kernel. EPERM for every
    # type is the filter's answer; a kernel without the family says
    # EAFNOSUPPORT instead, so this can't pass by the family simply being
    # absent. The line printed for each escape shows what the kernel said.
    done = jail(
        RAW + FAMILIES,
        before="NR = seccomp._nr('socket')",
        policy=f"Policy(net={net})",
    )
    print(done.stdout, done.stderr[-500:])
    escaped = [line for line in done.stdout.splitlines() if line.startswith("family ")]
    assert "EPERM from the filter for 46 families" in done.stdout, (
        f"families the filter left to the kernel under net={net}: {escaped}"
    )


@pytest.mark.parametrize("net", ["False", "[443]"])
def test_the_allowed_families_still_work(net):
    # Unix sockets and route netlink (getifaddrs) must survive every mode;
    # socketpair is how multiprocessing and asyncio talk to themselves.
    done = jail(
        """
        import socket
        a, b = socket.socketpair()
        a.sendall(b"ping"); print("socketpair:", b.recv(4))
        socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).close(); print("unix dgram: ok")
        print("interfaces:", [name for _, name in socket.if_nameindex()])
        socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0).close(); print("route netlink: ok")
        """,
        policy=f"Policy(net={net})",
    )
    print(done.stdout, done.stderr[-500:])
    assert "socketpair: b'ping'" in done.stdout
    assert "unix dgram: ok" in done.stdout
    assert "route netlink: ok" in done.stdout
    assert "lo" in done.stdout


def test_kernel_subsystems_over_netlink_are_shut():
    # Netlink reaches kernel subsystems rather than the network. Protocol 0 is
    # the exception and has its own test below.
    done = jail(
        """
        import socket
        try:
            socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9)  # NETLINK_AUDIT
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=True)",
    )
    assert "REFUSED" in done.stdout, f"a netlink subsystem was reachable: {done.stdout}"


def test_interface_enumeration_still_works():
    # NETLINK_ROUTE is how getifaddrs(3) enumerates interfaces, and Python,
    # Node, Go and most HTTP clients call it while starting up. Refusing it
    # would break the agent before it ran.
    done = jail(
        """
        import socket
        socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0).close()  # NETLINK_ROUTE
        print("OK")
        """,
        policy="Policy(net=True)",
    )
    assert "OK" in done.stdout, f"NETLINK_ROUTE was refused, which breaks startup: {done.stderr}"


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
        *seccomp.SHARED,
    ]
    missing = [name for name in must if seccomp._nr(name) == seccomp.BAD]
    assert not missing, f"these syscalls did not resolve, so they are not blocked: {missing}"


def test_every_shut_syscall_has_a_reason():
    from hlyn.core import seccomp

    for name in seccomp.SHUT:
        assert seccomp.why(name), f"{name} is blocked without a stated reason"
