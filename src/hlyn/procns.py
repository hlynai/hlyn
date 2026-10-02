# SPDX-License-Identifier: Apache-2.0
"""Linux: a process view of its own for the command (`hlyn claude`).

Claude Code's runtime, and many npm tools, read /proc/self/{cgroup,statm,...}
in every process they start. Landlock grants paths, and /proc/PID is a new
path for every process, so no grant can give "my own" to each. The answer
every container tool uses (bubblewrap, nsjail, Docker): a pid namespace with
its own procfs. The command and what it starts then see /proc/<their pids>,
and nothing outside: not the process that started hlyn, not pid 1 of the
machine, not anyone's command line.

Three processes stand between hlyn and the command, made here before the seal
(the namespaces are made by hlyn, which is unconfined; the command's own
`unshare` stays refused):

    C  outside the namespace: waits, passes on signals, exits as the command did
    A  pid 1 inside: mounts procfs, reaps orphans, passes on signals
    B  the command (pid 2): seals itself and execs, as it did without this

The procfs is mounted `subset=pid`: only the per-process folders, none of
/proc/sys, /proc/net, /proc/meminfo (closed today, and still closed). A is
unconfined and holds hlyn's environment; the command can read A's command line
but not its environment (Landlock's ptrace scope, FINDINGS.md "hlyn claude").
When the namespaces can't be made (Docker's default profile, an AppArmor rule
against user namespaces, a kernel before 5.8) `contain` returns False and the
caller grants the command's own /proc/PID instead (`cli._own`).
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import resource
import signal
import struct
import sys
from typing import Any, NoReturn

# Whether this process is the command, inside the namespace.
inside = False

_NEWNS, _NEWUSER, _NEWPID = 0x00020000, 0x10000000, 0x20000000
_MS_NOSUID, _MS_NODEV, _MS_NOEXEC, _MS_REC, _MS_PRIVATE = 0x2, 0x4, 0x8, 0x4000, 0x40000
_PR_SET_PDEATHSIG = 1
_SI_KERNEL = 0x80  # what the terminal's own signals (Ctrl-C, Ctrl-Z, a resize) carry
_STOPS = {signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU}
# Signals a process can wait for: not the ones that report a fault in itself.
_CAUGHT = (set(range(1, 32)) - {signal.SIGKILL, signal.SIGSTOP, signal.SIGSEGV, signal.SIGBUS,
                                  signal.SIGFPE, signal.SIGILL})


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    return libc


def _fail(what: str) -> OSError:
    number = ctypes.get_errno()
    return OSError(number, f"{what}: {os.strerror(number)}")


def _unshare(libc: ctypes.CDLL) -> None:
    """Leave this process's pid and mount namespaces for new ones (its next
    child is pid 1 of the new pid namespace). Without the privilege for that,
    inside a user namespace that maps this user to itself."""
    if libc.unshare(_NEWNS | _NEWPID) == 0:
        return
    uid, gid = os.geteuid(), os.getegid()
    if libc.unshare(_NEWUSER | _NEWNS | _NEWPID) != 0:
        raise _fail("unshare")
    for name, text in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
        with open(f"/proc/self/{name}", "w", encoding="ascii") as fh:
            fh.write(text)


def _mount(libc: ctypes.CDLL) -> None:
    """In pid 1 of the new namespace: a procfs of its own on /proc."""
    if libc.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None) != 0:
        raise _fail("making the mounts private")
    if libc.mount(b"proc", b"/proc", b"proc", _MS_NOSUID | _MS_NODEV | _MS_NOEXEC, b"subset=pid") != 0:
        raise _fail("mounting /proc")


def possible() -> bool:
    """Whether `contain` can work here, found by trying it in a throwaway child."""
    if sys.platform != "linux":
        return False
    try:
        probe = os.fork()
    except OSError:
        return False
    if probe == 0:
        code = 1
        try:
            libc = _libc()
            _unshare(libc)
            inner = os.fork()
            if inner == 0:
                try:
                    _mount(libc)
                    os._exit(0)
                finally:
                    os._exit(1)
            code = 0 if os.waitpid(inner, 0)[1] == 0 else 1
        except BaseException:  # noqa: BLE001 - any failure means no
            code = 1
        finally:
            os._exit(code)
    return os.waitpid(probe, 0)[1] == 0


def contain() -> bool:
    """In the process that will seal and exec the command: start it in a pid
    namespace with its own /proc. Returns True in the command, with `inside`
    set. Returns False, having changed nothing, when that can't be done. The
    other two processes never return: they wait, and exit as the command did."""
    global inside
    if not possible():
        return False
    libc = _libc()
    before = signal.pthread_sigmask(signal.SIG_BLOCK, _CAUGHT)
    _unshare(libc)
    out_r, out_w = os.pipe()
    init = os.fork()
    if init == 0:
        code = 70
        try:
            os.close(out_r)
            libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)  # C gone: all of it goes
            _mount(libc)
            command = os.fork()
            if command == 0:
                os.close(out_w)
                signal.pthread_sigmask(signal.SIG_SETMASK, before)
                inside = True
                return True
            _hide()
            _be_init(command, out_w)
        except BaseException as exc:  # noqa: BLE001 - said, then pid 1 exits
            print(f"hlyn: can't set up the command's process view: {exc}", file=sys.stderr)
            code = 1
        os._exit(code)
    os.close(out_w)
    _wait(init, out_r)


def _hide() -> None:
    """Pid 1 is hlyn, holding hlyn's own command line and environment in its
    memory. The command can read /proc/1/cmdline (not its environment, which
    Landlock's ptrace scope refuses), so overwrite both where this process
    keeps them, found in /proc/self/stat (fields 48 to 51). If that fails they
    stay as they are."""
    with contextlib.suppress(OSError, ValueError, IndexError):
        with open("/proc/self/stat", encoding="ascii") as fh:
            rest = fh.read().rpartition(")")[2].split()
        arg_start, arg_end, env_start, env_end = (int(rest[n - 3]) for n in (48, 49, 50, 51))
        for start, end in ((arg_start, arg_end), (env_start, env_end)):
            if 0 < start < end:
                ctypes.memset(start, 0, end - start)


def _next(wanted: set[int]) -> Any:
    while True:
        try:
            return signal.sigwaitinfo(wanted)  # type: ignore[attr-defined,unused-ignore]
        except InterruptedError:
            continue


def _be_init(command: int, out: int) -> NoReturn:
    """Pid 1: reap what is orphaned, pass signals to the command, and hand its
    wait status to the outside when it exits. Never returns."""
    status = None
    while status is None:
        while True:
            try:
                got, found = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                got = 0
                status = 0 if status is None else status
            if not got:
                break
            if got == command:
                status = found
        if status is not None:
            break
        info = _next(_CAUGHT)
        # The terminal sent its signals to everyone in the group: the command
        # got its own. Another process's (a `kill`) comes only to this one.
        if info.si_signo != signal.SIGCHLD and info.si_code != _SI_KERNEL:
            with contextlib.suppress(ProcessLookupError):
                os.kill(command, info.si_signo)
    os.write(out, struct.pack("i", status))
    os._exit(0)


def _wait(init: int, said: int) -> NoReturn:
    """Outside: wait for pid 1, pass signals to it, and end as the command
    did. Never returns."""
    while True:
        try:
            got, found = os.waitpid(init, os.WNOHANG | os.WUNTRACED)
        except ChildProcessError:
            got, found = init, 1 << 8
        if got and not os.WIFSTOPPED(found):
            break
        info = _next(_CAUGHT)
        if info.si_signo == signal.SIGCHLD:
            continue
        if info.si_code == _SI_KERNEL:
            if info.si_signo in _STOPS:
                # Stop with the command, so the shell sees the job stop (the gate waits for it).
                os.kill(os.getpid(), signal.SIGSTOP)
            continue
        with contextlib.suppress(ProcessLookupError):
            os.kill(init, info.si_signo)
    told = os.read(said, 4)
    if len(told) == 4:
        found = struct.unpack("i", told)[0]
    if os.WIFEXITED(found):
        os._exit(os.WEXITSTATUS(found))
    death = os.WTERMSIG(found)
    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with contextlib.suppress(OSError, ValueError):
        signal.signal(death, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {death})
    os.kill(os.getpid(), death)
    os._exit(128 + death)


def grant(read: tuple[str, ...]) -> tuple[str, ...]:
    """`read` with what the command needs of /proc: all of it inside the
    namespace (only the namespace's processes are there), else its own pid."""
    return (*read, "/proc" if inside else f"/proc/{os.getpid()}")

