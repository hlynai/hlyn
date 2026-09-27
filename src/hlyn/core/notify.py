"""The kernel side of the Linux gate: seccomp notifications, read and answered.

DESIGN-host-allowlisting.md 5.3. In host mode the seccomp filter sends every
`connect()`, and every `sendto()` that names an address, to the gate instead
of running it. This module is the mechanism the gate uses to see and answer
them; `guard.py` decides. Nothing here decides anything.

- Receiving, answering and checking a notification go through libseccomp's
  notify API (2.5.0+), the same library `seccomp.py` builds the filter with.
- Installing a socket in the agent is one raw ioctl, `SECCOMP_IOCTL_NOTIF_ADDFD`
  with `SETFD` (Linux 5.9): libseccomp has no wrapper for it.
- What a socket is, where the agent's pointer points and what flags its
  descriptor has are read from `/proc`: the descriptor's inode from
  `/proc/PID/fd`, unix sockets from `/proc/PID/net/unix`, the address from
  `/proc/PID/mem`, flags from `/proc/PID/fdinfo`.

Every read of the agent's state must be followed by `valid()` before the
answer acts on it: the notification, and with it the pid, may have gone
(seccomp_unotify(2), NOTES). That check does not make the bytes race-free --
another thread can rewrite them -- which is why the gate never lets a TCP
connect continue (5.3, "why this is race-free").

Linux only. Standard library plus libseccomp.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import ipaddress
import os
import platform
import socket
import struct
from dataclasses import dataclass

from ..error import Failed
from . import seccomp

__all__ = [
    "Address",
    "Call",
    "Notice",
    "addfd",
    "answer",
    "cwd",
    "fdflags",
    "inode",
    "netlink",
    "read",
    "receive",
    "sockaddr",
    "tcp",
    "unix",
    "valid",
]

# `SECCOMP_USER_NOTIF_FLAG_CONTINUE`: let the call run as the agent made it.
# Only ever used where a race gains nothing (5.3's table).
CONTINUE = 1

# `SECCOMP_ADDFD_FLAG_SETFD`: install at the number given, replacing it.
SETFD = 1

# `SECCOMP_IOCTL_NOTIF_ADDFD`: _IOW('!', 3, struct seccomp_notif_addfd).
# The generic ioctl encoding, the same on x86_64 and aarch64.
ADDFD = (1 << 30) | (24 << 16) | (ord("!") << 8) | 3

# Pointers on aarch64 may carry a tag in the top byte (MTE, HWASan); the
# kernel ignores it, so the gate must too before seeking /proc/PID/mem.
UNTAG = (1 << 56) - 1 if platform.machine() in ("aarch64", "arm64") else (1 << 64) - 1

# Largest sockaddr the gate reads: sockaddr_storage.
MOST = 128


class Data(ctypes.Structure):
    """`struct seccomp_data`."""

    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("ip", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class Notif(ctypes.Structure):
    """`struct seccomp_notif`. libseccomp allocates it at the size the kernel
    reports, which may be larger; these are the fields every version has."""

    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", Data),
    ]


class Resp(ctypes.Structure):
    """`struct seccomp_notif_resp`."""

    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


@dataclass(frozen=True)
class Call:
    """One trapped system call, copied out of the kernel's notification.

    `pid` is the calling thread's id. `args` are the six register arguments,
    which the agent can't change once the call is made: only memory they
    point to can be rewritten under the gate.
    """

    id: int
    pid: int
    nr: int
    arch: int
    args: tuple[int, ...]


_ready = False


def _lib() -> ctypes.CDLL:
    """libseccomp, with the notify functions typed. Raises `Failed` if the
    installed version predates the notify API (2.5.0)."""
    global _ready
    api = seccomp.lib()
    if _ready:
        return api
    try:
        api.seccomp_notify_alloc.argtypes = [ctypes.POINTER(ctypes.POINTER(Notif)),
                                             ctypes.POINTER(ctypes.POINTER(Resp))]
        api.seccomp_notify_alloc.restype = ctypes.c_int
        api.seccomp_notify_free.argtypes = [ctypes.POINTER(Notif), ctypes.POINTER(Resp)]
        api.seccomp_notify_free.restype = None
        api.seccomp_notify_receive.argtypes = [ctypes.c_int, ctypes.POINTER(Notif)]
        api.seccomp_notify_receive.restype = ctypes.c_int
        api.seccomp_notify_respond.argtypes = [ctypes.c_int, ctypes.POINTER(Resp)]
        api.seccomp_notify_respond.restype = ctypes.c_int
        api.seccomp_notify_id_valid.argtypes = [ctypes.c_int, ctypes.c_uint64]
        api.seccomp_notify_id_valid.restype = ctypes.c_int
        api.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
        api.seccomp_notify_fd.restype = ctypes.c_int
    except AttributeError:
        raise Failed(
            "the installed libseccomp has no notify API, which --net hosts needs (libseccomp "
            "2.5.0 or newer). Upgrade libseccomp, or use ports (--net 443) or net=False."
        ) from None
    _ready = True
    return api


def ready() -> bool:
    """Whether libseccomp here has the notify API."""
    try:
        _lib()
    except Exception:  # noqa: BLE001 - any failure to load means "no"
        return False
    return True


def _sizes() -> tuple[int, int]:
    """The kernel's sizes of `struct seccomp_notif` and `seccomp_notif_resp`
    (`SECCOMP_GET_NOTIF_SIZES`), at least the fields this module knows."""
    got = (ctypes.c_uint16 * 3)()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    number = seccomp._nr("seccomp")
    if libc.syscall(ctypes.c_long(number), ctypes.c_long(3), ctypes.c_long(0), got) != 0:
        return ctypes.sizeof(Notif), ctypes.sizeof(Resp)
    return max(got[0], ctypes.sizeof(Notif)), max(got[1], ctypes.sizeof(Resp))


class Notice:
    """A reusable receive buffer for one notification descriptor.

    libseccomp sizes the buffers for this kernel; one pair serves every
    `receive()` and `answer()`. Not thread-safe: the gate is one loop.
    """

    def __init__(self, fd: int) -> None:
        self.fd = fd
        # The kernel refuses (EINVAL) a receive into a buffer that isn't all
        # zero, and libseccomp clears it only when allocating.
        self.size, _ = _sizes()
        api = _lib()
        self._req = ctypes.POINTER(Notif)()
        self._resp = ctypes.POINTER(Resp)()
        rc = api.seccomp_notify_alloc(ctypes.byref(self._req), ctypes.byref(self._resp))
        if rc != 0:
            raise Failed(f"libseccomp could not allocate notification buffers (error {-rc})")

    def close(self) -> None:
        if self._req:
            _lib().seccomp_notify_free(self._req, self._resp)
            self._req = ctypes.POINTER(Notif)()
            self._resp = ctypes.POINTER(Resp)()


def _errno(rc: int) -> int:
    """The kernel's errno behind a libseccomp failure. Its notify functions
    return -ECANCELED for any system failure and leave the ioctl's errno in
    place ("check the errno value", seccomp_notify_alloc(3))."""
    if rc == -errno.ECANCELED:
        return ctypes.get_errno() or errno.ECANCELED
    return -rc


def receive(notice: Notice) -> Call | None:
    """The next notification, or `None` if the call it was for has gone
    already (the thread was killed or interrupted before it was read).

    Blocks: call it when the descriptor polls readable. Raises `OSError`
    for anything else, such as the descriptor being closed.
    """
    ctypes.memset(notice._req, 0, notice.size)
    ctypes.set_errno(0)
    rc = _lib().seccomp_notify_receive(notice.fd, notice._req)
    if rc != 0:
        code = _errno(rc)
        if code in (errno.ENOENT, errno.EINTR):
            return None
        raise OSError(code, os.strerror(code))
    got = notice._req.contents
    return Call(int(got.id), int(got.pid), int(got.data.nr), int(got.data.arch),
                tuple(int(value) for value in got.data.args))


def answer(notice: Notice, call: Call, *, value: int = 0, error: int = 0, go: bool = False) -> bool:
    """Answer `call`: return `value`, fail with errno `error`, or (`go`) let
    it run as made. Returns False if the call has gone in the meantime."""
    resp = notice._resp.contents
    ctypes.memset(ctypes.addressof(resp), 0, ctypes.sizeof(Resp))
    resp.id = call.id
    if go:
        resp.flags = CONTINUE
    elif error:
        resp.error = -error
    else:
        resp.val = value
    ctypes.set_errno(0)
    rc = _lib().seccomp_notify_respond(notice.fd, notice._resp)
    if rc != 0:
        code = _errno(rc)
        if code in (errno.ENOENT, errno.EINTR):
            return False
        raise OSError(code, os.strerror(code))
    return True


def valid(fd: int, call: Call) -> bool:
    """Whether `call` is still waiting for an answer, so what was read about
    its thread describes that thread and not a reused pid."""
    return bool(_lib().seccomp_notify_id_valid(fd, call.id) == 0)


def addfd(fd: int, call: Call, source: int, target: int, cloexec: bool) -> None:
    """Install a copy of this process's descriptor `source` in the calling
    process at number `target`, replacing what was there.

    The agent's own thread does the install when the kernel wakes it, so a
    failure (the thread was interrupted or killed) raises `OSError` and
    installs nothing.
    """
    flags = os.O_CLOEXEC if cloexec else 0
    buf = bytearray(struct.pack("=QIIII", call.id, SETFD, source, target, flags))
    fcntl.ioctl(fd, ADDFD, buf, True)


# ---------------------------------------------------------------------------
# reading the agent's state from /proc
# ---------------------------------------------------------------------------


def inode(pid: int, fd: int) -> int | None:
    """The socket inode behind descriptor `fd` of thread `pid`, or `None` if
    it is not a socket (or gone). A read-level check: Yama doesn't limit it."""
    try:
        link = os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return None
    if not (link.startswith("socket:[") and link.endswith("]")):
        return None
    try:
        return int(link[8:-1])
    except ValueError:
        return None


def unix(pid: int) -> set[int]:
    """Inodes of every unix socket in thread `pid`'s network namespace,
    bound or not (measured: FINDINGS.md, "Host allowlisting groundwork").
    TCP sockets never appear here."""
    out: set[int] = set()
    try:
        with open(f"/proc/{pid}/net/unix", "rb") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 7:
                    try:
                        out.add(int(parts[6]))
                    except ValueError:
                        continue
    except OSError:
        pass
    return out


def netlink(pid: int) -> set[int]:
    """Inodes of every netlink socket in thread `pid`'s network namespace
    (the last column of /proc/PID/net/netlink)."""
    return _table(f"/proc/{pid}/net/netlink", -1)


def tcp(pid: int) -> set[int]:
    """Inodes of TCP sockets bound or connected in thread `pid`'s network
    namespace (IPv4 and IPv6). A socket the gate installed is connected, so
    one missing from here has been closed."""
    return _table(f"/proc/{pid}/net/tcp", 9) | _table(f"/proc/{pid}/net/tcp6", 9)


def _table(path: str, column: int) -> set[int]:
    out: set[int] = set()
    try:
        with open(path, "rb") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                try:
                    out.add(int(parts[column]))
                except (IndexError, ValueError):
                    continue
    except OSError:
        pass
    return out


def fdflags(pid: int, fd: int) -> int | None:
    """The open flags of descriptor `fd` of thread `pid`, from its fdinfo:
    `O_NONBLOCK` and `O_CLOEXEC` among them. `None` if unreadable."""
    try:
        with open(f"/proc/{pid}/fdinfo/{fd}", "rb") as fh:
            for line in fh:
                if line.startswith(b"flags:"):
                    return int(line.split()[1], 8)
    except (OSError, ValueError, IndexError):
        return None
    return None


def cwd(pid: int) -> str | None:
    """Thread `pid`'s working folder, for relative unix-socket paths."""
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def read(pid: int, where: int, size: int) -> bytes | None:
    """`size` bytes of thread `pid`'s memory at `where`, or `None` if the
    gate may not read it (Yama; reduced mode, 5.3) or the thread is gone.

    Needs ptrace-attach access, which the gate has as an ancestor of the
    agent (5.2). Call `valid()` afterwards before acting on the bytes."""
    if size <= 0:
        return b""
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        return os.pread(fd, min(size, MOST), where & UNTAG)
    except OSError:
        return None
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# the address the agent gave
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Address:
    """A sockaddr as the agent wrote it.

    `family` is the raw `sa_family`. For IP, `ip` and `port`; for unix,
    `path` (a filesystem path) or `abstract` (the name after the NUL), or
    neither for an unnamed address.
    """

    family: int
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    port: int | None = None
    path: str | None = None
    abstract: bytes | None = None


def sockaddr(data: bytes) -> Address | None:
    """Parse the bytes `read()` returned. `None` if they are too short for
    their family: the call is then refused (fail closed)."""
    if len(data) < 2:
        return None
    (family,) = struct.unpack_from("=H", data)
    if family == socket.AF_INET:
        if len(data) < 8:
            return None
        port = struct.unpack_from("!H", data, 2)[0]
        return Address(family, ipaddress.IPv4Address(data[4:8]), port)
    if family == socket.AF_INET6:
        if len(data) < 24:
            return None
        port = struct.unpack_from("!H", data, 2)[0]
        return Address(family, ipaddress.IPv6Address(data[8:24]), port)
    if family == socket.AF_UNIX:
        body = data[2:]
        if not body:
            return Address(family)  # unnamed (autobind on bind; nothing on connect)
        if body[0] == 0:
            return Address(family, abstract=body[1:])
        end = body.find(b"\0")
        raw = body if end < 0 else body[:end]
        return Address(family, path=os.fsdecode(raw))
    return Address(family)
