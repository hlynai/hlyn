# SPDX-License-Identifier: Apache-2.0
"""The Linux gate's decisions: every trapped connect, answered without the race.

DESIGN-host-allowlisting.md 5.3, layer 3. In host mode the seccomp filter
sends each `connect()`, and each `sendto()` that names an address, to the
gate. `Guard` answers them from one loop:

| The gate sees                                         | It does                      |
|-------------------------------------------------------|------------------------------|
| a socket it installed earlier                         | `EISCONN`, as the kernel would |
| TCP to the proxy (127.0.0.1:P, [::1]:P, mapped)        | swap, answer 0               |
| TCP to an address the policy lists (IP, CIDR, localhost) | swap, wait for the proxy's verdict, answer it |
| TCP anywhere else                                     | `EACCES`                     |
| an IP socket other than TCP (UDP: a name lookup)       | `EPERM`, and say so          |
| unix connect, path in a write-granted folder, not refused | pinned swap                |
| unix path anywhere else, or on the refused list        | `EACCES`                     |
| unix `sendto` naming a path                            | `EACCES`                     |
| unix abstract or unnamed, `AF_UNSPEC`, netlink         | let it run                   |
| anything unreadable or unknown                        | `EACCES` (fail closed)       |

A *swap* is the gate opening its own connection to the proxy, writing the
PROXY v2 header naming what the agent dialled, and installing that socket at
the agent's descriptor number (`notify.addfd`). A TCP connect is never let
run: if another thread rewrites the address after the gate read it, the only
effect is which row applied, and the proxy re-checks every claim.

A *pinned swap* does the same for a unix socket: the gate opens the socket
file it checked with no symlink allowed on the way (`notify.pin`), checks
that object (a socket; not one of the refused sockets, by inode, so a hard
link under another name is refused too), connects a new socket of the
agent's type to it through `/proc/self/fd/N`, and installs that. The agent's
own call never runs, so neither a racing thread nor a folder swapped for a
symlink after the check reaches anything else (CVE-2026-79994's pattern;
FINDINGS.md, "Checking the eight decisions"). What it costs: the listener
sees the gate as the connecting process (same user), options set before
`connect` are lost, and a socket bound before connecting is refused (its
address would be lost). The rows that still let a call run are disconnects,
abstract names (Landlock's scope applies) and route netlink; a race that
turns one into a TCP connect meets Landlock's zero TCP ports.

**Reduced mode**: when the gate may not read the agent's memory (Yama
`ptrace_scope` 2 or 3, or a child of `hlyn.on()` at 1), it still knows the
socket from its inode. TCP is swapped into the proxy with a header saying
"destination unknown", so proxy-aware clients work; unix is refused.

Nothing here parses anything but fixed-layout kernel structures and sockaddrs.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import json
import os
import re
import select
import shlex
import socket
import stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .. import hosts
from ..hosts import Rule
from ..wire import header
from . import notify, seccomp

# `typing` itself costs a helper's start ~5 ms, and every use here is an
# annotation; mypy reads this flag as it reads typing's.
TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Literal

__all__ = ["REFUSED", "Config", "Guard"]

# Unix sockets never reachable in host mode, whatever folders are granted:
# the program behind each acts for its caller on the network or the machine
# (5.3). Regexes over the path, checked as written and resolved.
# The resolvers: a lookup through nss-resolve goes to systemd-resolved over
# Varlink and never touches UDP port 53; nscd queries DNS for its caller
# (FINDINGS.md, gap 8.2). A refusal here is a name lookup, and says so.
RESOLVERS: tuple[str, ...] = (
    r"^/run/systemd/resolve/",
    r"^/(var/)?run/nscd/",
)
REFUSED: tuple[str, ...] = (
    *RESOLVERS,
    # The D-Bus buses: systemd-resolved answers lookups over D-Bus too.
    r"^/(var/)?run/dbus/system_bus_socket$",
    r"^/run/user/[^/]+/bus$",
    # Container runtimes: an agent that reaches one controls the machine.
    r"/(docker|containerd|podman|crio)[^/]*\.sock$",
)
_REFUSED = tuple(re.compile(pattern) for pattern in REFUSED)

# Where the refused sockets live on common Linux systems, for `granted`.
PLACES: tuple[str, ...] = (
    "/run/systemd/resolve/*",
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/run/dbus/system_bus_socket",
    "/run/user/*/bus",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/user/*/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "/run/user/*/podman/podman.sock",
    "/run/crio/crio.sock",
    "~/.docker/run/docker.sock",
)


def granted(writes: tuple[str, ...] | bool) -> list[str]:
    """Refused sockets that exist here and sit under a write grant.

    The gate checks a unix connect's path and lets it run (5.3), so a program
    racing threads can swap in another path after the check. Outside the
    write grants, Landlock refuses that on Linux 7.1+; inside one, nothing
    does, on any kernel. A grant such as `--write /run` therefore leaves the
    resolver, D-Bus or a container runtime one lost race away.
    """
    import glob

    if not writes:
        return []
    roots = None if isinstance(writes, bool) else [os.path.realpath(item) for item in writes]
    out = []
    for place in PLACES:
        for found in glob.glob(os.path.expanduser(place)):
            real = os.path.realpath(found)
            try:
                if not stat.S_ISSOCK(os.stat(real).st_mode):
                    continue
            except OSError:
                continue  # gone since the glob
            if not any(pattern.search(item) for pattern in _REFUSED for item in (found, real)):
                continue
            if roots is None or any(real == root or real.startswith(root.rstrip("/") + "/")
                                    for root in roots):
                out.append(real)
    return sorted(set(out))

# MSG_FASTOPEN. The filter refuses it; the gate checks the register again.
FASTOPEN = 0x20000000

# How many installed sockets to remember before dropping closed ones.
REMEMBER = 4096

# How long past the proxy's connect timeout the gate waits for a verdict.
SLACK = 2.0

# How long the gate waits on a unix listener whose queue is full, for an
# agent socket that blocks (a non-blocking one gets EAGAIN at once). The
# gate answers everyone from one loop, so this is short.
QUEUED = 1.0

# How long the inodes of the refused sockets found here are trusted.
FRESH = 1.0

_LOOPBACK = (ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv6Address("::1"))


@dataclass
class Config:
    """What the gate needs to know about the run. Sent by the sealed process
    with the notification descriptor, before any agent code runs.

    `port` is the proxy's port for this run; `rules` the policy's host
    entries; `writes` the folders granted for write (`True`: everything);
    `connect` the proxy's connect timeout; `reduced` forces reduced mode
    (tests, and a gate that knows it can't read)."""

    port: int
    rules: tuple[Rule, ...]
    writes: tuple[str, ...] | Literal[True] = ()
    connect: float = 10.0
    reduced: bool = False

    def dumps(self) -> bytes:
        return json.dumps({
            "port": self.port,
            "rules": [str(rule) for rule in self.rules],
            "writes": self.writes if self.writes is True else list(self.writes),
            "connect": self.connect,
            "reduced": self.reduced,
        }).encode()

    @classmethod
    def loads(cls, data: bytes) -> Config:
        raw = json.loads(data)
        writes = raw.get("writes", [])
        return cls(
            port=int(raw["port"]),
            rules=tuple(hosts.parse(item) for item in raw["rules"]),
            writes=True if writes is True else tuple(str(item) for item in writes),
            connect=float(raw.get("connect", 10.0)),
            reduced=bool(raw.get("reduced", False)),
        )


@dataclass
class _Wait:
    """A direct connection waiting for the proxy's verdict byte (5.3)."""

    call: notify.Call
    sock: socket.socket
    target: int
    cloexec: bool
    until: float
    shown: str


@dataclass
class Guard:
    """Answers the notifications on `fd` until every task using the filter
    has exited. `tell(event)` receives each denial (5.9); it must not block.
    """

    fd: int
    config: Config
    tell: Callable[[dict[str, object]], None] | None = None
    mine: set[int] = field(default_factory=set)
    owed: set[int] = field(default_factory=set)
    waits: dict[int, _Wait] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.notice = notify.Notice(self.fd)
        self._poll: select.poll | None = None
        self.connect_nr = seccomp._nr("connect")
        self.sendto_nr = seccomp._nr("sendto")
        self.socket_nr = seccomp._nr("socket")
        self.served = 0
        writes = self.config.writes
        self.writes: tuple[str, ...] | Literal[True] = (
            True if writes is True else tuple(os.path.realpath(item) for item in writes)
        )
        self._refused: tuple[float, set[tuple[int, int]]] = (0.0, set())

    # -- the loop ---------------------------------------------------------

    def serve(self, stop: Callable[[], bool] | None = None, wake: int | None = None) -> None:
        """Answer notifications until the descriptor hangs up (no task uses
        the filter any more: FINDINGS.md, POLLHUP on exit) or `stop()`
        returns True. `stop` is asked on every pass; `wake` is a descriptor
        that becomes readable when it is worth asking (a signal's wake-up
        pipe), drained here."""
        poll = self._poll = select.poll()
        poll.register(self.fd, select.POLLIN)
        for fd in self.waits:
            poll.register(fd, select.POLLIN)
        if wake is not None:
            poll.register(wake, select.POLLIN)
        try:
            while True:
                if stop is not None and stop():
                    return
                for fd, event in poll.poll(self._next()):
                    if fd == wake:
                        with contextlib.suppress(OSError):
                            os.read(wake, 512)
                    elif fd != self.fd:
                        self._verdict(fd)
                    elif event & select.POLLIN:
                        self.step()
                    elif event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                        self.finish()
                        return
                self._expire()
                if isinstance(self.tell, Reporter):
                    self.tell.flush()
        finally:
            self._poll = None
            if stop is None:
                # Done for good: nothing is left to answer.
                for pending in self.waits.values():
                    pending.sock.close()
                self.waits.clear()
                self.notice.close()

    def finish(self) -> None:
        """Nothing uses the filter any more: send the report what is owed."""
        if isinstance(self.tell, Reporter):
            self.tell.flush(final=True)

    def _next(self) -> int:
        """Milliseconds until the nearest verdict deadline, or 1 s."""
        if not self.waits:
            return 1000
        soonest = min(pending.until for pending in self.waits.values())
        return max(0, int((soonest - time.monotonic()) * 1000)) + 1

    def step(self) -> None:
        """Receive one notification and answer it (or start its verdict wait)."""
        call = notify.receive(self.notice)
        if call is None:
            return
        self.served += 1
        try:
            self._decide(call)
        except Exception as exc:  # noqa: BLE001 - whatever it was, this call is refused and the gate goes on
            # Anything unexpected while deciding: refuse this call and keep
            # serving. Its registers are the agent's to choose, and a gate
            # that stopped would leave the agent waiting on it forever, or
            # running on without it. A failed answer means the call has gone.
            with contextlib.suppress(OSError):
                notify.answer(self.notice, call, error=errno.EACCES)
            if not isinstance(exc, OSError):  # an OSError is the call or process going away
                self._event(call, "gate-error", type(exc).__name__, None)

    # -- deciding ---------------------------------------------------------

    def _decide(self, call: notify.Call) -> None:
        if call.nr == self.socket_nr:
            # Only IP sockets other than TCP come here (the filter): refuse,
            # and say what it was, from the registers alone.
            sort = call.args[1] & seccomp.KINDS
            names = {int(socket.SOCK_DGRAM): "UDP", int(socket.SOCK_RAW): "raw IP"}
            shown = names.get(sort, f"IP socket type {sort}")
            self._event(call, "udp", shown, None)
            self._no(call, errno.EPERM)
            return
        if call.nr == self.connect_nr:
            pointer, size = call.args[1], call.args[2]
        elif call.nr == self.sendto_nr:
            if call.args[3] & FASTOPEN:
                self._no(call, errno.EPERM)
                return
            pointer, size = call.args[4], call.args[5]
        else:
            # Only connect and sendto are trapped; anything else here is a
            # foreign ABI's number (x32). Refuse.
            self._no(call, errno.EACCES)
            return
        target = call.args[0] & 0xFFFFFFFF
        size &= 0xFFFFFFFF
        ino = notify.inode(call.pid, target)
        if ino is None:
            # Not a socket, or no such descriptor: the kernel's own answers,
            # given here so nothing runs (a thread could dup2 a socket in).
            exists = os.path.lexists(f"/proc/{call.pid}/fd/{target}")
            self._no(call, errno.ENOTSOCK if exists else errno.EBADF)
            return
        kind = "unix" if ino in notify.unix(call.pid) else (
            "netlink" if ino in notify.netlink(call.pid) else "ip")
        data = None if self.config.reduced else notify.read(call.pid, pointer, size)
        if not notify.valid(self.fd, call):
            return  # gone: the thread was interrupted or killed
        address = notify.sockaddr(data) if data is not None else None
        sending = call.nr == self.sendto_nr

        if kind == "netlink":
            self._go(call)  # route netlink only (the filter); it can't leave the machine
            return
        if kind == "unix":
            self._unix(call, address, data is None, target, ino)
            return

        # An IP socket: TCP, since the filter allows no other kind.
        if sending:
            # A TCP send ignores its address unless it is Fast Open (refused
            # above), so this connects nothing.
            self._go(call)
            return
        if address is not None and address.family == socket.AF_UNSPEC:
            # A disconnect. The socket may be ours; after this it isn't
            # connected, and the next connect is swapped afresh.
            self.mine.discard(ino)
            self.owed.discard(ino)
            self._go(call)
            return
        if ino in self.owed:
            # The gate installed this socket, then a signal interrupted the
            # call before its answer; this is the same connect, restarted
            # (FINDINGS.md, "half"). It is connected: answer what it asked.
            self.owed.discard(ino)
            self.mine.add(ino)
            notify.answer(self.notice, call, value=0)
            return
        if ino in self.mine:
            self._no(call, errno.EISCONN)
            return
        if data is None:
            # Reduced mode: the address can't be read. The proxy serves only
            # CONNECT and plain HTTP on this connection.
            self._swap(call, target, socket.AF_INET, header(), wait=False, shown="(unknown address)")
            return
        if address is None:
            self._no(call, errno.EFAULT if not data else errno.EINVAL)
            return
        if address.family not in (socket.AF_INET, socket.AF_INET6) or address.ip is None:
            self._no(call, errno.EAFNOSUPPORT)
            return

        ip = hosts.unwrap(address.ip)
        port = address.port or 0
        shown = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
        if ip in _LOOPBACK and port == self.config.port:
            self._swap(call, target, address.family, header(ip, port), wait=False, shown=shown)
            return
        if hosts.match(self.config.rules, port=port, address=ip) is not None:
            self._swap(call, target, address.family, header(ip, port), wait=True, shown=shown)
            return
        self._event(call, "dns" if port == 53 else "direct", shown, None if port == 53 else _flag(ip, port))
        self._no(call, errno.EACCES)

    def _unix(self, call: notify.Call, address: notify.Address | None, reduced: bool,
              target: int, ino: int) -> None:
        """Unix sockets: a path needs a write grant on its folder and must
        not be one of the refused sockets; the gate then connects the object
        it checked and swaps it in (the module's pinned swap). Reduced mode
        refuses them all."""
        if reduced or address is None:
            self._event(call, "unix", "(unknown path)", None,
                        detail="reduced mode: the gate can't read addresses here")
            self._no(call, errno.EACCES)
            return
        if address.family == socket.AF_UNSPEC or (address.family == socket.AF_UNIX and address.path is None):
            # A disconnect, an abstract name (Landlock's abstract-socket
            # scope applies) or an unnamed address (the kernel refuses it).
            if address.family == socket.AF_UNSPEC:
                self.mine.discard(ino)
            self._go(call)
            return
        if address.family != socket.AF_UNIX or address.path is None:
            self._no(call, errno.EINVAL)
            return
        path = address.path
        if not os.path.isabs(path):
            base = notify.cwd(call.pid)
            if base is None:
                self._no(call, errno.EACCES)
                return
            path = os.path.join(base, path)
        path = os.path.normpath(path)
        real = os.path.realpath(path)
        if any(pattern.search(item) for pattern in _REFUSED for item in (path, real)):
            if not os.path.lexists(real):
                # Nothing listens there (glibc tries nscd's socket on every
                # lookup, running or not): the kernel's own answer, without
                # running the call, and nothing to report.
                self._no(call, errno.ENOENT)
                return
            self._refuse(call, real)
            return
        if not self._granted(real):
            self._event(call, "unix", real, f"--write {shlex.quote(os.path.dirname(real) or '/')}")
            self._no(call, errno.EACCES)
            return
        if call.nr == self.sendto_nr:
            # The kernel would resolve the path again after this check. Only
            # a send on a connected socket is safe; glibc's syslog, Python's
            # SysLogHandler and the like connect first.
            self._event(call, "unix-send", real, "--net-any",
                        detail="a datagram sent to a path can't be checked race-free: "
                               "connect the socket first")
            self._no(call, errno.EACCES)
            return
        found = notify.unixsock(call.pid, ino)
        if found is None:
            self._no(call, errno.EACCES)
            return
        sort, bound = found
        if ino in self.mine and sort != socket.SOCK_DGRAM:
            self._no(call, errno.EISCONN)
            return
        if bound:
            self._event(call, "unix-bound", real, "--net-any",
                        detail="a socket bound before connecting would lose its address "
                               "when the gate connects it")
            self._no(call, errno.EACCES)
            return
        try:
            pinned = notify.pin(real)
        except OSError as exc:
            # ENOENT and the like: the kernel's own answer. ELOOP: a symlink
            # appeared in a path that had none a moment ago.
            self._no(call, errno.EACCES if exc.errno == errno.ELOOP else (exc.errno or errno.EACCES))
            return
        try:
            info = os.fstat(pinned)
            if not stat.S_ISSOCK(info.st_mode):
                self._no(call, errno.ECONNREFUSED)  # what connect(2) says for a file that isn't a socket
                return
            if (info.st_dev, info.st_ino) in self._sockets():
                self._refuse(call, real)
                return
            flags = notify.fdflags(call.pid, target) or 0
            sock = socket.socket(socket.AF_UNIX, sort)
            try:
                sock.settimeout(0 if flags & os.O_NONBLOCK else QUEUED)
                sock.connect(f"/proc/self/fd/{pinned}")
            except TimeoutError:
                sock.close()
                self._no(call, errno.EAGAIN)
                return
            except OSError as exc:
                sock.close()
                self._no(call, exc.errno or errno.ECONNREFUSED)
                return
            self._install(call, sock, target, bool(flags & os.O_CLOEXEC), flags)
        finally:
            os.close(pinned)

    def _refuse(self, call: notify.Call, real: str) -> None:
        self._event(call, "unix", real, "--net-any",
                    detail="never allowed with --net hosts: the program behind it acts for its caller")
        self._no(call, errno.EACCES)

    def _sockets(self) -> set[tuple[int, int]]:
        """The refused sockets that exist here, by (device, inode), found
        again at most once per `FRESH` seconds (a daemon restart makes a new
        one)."""
        when, found = self._refused
        now = time.monotonic()
        if now - when < FRESH:
            return found
        import glob

        found = set()
        for place in PLACES:
            for item in glob.glob(os.path.expanduser(place)):
                with contextlib.suppress(OSError):
                    info = os.stat(item)
                    if stat.S_ISSOCK(info.st_mode):
                        found.add((info.st_dev, info.st_ino))
        self._refused = (now, found)
        return found

    def _granted(self, real: str) -> bool:
        if self.writes is True:
            return True
        return any(real == item or real.startswith(item.rstrip("/") + "/") for item in self.writes)

    # -- answering --------------------------------------------------------

    def _no(self, call: notify.Call, code: int) -> None:
        notify.answer(self.notice, call, error=code)

    def _go(self, call: notify.Call) -> None:
        notify.answer(self.notice, call, go=True)

    def _swap(
        self, call: notify.Call, target: int, family: int, head: bytes, *, wait: bool, shown: str
    ) -> None:
        """Connect to the proxy, write `head`, and install the connection at
        the agent's descriptor. With `wait`, first wait for the proxy's
        verdict on the real destination (5.3); the call stays blocked."""
        flags = notify.fdflags(call.pid, target) or 0
        try:
            sock = self._dial(family)
            sock.sendall(head)
        except OSError:
            # The proxy is gone: the network fails closed, never open.
            self._event(call, "proxy-gone", shown, None)
            self._no(call, errno.ECONNREFUSED)
            return
        cloexec = bool(flags & os.O_CLOEXEC)
        if wait:
            sock.setblocking(False)
            self.waits[sock.fileno()] = _Wait(call, sock, target, cloexec,
                                              time.monotonic() + self.config.connect + SLACK, shown)
            if self._poll is not None:
                self._poll.register(sock.fileno(), select.POLLIN)
            return
        self._install(call, sock, target, cloexec, flags)

    def _dial(self, family: int) -> socket.socket:
        """A connection to the proxy, of the agent's socket family so the
        agent's own calls on it (getpeername) answer in the form it expects."""
        port = self.config.port
        if family == socket.AF_INET6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock.connect(("::1", port))
            except OSError:
                sock.close()
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.connect(("::ffff:127.0.0.1", port))
            return sock
        return socket.create_connection(("127.0.0.1", port))

    def _install(
        self, call: notify.Call, sock: socket.socket, target: int, cloexec: bool, flags: int
    ) -> None:
        try:
            if flags & os.O_NONBLOCK:
                # Status flags belong to the open file, which the agent now
                # shares: its non-blocking socket stays non-blocking.
                sock.setblocking(False)
            else:
                sock.setblocking(True)
            ino = os.fstat(sock.fileno()).st_ino
            try:
                notify.addfd(self.fd, call, sock.fileno(), target, cloexec)
            except OSError:
                return  # interrupted or killed before the install: nothing installed
            if notify.answer(self.notice, call, value=0):
                self._remember(ino, call.pid)
            else:
                # Installed, then interrupted before the answer: the call
                # restarts on a socket that is already connected.
                self.owed.add(ino)
        finally:
            sock.close()

    def _remember(self, ino: int, pid: int) -> None:
        self.mine.add(ino)
        if len(self.mine) > REMEMBER:
            live = notify.tcp(pid) | notify.unix(pid)
            self.mine &= live
            self.owed &= live

    def _forget(self, fd: int) -> None:
        if self._poll is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._poll.unregister(fd)

    def _verdict(self, fd: int) -> None:
        pending = self.waits.pop(fd, None)
        self._forget(fd)
        if pending is None:
            return
        try:
            byte = pending.sock.recv(1)
        except OSError:
            byte = b""
        if byte == b"\x00":
            flags = notify.fdflags(pending.call.pid, pending.target) or 0
            self._install(pending.call, pending.sock, pending.target, pending.cloexec, flags)
            return
        pending.sock.close()
        code = byte[0] if byte else errno.ECONNREFUSED
        with contextlib.suppress(OSError):
            self._no(pending.call, code)

    def _expire(self) -> None:
        now = time.monotonic()
        for fd, pending in list(self.waits.items()):
            if pending.until <= now:
                del self.waits[fd]
                self._forget(fd)
                pending.sock.close()
                with contextlib.suppress(OSError):
                    self._no(pending.call, errno.ETIMEDOUT)

    def _event(self, call: notify.Call, why: str, target: str, allow: str | None, **more: object) -> None:
        if self.tell is None:
            return
        with contextlib.suppress(Exception):
            self.tell({"kind": "net", "target": target, "allow": allow, "why": why, "source": "gate",
                       "pid": call.pid, **more})


class Reporter:
    """Where the gate's refusals go (DESIGN-host-allowlisting.md 4.6, 5.9).

    - `log`: hlyn's JSON log. One `deny` record per refusal, in the same form
      the proxy writes, with the program's name; repeats collapse the way
      every hlyn log does (1st, 2nd, 4th, 8th ... occurrence, `log.line`).
    - `events`: the pipe `hlyn run` reads for its report. The first of each
      distinct refusal goes at once; repeats are counted and sent as one
      line with a `count` now and then, and when the gate finishes.

    It never blocks the gate: a line that can't be written now waits in a
    short queue, and past that is dropped and counted. Distinct refusals are
    capped (`LIMIT`); past the cap they are counted, not kept. So a flood of
    connects to distinct addresses (matrix row 28) costs the gate a fixed
    amount of memory, and the connects it answers keep their pace.
    """

    LIMIT = 1000  # distinct refusals kept, as report.LIMIT
    QUEUE = 256  # log lines waiting for a writable log
    EVERY = 0.5  # seconds between sending repeat counts

    def __init__(self, log: int | None = None, events: int | None = None) -> None:
        import collections

        self.log = log
        self.events = events
        self.seen: dict[str, int] = {}  # log.line's repeat tally
        self.counts: dict[tuple[str, str], int] = {}  # sent to the report so far
        self.owed: dict[tuple[str, str], dict[str, object]] = {}  # repeats not yet sent
        self.more = 0  # distinct refusals past LIMIT
        self.dropped = 0  # lines that found no room
        self.queue: collections.deque[bytes] = collections.deque()
        self.names: dict[int, str] = {}
        self.sent = time.monotonic()
        if events is not None:
            with contextlib.suppress(OSError):
                os.set_blocking(events, False)

    def __call__(self, event: dict[str, object]) -> None:
        pid = event.pop("pid", None)
        by = self._name(pid) if isinstance(pid, int) else ""
        key = (str(event.get("why")), str(event.get("target")))
        if key not in self.counts:
            if len(self.counts) >= self.LIMIT:
                self.more += 1
                return
            self.counts[key] = 1
            self._send({**event, "by": by, "count": 1})
        else:
            self.counts[key] += 1
            waiting = self.owed.setdefault(key, {**event, "by": by, "count": 0})
            waiting["count"] = int(waiting["count"]) + 1  # type: ignore[call-overload]
        if self.log is not None:
            from .. import log

            fields = {"what": "net", **{k: v for k, v in event.items() if k != "kind"}, "by": by}
            text = log.line("deny", fields, self.seen, pid=os.getpid())
            if text is not None:
                if len(self.queue) >= self.QUEUE:
                    self.dropped += 1
                else:
                    self.queue.append((text + "\n").encode())
        self.flush()

    def flush(self, final: bool = False) -> None:
        """Write what can be written without waiting; with `final`, send
        every repeat count still owed."""
        if self.owed and (final or time.monotonic() - self.sent >= self.EVERY):
            for waiting in self.owed.values():
                self._send(waiting)
            self.owed.clear()
            self.sent = time.monotonic()
        if final and (self.more or self.dropped):
            self._send({"kind": "more", "count": self.more, "dropped": self.dropped})
        while self.queue and self.log is not None and self._writable(self.log):
            try:
                os.write(self.log, self.queue[0])
            except BlockingIOError:
                break
            except OSError:
                self.queue.clear()
                self.log = None
                break
            self.queue.popleft()

    def _send(self, event: dict[str, object]) -> None:
        if self.events is None:
            return
        line = json.dumps(event, separators=(",", ":"))
        if len(line) >= 512:
            # One atomic pipe write: keep what the report needs, then shorten.
            event = {**event, "target": str(event.get("target", ""))[:200], "detail": None}
            line = json.dumps(event, separators=(",", ":"))[:510]
        try:
            os.write(self.events, (line + "\n").encode())
        except BlockingIOError:
            self.dropped += 1  # a full pipe: the gate never waits on a reader
        except OSError:
            self.events = None

    @staticmethod
    def _writable(fd: int) -> bool:
        poll = select.poll()
        poll.register(fd, select.POLLOUT)
        return any(event & select.POLLOUT for _, event in poll.poll(0))

    def _name(self, pid: int) -> str:
        """The program's name, from /proc (the thread's own `comm`)."""
        if pid not in self.names:
            if len(self.names) > 256:
                self.names.clear()
            try:
                with open(f"/proc/{pid}/comm") as fh:
                    self.names[pid] = fh.read().strip()[:32]
            except OSError:
                self.names[pid] = ""
        return self.names[pid]


def _flag(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> str | None:
    """The `--net` flag that would allow a direct connection to `ip:port`:
    `localhost:PORT` for loopback, the way a local service is named (4.2)."""
    if ip in _LOOPBACK:
        return f"--net localhost:{port}"
    shown = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
    try:
        return hosts.parse(shown).flag()
    except Exception:  # noqa: BLE001 - no flag is better than a wrong one
        return None


def rules(items: Sequence[str]) -> tuple[Rule, ...]:
    """Host entries from their canonical text, as `Config.loads` reads them."""
    return tuple(hosts.parse(item) for item in items)
