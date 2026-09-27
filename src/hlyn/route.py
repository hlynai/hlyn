"""Routing a sealed program's network through hlyn's proxy (host mode).

DESIGN-host-allowlisting.md 5.2, 5.7 and 5.8. When `net` names hosts, the
agent's only way out is a local proxy that checks every destination
(`proxy.py`). This module is the unconfined side of that arrangement:

`start(rules, ...) -> Route`
    Start a proxy helper for `rules`, wait for it to say it is listening and
    sealed, and return a handle: its port, its pid, and the write end of its
    lifetime pipe. The proxy exits when every copy of that write end is
    closed, which is when the process tree that holds it has gone.

`Shared`, `shared(rules, ...)`
    One proxy per allowlist for the life of the calling process, handing out
    a fresh port per `hlyn.run(fn)` call (5.8): two interpreter starts per
    tool call would be too slow, and the port names the run in the log.

`env(port, base) -> dict`
    The variables that point every common client at the proxy (5.7).

`sockets() -> list[Open]`, `neutralise(found)`, `describe(found)`
    Network sockets already open in this process, which a seal can't touch
    (5.2, "connections that already exist").

Standard library only. Nothing here seals anything.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import IO

from . import helpers
from .error import Unsupported
from .hosts import Rule
from .policy import SAFE

__all__ = ["Open", "Route", "Shared", "describe", "env", "neutralise", "shared", "sockets", "start"]

# How long a helper may take to start, seal itself and say so.
READY = 15.0

# The variables that name a proxy, in the order a client consults them.
PROXIES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


@dataclass
class Route:
    """A running proxy helper.

    `port` is where it listens (`None` for a shared proxy, which hands out a
    port per run). `life` is the write end of its lifetime pipe: whoever
    must keep the proxy alive holds a copy, and the proxy exits once none is
    left. `close()` drops this process's copy.
    """

    port: int | None
    pid: int
    life: int
    control: socket.socket | None = field(default=None, repr=False)
    # Started without waiting (`start(wait=False)`): the helper's stdout,
    # which will carry its ready line, and its captured stderr.
    pending: IO[bytes] | None = field(default=None, repr=False)
    err: IO[bytes] | None = field(default=None, repr=False)

    def problem(self, final: bool = False) -> str | None:
        """Why a proxy started without waiting never became ready, or None.

        None while it is still starting, and once it has said it is ready and
        sealed. Reads without blocking. `final` also lets go of the pipes:
        the caller has no further use for the answer (a proxy still starting
        then carries on; its ready line goes nowhere, harmlessly).
        """
        said = None
        if self.pending is not None:
            out = self.pending.fileno()
            data = b""
            while select.select([out], [], [], 0)[0]:
                more = os.read(out, 4096)
                if not more:
                    said = self._failed(data)
                    break
                data += more
                if b"\n" in data:
                    line = data.split(b"\n", 1)[0]
                    try:
                        ready = json.loads(line)
                    except ValueError:
                        ready = None
                    if not (isinstance(ready, dict) and ready.get("sealed")):
                        said = f"the proxy said something unexpected: {line[:200]!r}"
                    self._settle()
                    break
        if final:
            self._settle()
        return said

    def _failed(self, data: bytes) -> str:
        detail = ""
        if self.err is not None:
            self.err.seek(0)
            detail = self.err.read().decode(errors="replace").strip()
        self._settle()
        return ("the proxy stopped before it was ready, so nothing in --net was reachable"
                + (f": {detail[-600:]}" if detail else "") + (f" ({data[:200]!r})" if data else ""))

    def _settle(self) -> None:
        for item in (self.pending, self.err):
            if item is not None:
                with contextlib.suppress(OSError):
                    item.close()
        self.pending = self.err = None

    def alive(self) -> bool:
        """Whether the proxy is still running (its pid, not a reused one, as
        long as the lifetime pipe is held: it can't have exited before)."""
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # a sealed caller may not signal it; it exists
        return True

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def close(self) -> None:
        """Drop this process's hold on the proxy. It exits when no process
        holds the lifetime pipe any more."""
        if self.control is not None:
            self.control.close()
            self.control = None
        if self.life >= 0:
            with contextlib.suppress(OSError):
                os.close(self.life)
            self.life = -1


def _upstream(source: Mapping[str, str]) -> list[str]:
    """`--upstream` and `--skip` for the user's own proxy, if it names one.

    Read from the caller's environment before hlyn cleans it (5.5); checked
    here, so a proxy hlyn can't chain through is refused with the variable
    to change rather than silently bypassed.
    """
    from .chain import upstream

    if upstream(source) is None:
        return []
    url = next(source[key] for key in PROXIES if source.get(key))
    skip = source.get("NO_PROXY") or source.get("no_proxy") or ""
    return ["--upstream", url, "--skip", skip]


def _helper_env() -> dict[str, str]:
    """The environment a helper starts with: nothing secret. A frozen app is
    re-run as itself and may need its own loader's variables, so it keeps
    everything; the proxy scrubs its environment when it seals either way."""
    if getattr(sys, "frozen", False):
        return dict(os.environ)
    return {key: value for key, value in os.environ.items() if key in SAFE}


def start(
    rules: Sequence[Rule],
    *,
    log: int | None = None,
    events: int | None = None,
    gate: bool = False,
    control: bool = False,
    source: Mapping[str, str] | None = None,
    inherit: bool = False,
    wait: bool = True,
) -> Route:
    """Start a proxy for `rules` and return once it is listening and sealed.

    `log` is a descriptor to write `deny` records to (hlyn's log), `events`
    one to write each denial to as a JSON line (for `hlyn run`'s report). `gate`
    makes it expect the Linux gate's header. `control` makes it a shared
    proxy that hands out a port per run (see `Shared`). `source` is the
    environment to read the user's own proxy settings from (default: this
    process's). `inherit` makes the lifetime pipe's write end survive `exec`,
    for a process that will become the agent.

    Raises `Unsupported`, naming the fix, if the helper can't be started, and
    never returns a proxy that hasn't sealed itself (5.1) -- unless `wait` is
    False. Then this process binds the proxy's sockets itself and hands them
    over (socket activation), and returns as soon as the helper has said its
    pid, a few milliseconds in: its imports and seal overlap the agent's own
    start. Nothing is lost by it. A connection made early waits in the
    kernel's backlog, and the proxy reads nothing until it has sealed; if it
    never gets there, it exits, and with no other process holding the
    sockets every connection is refused. `Route.problem()` then says why.
    Not for a shared proxy (`control`), which starts once and waits.
    """
    early = not wait and not control
    args = ["--json", "--quiet", "--detach", *(x for rule in rules for x in ("--net", str(rule)))]
    args += _upstream(os.environ if source is None else source)
    keep: list[int] = []
    mine: list[int] = []  # descriptors this function opened and must close
    if gate:
        args.append("--gate")
    if events is not None:
        keep.append(events)
        args += ["--events", str(events)]
    if log is not None:
        # A fresh number: the helper's own 0, 1 and 2 are redirected.
        copy = os.dup(log)
        mine.append(copy)
        keep.append(copy)
        args += ["--log", str(copy)]
    ours = theirs = None
    if control:
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        keep.append(theirs.fileno())
        args += ["--control", str(theirs.fileno())]
    bound: list[socket.socket] = []
    port = 0
    if early:
        from .listen import bind

        try:
            bound = bind()
        except OSError as exc:
            for fd in mine:
                os.close(fd)
            raise Unsupported(_cannot(f"no port to listen on ({exc})")) from None
        port = int(bound[0].getsockname()[1])
        for sock in bound:
            keep.append(sock.fileno())
            args += ["--listen-fd", str(sock.fileno())]
        args.append("--early")
    read, life = os.pipe()
    err = tempfile.TemporaryFile()  # noqa: SIM115 - read on failure, then closed below
    kept = False  # handed to the Route (early start), so not closed here
    argv = helpers.command("proxy", *args)
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - our own helper, argument vector built above
                argv, stdin=read, stdout=subprocess.PIPE, stderr=err, pass_fds=keep,
                start_new_session=True, env=_helper_env(), cwd="/",
            )
        except OSError as exc:
            os.close(life)
            raise Unsupported(_cannot(f"{argv[0]} would not start ({exc.strerror or exc})")) from None
        finally:
            os.close(read)
            for fd in mine:
                os.close(fd)
            if theirs is not None:
                theirs.close()
            for sock in bound:
                sock.close()  # the proxy's alone now: if it dies, connections are refused
        if early:
            try:
                said = _said(process)
            except Unsupported as exc:
                os.close(life)
                process.kill()
                process.wait()
                err.seek(0)
                detail = err.read().decode(errors="replace").strip()
                raise Unsupported(_cannot(f"{exc}" + (f": {detail[-600:]}" if detail else ""))) from None
            process.wait()  # the first process, which forked the proxy away and exited
            if inherit:
                os.set_inheritable(life, True)
            kept = True
            return Route(port, said, life, pending=process.stdout, err=err)
        try:
            ready = _ready(process)
        except Unsupported as exc:
            os.close(life)
            process.kill()
            process.wait()
            err.seek(0)
            detail = err.read().decode(errors="replace").strip()
            raise Unsupported(_cannot(f"{exc}" + (f": {detail[-600:]}" if detail else ""))) from None
    finally:
        if not kept:
            err.close()
    # The first process exits as soon as the proxy has detached (see
    # proxy._detach); reap it. The proxy itself is init's child now.
    process.wait()
    pid = ready.get("pid")
    if not isinstance(pid, int):
        os.close(life)
        raise Unsupported(_cannot(f"the proxy didn't say its pid: {ready!r}"))
    if inherit:
        os.set_inheritable(life, True)
    return Route(ready.get("port"), pid, life, ours)  # type: ignore[arg-type]


def _said(process: subprocess.Popen[bytes]) -> int:
    """The pid an early-started proxy says first (`helpers.main`), within
    `READY` seconds. Reads exactly that line, so the ready line stays in the
    pipe for `Route.problem`."""
    if process.stdout is None:
        raise Unsupported("the proxy was started without a pipe to answer on")
    out = process.stdout.fileno()
    data = b""
    end = time.monotonic() + READY
    while not data.endswith(b"\n"):
        left = end - time.monotonic()
        if left <= 0:
            raise Unsupported(f"the proxy didn't say its pid within {READY:g} s")
        if not select.select([out], [], [], left)[0]:
            continue
        more = os.read(out, 1)  # one byte at a time: never read past this line
        if not more:
            raise Unsupported(f"the proxy exited before it started (exit {process.wait()})")
        data += more
    try:
        said = json.loads(data)
    except ValueError:
        said = None
    if not (isinstance(said, dict) and isinstance(said.get("pid"), int)):
        raise Unsupported(f"the proxy said something unexpected: {data[:200]!r}")
    return int(said["pid"])


def _ready(process: subprocess.Popen[bytes]) -> dict[str, object]:
    """Read the helper's one ready line, within `READY` seconds, and check it."""
    if process.stdout is None:
        raise Unsupported("the proxy was started without a pipe to answer on")
    out = process.stdout.fileno()
    data = b""
    end = time.monotonic() + READY
    while b"\n" not in data:
        left = end - time.monotonic()
        if left <= 0:
            raise Unsupported(f"the proxy didn't say it was ready within {READY:g} s")
        ready, _, _ = select.select([out], [], [], left)
        if not ready:
            continue
        more = os.read(out, 4096)
        if not more:
            raise Unsupported(f"the proxy exited before it was ready (exit {process.wait()})")
        data += more
    process.stdout.close()
    try:
        said = json.loads(data.split(b"\n", 1)[0])
    except ValueError:
        raise Unsupported(f"the proxy said something unexpected: {data[:200]!r}") from None
    if not isinstance(said, dict) or not said.get("sealed"):
        raise Unsupported(f"the proxy did not seal itself: {said!r}")
    return said


def _cannot(why: str) -> str:
    """The refusal when a helper won't start, with the fix when the cause is
    an interpreter that isn't Python (5.1)."""
    text = f"can't start the network helper: {why}."
    if not getattr(sys, "frozen", False):
        exe = helpers.interpreter()
        name = os.path.basename(exe).lower()
        if not name.startswith(("python", "pypy")):
            text += (f" sys.executable is {exe}, not Python. "
                     f'Call multiprocessing.set_executable("/path/to/python") first.')
    else:
        text += " In a frozen app, call hlyn.helper() first thing in main()."
    return text + " Nothing was sealed."


# ---------------------------------------------------------------------------
# one proxy per allowlist for hlyn.run(fn), a port per run (5.8)
# ---------------------------------------------------------------------------


class Shared:
    """A proxy this process keeps for one allowlist, handing out a port per run.

    Thread-safe: `run()` may be called from several threads at once. Its
    lifetime pipe is held by this process only, so the proxy exits when this
    process does.
    """

    def __init__(
        self, rules: Sequence[Rule], source: Mapping[str, str] | None = None, gate: bool = False
    ) -> None:
        self.route = start(rules, control=True, source=source, gate=gate)
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.asked = 0

    def lease(self, log: int | None = None) -> int:
        """A new port for one run; its denials go to `log`."""
        with self.lock:
            self.asked += 1
            reply = self._ask({"open": self.asked}, [] if log is None else [log])
        port = reply.get("port")
        if not isinstance(port, int):
            raise Unsupported(f"the proxy gave no port for this run: {reply!r}. Nothing was sealed.")
        return port

    def release(self, port: int) -> None:
        """Close a run's port once the run is over."""
        with self.lock, contextlib.suppress(OSError, Unsupported):
            self._ask({"close": port}, [])

    def _ask(self, request: dict[str, object], fds: list[int]) -> dict[str, object]:
        sock = self.route.control
        if sock is None:
            raise Unsupported("the shared proxy is closed")
        sock.settimeout(READY)
        try:
            socket.send_fds(sock, [json.dumps(request).encode()], fds)
            reply = json.loads(sock.recv(4096))
        except (OSError, ValueError) as exc:
            raise Unsupported(f"the shared proxy didn't answer ({exc}). Nothing was sealed.") from None
        if not isinstance(reply, dict) or "error" in reply:
            raise Unsupported(f"the shared proxy refused: {reply!r}. Nothing was sealed.")
        return reply

    def close(self) -> None:
        """Stop using this proxy; it exits once no process holds it. The next
        `shared()` for the same hosts starts a new one."""
        self.route.close()
        with _shared_lock:
            for key, item in list(_shared.items()):
                if item is self:
                    del _shared[key]


_shared: dict[tuple[str, ...], Shared] = {}
_shared_lock = threading.Lock()


def shared(rules: Sequence[Rule], source: Mapping[str, str] | None = None, gate: bool = False) -> Shared:
    """This process's shared proxy for `rules`, started on first use. `gate`:
    it expects the Linux gate's header on every connection (see `start`)."""
    upstream = tuple(_upstream(os.environ if source is None else source))
    key = (*(str(rule) for rule in rules), "|", *upstream, "|", str(gate))
    with _shared_lock:
        found = _shared.get(key)
        if (found is None or found.pid != os.getpid() or found.route.control is None
                or not found.route.alive()):
            found = _shared[key] = Shared(rules, source, gate)
        return found


def _forget() -> None:
    """In a forked child: drop the parent's shared proxies. Their control
    sockets belong to the parent; a child that used them would mix its
    requests with the parent's. The child starts its own if it needs one."""
    for item in _shared.values():
        with contextlib.suppress(OSError):
            item.route.close()
    _shared.clear()


os.register_at_fork(after_in_child=_forget)


# ---------------------------------------------------------------------------
# the agent's environment (5.7)
# ---------------------------------------------------------------------------


def env(port: int, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The variables that send every common client through the proxy on `port`.

    `base` is the environment they are added to, for `JAVA_TOOL_OPTIONS`,
    which is appended to rather than replaced. Local addresses bypass the
    proxy: the Seatbelt profile (and on Linux the gate) handle those.
    """
    url = f"http://127.0.0.1:{port}"
    local = "localhost,127.0.0.1,::1"
    out = dict.fromkeys(PROXIES, url)
    out.update({
        "NO_PROXY": local,
        "no_proxy": local,
        "NODE_USE_ENV_PROXY": "1",  # Node's own fetch, http and https (22.21+, 24.5+)
        "npm_config_proxy": url,
        "npm_config_https_proxy": url,
    })
    java = (f"-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort={port} "
            f"-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort={port} "
            f"-Dhttp.nonProxyHosts=localhost|127.*|[::1]")
    before = (base or {}).get("JAVA_TOOL_OPTIONS", "")
    out["JAVA_TOOL_OPTIONS"] = f"{before} {java}".strip()
    return out


# ---------------------------------------------------------------------------
# network sockets open before the seal (5.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Open:
    """A network socket open in this process: its descriptor, what kind it
    is (`"TCP"`, `"UDP"`, or the socket type's name) and its peer, if any."""

    fd: int
    kind: str
    peer: str | None = None

    def __str__(self) -> str:
        return f"fd {self.fd} to {self.peer}" if self.peer else f"fd {self.fd} {self.kind}"


def sockets() -> list[Open]:
    """Every IPv4 and IPv6 socket open in this process, in any state.

    Landlock, seccomp and Seatbelt all act when a connection is made; a
    socket connected before the seal keeps working after it, whatever its
    destination. Found by asking each open descriptor its family.
    """
    where = "/dev/fd" if sys.platform == "darwin" else "/proc/self/fd"
    try:
        names = [int(name) for name in os.listdir(where) if name.isdigit()]
    except OSError:
        # Unlistable, as inside another hlyn seal (no /proc): ask every
        # descriptor number this process may hold instead.
        import resource

        names = list(range(min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 65536)))
    found = []
    for fd in sorted(names):
        try:
            if not stat.S_ISSOCK(os.fstat(fd).st_mode):
                continue
            sock = socket.socket(fileno=fd)
        except OSError:
            continue  # closed since the listing, or the listing's own descriptor
        try:
            if sock.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            kind = {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}.get(sock.type, sock.type.name)
            peer = None
            with contextlib.suppress(OSError):
                address = sock.getpeername()
                host = f"[{address[0]}]" if sock.family == socket.AF_INET6 else address[0]
                peer = f"{host}:{address[1]}"
            found.append(Open(fd, kind, peer))
        finally:
            sock.detach()
    return found


def describe(found: Sequence[Open]) -> str:
    """`found` as the refusal lists it: `fd 7 to 104.18.6.192:443, fd 9 UDP`."""
    shown = ", ".join(str(item) for item in found[:5])
    return shown + (f" and {len(found) - 5} more" if len(found) > 5 else "")


def neutralise(found: Sequence[Open]) -> int:
    """Put a copy of /dev/null over each socket's descriptor. Returns how many.

    Not `close`: the number stays taken, so a Python object that still owns
    it and closes it later closes the /dev/null copy, never a file that
    reused the number. Anything done with it as a socket fails.
    """
    if not found:
        return 0
    null = os.open(os.devnull, os.O_RDWR)
    try:
        for item in found:
            os.dup2(null, item.fd, inheritable=os.get_inheritable(item.fd))
    finally:
        os.close(null)
    return len(found)
