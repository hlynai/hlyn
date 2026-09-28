# SPDX-License-Identifier: Apache-2.0
"""Applying a policy to a process.

Confinement here is one-way. Landlock and seccomp cannot be lifted once set,
and neither can Seatbelt, so there is no `off()` and no context manager that
pretends to restore anything on exit. The three entry points differ only in
*which* process ends up confined:

    on(policy)          this one, permanently
    run(fn, policy)     a forked child, which runs fn and reports back
    spawn(cmd, policy)  this one, which then becomes cmd
"""

from __future__ import annotations

import contextlib
import os
import pickle
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from types import ModuleType
from typing import Any, NoReturn

from . import log
from .error import Failed, Invalid, Sealed, Unsupported
from .policy import Policy, preset, presets, under

__all__ = ["back", "on", "probe", "run", "sealed", "spawn"]

# Given the environment the scrub kept, the variables to add to it.
Extra = Callable[[Mapping[str, str]], Mapping[str, str]]


_sealed = False


def back() -> ModuleType:
    """The enforcement backend for this machine.

    Imported lazily so that a Linux-only or macOS-only module is never loaded
    on the other platform, and an unsupported platform still gets the refusing
    backend rather than an ImportError.
    """
    if sys.platform == "linux":
        from .core import linux

        return linux
    if sys.platform == "darwin":
        from .core import mac

        return mac
    from .core import none

    return none


def sealed() -> bool:
    """True once this process has been confined."""
    return _sealed


def probe() -> dict[str, object]:
    """What this machine can enforce. Changes nothing.

    Worth calling before shipping: it is the difference between believing a
    boundary exists and knowing it does.
    """
    out: dict[str, object] = back().probe()
    return out


def _plan(policy: object, edits: Mapping[str, Any]) -> Policy:
    """Resolve everything a caller may pass into a single Policy.

    Accepts nothing at all, a preset name, a policy file, a Policy, or plain
    keywords, so the one-line and the fully-specified forms are the same call.
    """
    if policy is None:
        base = Policy()
    elif isinstance(policy, Policy):
        base = policy
    elif isinstance(policy, str):
        # A preset name and a filename are both strings, so one has to be
        # tried first. Presets win: they are a closed, known set, and a file
        # called `coder` with no extension is not something to guess at.
        base = preset(policy) if policy in presets else _read(policy)
    elif isinstance(policy, os.PathLike):
        base = _read(policy)
    elif isinstance(policy, Mapping):
        base = Policy(**policy)
    else:
        raise Invalid(
            f"expected a preset name, a policy file, a Policy, or keywords, got "
            f"{type(policy).__name__}. Try hlyn.on(), hlyn.on(\"coder\"), "
            f'hlyn.on("policy.toml"), or hlyn.on(read=["/src"]).'
        )
    return base.with_(**edits) if edits else base


def _read(path: object) -> Policy:
    """Load a policy file, or explain that it was neither a preset nor a file."""
    from .spec import load

    try:
        return load(path)  # type: ignore[arg-type]
    except Invalid as exc:
        known = ", ".join(sorted(presets))
        raise Invalid(f"{exc} (not a known preset either; those are: {known})") from None


def _scratch(policy: Policy) -> tuple[Policy, str | None]:
    """Give the agent a private scratch directory, if it asked for one.

    A fresh empty directory grants no access to anything that already exists,
    which is why it can be on by default without weakening deny-by-default.
    """
    if policy.tmp is True:
        box = tempfile.mkdtemp(prefix="hlyn-")
        return policy.with_(tmp=box), box
    if isinstance(policy.tmp, str):
        os.makedirs(policy.tmp, exist_ok=True)
        return policy, policy.tmp
    return policy, None


def on(policy: object = None, **edits: Any) -> dict[str, object]:
    """Confine this process. Permanently.

        import hlyn; hlyn.on()                     # deny all but the runtime
        hlyn.on("coder")                           # a preset
        hlyn.on(read=["/src"], net=["api.openai.com"])  # named grants

    Returns what was applied. Raises rather than return if the kernel could
    not apply it, because a caller that believes it is confined and is not is
    the worst outcome this package has.

    No child processes, unless `net` names hosts (DESIGN-host-allowlisting.md
    5.8): then two detached helpers start before the seal and live as long as
    this process -- a local proxy, and on Linux a gate that makes it the only
    way out. On Linux before 7.1 a gate starts for the other limited modes
    too (`net=False`, ports), to check unix sockets, which Landlock can't
    there (`watched`). The seal record names them (`"helpers"`), and the proxy
    variables (`HTTPS_PROXY` and the rest) are set in `os.environ`, so a
    client created before this call misses them: create it after.
    """
    if _sealed:
        raise Sealed(
            "this process is already confined, and confinement cannot be "
            "changed once applied. Build the full policy before calling on()."
        )
    plan = _plan(policy, edits)
    unbuilt(plan)
    _ready(plan)
    from . import route

    open_ = _loose(plan)
    if open_:
        raise Unsupported(
            f"{len(open_)} network connection{'s are' if len(open_) > 1 else ' is'} already open "
            f"({route.describe(open_)}) that this policy's net wouldn't allow. "
            f"{'They' if len(open_) > 1 else 'It'} would keep working after the seal, whatever its "
            f"destination. Close them first (for example session.close()), call hlyn.on() before "
            f"creating network clients, or use hlyn.run(fn), which closes them in its child."
        )
    found = _warn(plan)
    if not plan.hosts():
        if not watched(plan):
            return _seal(plan, found=found)
        # Unix sockets before Linux 7.1 (`watched`): a gate without a proxy,
        # started and exempted from Yama as host mode's is, below.
        from . import gate

        with _denials(plan) as fd:
            _ptracer(gate.detached(log=fd))
        try:
            return _seal(plan, found=found)
        except BaseException:
            gate.drop()
            raise

    # Host mode (DESIGN-host-allowlisting.md 5.2, 5.8): a proxy started now,
    # before the seal, and held alive by this process for the rest of its
    # life -- the lifetime pipe survives exec too.
    with _denials(plan) as fd:
        way = route.start(plan.hosts(), log=fd, inherit=True, gate=gated())
        try:
            if gated():
                # The calling process can't gain a parent, so its gate runs
                # detached, and is exempted from Yama's ancestors-only rule so
                # it may read this process's memory (5.2). Children of this
                # process aren't covered by the exemption: they get reduced
                # mode where Yama is at 1 (5.3). Its refusals go to the log.
                from . import gate

                _ptracer(gate.detached(log=fd))
        except BaseException:
            way.close()
            raise
    try:
        return _seal(plan, _proxied(_port(way)), found=found, proxy=(_port(way), way.pid))
    except BaseException:
        way.close()
        if gated():
            from . import gate

            gate.drop()
        raise


def watched(plan: Policy) -> bool:
    """Whether sealing `plan` here starts a gate for unix sockets although it
    names no hosts (Linux before 7.1: `core/linux.watched`)."""
    check = getattr(back(), "watched", None)
    return bool(check is not None and check(plan))


def gated() -> bool:
    """Whether host mode on this platform puts the gate in front of the proxy
    (Linux, 5.3): the proxy then expects the gate's header first."""
    return bool(getattr(back(), "GATE", False))


def _ptracer(pid: int) -> None:
    """`prctl(PR_SET_PTRACER, pid)`: let `pid` read this process's memory
    under Yama's `ptrace_scope` 1. A no-op without Yama (EINVAL)."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(0x59616D61, ctypes.c_ulong(pid), 0, 0, 0)


def unbuilt(plan: Policy) -> None:
    """Refuse to seal a policy that names hosts on a backend that can't
    enforce them, before any helper starts.

    Linux and macOS both enforce host names; the backend for every other
    platform (`core/none.py`) enforces nothing. Sealing with hosts quietly
    treated as ports, or as open, would be the one thing a containment layer
    must never do, so every entry point refuses here first, before anything
    is changed -- including the proxy it would otherwise start.
    """
    named = plan.hosts()
    if named and not getattr(back(), "HOSTS", False):
        shown = ", ".join(str(rule) for rule in named[:3]) + (" ..." if len(named) > 3 else "")
        raise Unsupported(
            f"net names hosts ({shown}), and this platform can't enforce them. Nothing was "
            f"sealed. hlyn enforces host names on Linux and macOS."
        )


def _loose(plan: Policy) -> list[Any]:
    """Network sockets this process holds that `plan` wouldn't let it open.

    Landlock, seccomp and Seatbelt all act when a connection is made, so one
    made before the seal keeps working after it, to wherever it goes. With
    `net=True` nothing is loose. With ports, a TCP connection to a listed
    port is one the policy would allow anyway, so it stays usable; anything
    else -- listeners, UDP, other ports -- is loose. With hosts or
    `net=False`, every socket is: the proxy is the only way out.
    """
    if plan.net is True:
        return []
    from . import route

    found = route.sockets()
    if plan.hosts() or not isinstance(plan.net, tuple):
        return found
    listed = {port for port in plan.net if isinstance(port, int)}

    def allowed(item: Any) -> bool:
        if item.kind != "TCP" or not item.peer:
            return False
        port = item.peer.rpartition(":")[2]
        return port.isdigit() and int(port) in listed

    return [item for item in found if not allowed(item)]


def _neutral(plan: Policy) -> int:
    """In a child about to seal: put the loose sockets out of use (5.2)."""
    from . import route

    return route.neutralise(_loose(plan))


def _ready(plan: Policy) -> None:
    """Refuse a host policy this machine or this process can't take (Linux:
    libseccomp too old, or already inside a listener), before any helper
    starts. The backend asks again when it seals."""
    check = getattr(back(), "ready_hosts", None)
    if plan.hosts() and check is not None:
        check()


@contextlib.contextmanager
def _denials(plan: Policy) -> Iterator[int | None]:
    """The descriptor host mode's helpers write `deny` records to (4.6), for
    as long as it takes to hand them their own copy.

    None when there is nowhere they can write: the log is off, or it is an
    in-memory stream another process can't reach (warned about once). A log
    path is opened here in append mode, so records from several processes
    never interleave within a line, and closed again on the way out.
    """
    if plan.log is False:
        yield None
        return
    if isinstance(plan.log, str):
        opened = os.open(plan.log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            yield opened
        finally:
            os.close(opened)
        return
    fd: int | None
    try:
        fd = log.fileno()
    except ValueError:
        global _memory
        if not _memory:
            import warnings

            warnings.warn(
                "hlyn: network denials can't reach an in-memory log; pass a file path or "
                "stderr to hlyn.log.sink()", RuntimeWarning, stacklevel=4,
            )
            _memory = True
        fd = None
    yield fd


# Whether the in-memory-log warning has been given in this process.
_memory = False


def _port(way: object) -> int:
    """A started proxy's port. A proxy started for one run always has one."""
    port = getattr(way, "port", None)
    if not isinstance(port, int):
        raise Failed("the proxy started without a port. Nothing was sealed.")
    return port


def _proxied(port: int) -> Extra:
    """The environment hook that points the agent at the proxy (5.7)."""
    from . import route

    return lambda keep: route.env(port, keep)


def _both(one: Extra | None, two: Extra) -> Extra:
    """Two environment hooks, applied in order."""
    if one is None:
        return two
    return lambda keep: {**one(keep), **two(keep)}


def reaches(plan: Policy) -> list[str]:
    """Warnings for a policy that reaches further than it reads (6.7): a
    host entry naming a local service with onward reach, and, on Linux, a
    write grant holding a socket that runs things for its caller (the
    resolver, D-Bus, a container runtime) where nothing refuses it. With
    hosts, and before Linux 7.1 with any limited network, the gate refuses
    those race-free (guard's pinned swap); from 7.1, ports and `net=False`
    have no gate, and Landlock allows every socket in a write-granted folder."""
    from .hosts import warn

    named = plan.hosts()
    out = [said for said in (warn(rule) for rule in named) if said]
    if named or plan.net is True or sys.platform != "linux":
        return out
    from .core import landlock

    if landlock.abi() < 9:
        return out
    from .core.guard import granted

    writes = plan.writes()
    for path in granted(writes):
        if writes is True:
            where = "The policy grants writing everywhere, which covers"
        else:
            folder = max((item for item in writes if under(path, os.path.realpath(item))), key=len)
            where = f"--write {folder} covers"
        out.append(
            f"hlyn: {where} {path}, a socket whose program acts for its caller (it can run "
            f"things outside the sandbox). Linux lets a confined program connect to any socket "
            f"in a write-granted folder. Grant a narrower folder unless you mean it."
        )
    return out


_OPTIONS = False  # whether `options()` has run


def options() -> None:
    """Apply the `-W` / `PYTHONWARNINGS` entries that name hlyn's warnings
    (`error::hlyn.Exposed`, `ignore::hlyn.Reach`), once, before hlyn first
    warns.

    Python reads those options at startup, before site-packages is on its
    path, so for an installed hlyn it can't import the category: it prints
    "Invalid -W option ignored" and drops the entry. Here each such entry is
    applied with Python's own parser, in the order given -- unless a filter
    for that warning exists already: then Python applied it (hlyn was on
    PYTHONPATH), or the program set its own, which should win as it would
    have over an entry applied at startup."""
    global _OPTIONS
    if _OPTIONS:
        return
    _OPTIONS = True
    import warnings

    from .hosts import Reach
    from .secret import Exposed

    ours: dict[str, type[Warning]] = {
        "hlyn.Exposed": Exposed, "hlyn.secret.Exposed": Exposed,
        "hlyn.Reach": Reach, "hlyn.hosts.Reach": Reach,
    }
    have = {item[2] for item in warnings.filters}
    for option in sys.warnoptions:
        fields = option.split(":")
        category = ours.get(fields[2].strip()) if len(fields) > 2 else None
        if category is None or category in have:
            continue
        with contextlib.suppress(Exception):  # malformed: Python has said so already
            warnings._setoption(option)  # type: ignore[attr-defined]  # Python's own -W parser, 3.9-3.14


def _warn(plan: Policy) -> list[str]:
    """Say, before sealing, if the policy lets secrets out. See `secret.py`.

    A Python warning, so it can be filtered like any other. Made an error
    (`warnings.simplefilter("error", hlyn.Exposed)`, or `-W error`), it is
    raised here -- before the seal, so the process is left untouched, and a
    test suite can use it to keep leaky policies out. Returns what was found,
    for the log record `_seal` writes once the log is pointed where the
    policy says.
    """
    import warnings

    from .hosts import Reach
    from .secret import Exposed, exposed, warning

    options()
    for said in reaches(plan):
        warnings.warn(said, Reach, stacklevel=3)
    found = exposed(plan)
    if found:
        warnings.warn(warning(found, cli=False), Exposed, stacklevel=3)
    return found


def _seal(
    plan: Policy,
    extra: Extra | None = None,
    tag: str | None = None,
    found: list[str] | None = None,
    proxy: tuple[int, int] | None = None,
    closed: int = 0,
) -> dict[str, object]:
    """`on`, for callers that also shape the environment or tag the seal.

    `extra` returns variables to add after the environment is scrubbed, given
    what the scrub kept; `tag` marks the backend's refusal reports. Both exist
    for `hlyn run`, which uses them to hear what the command is refused.
    `proxy` is `(port, pid)` of the proxy a host policy goes through, and
    `closed` how many inherited sockets were put out of use (5.2); both go
    into the seal record.
    """
    global _sealed
    if _sealed:
        raise Sealed(
            "this process is already confined, and confinement cannot be "
            "changed once applied. Build the full policy before calling on()."
        )

    unbuilt(plan)
    plan, box = _scratch(plan)

    # Find the backend's libraries before the environment is scrubbed. The
    # Landlock shim can be pointed at by HLYN_SHIM, which is not in the safe
    # list, so resolving it any later looks for a variable that is already
    # gone -- `hlyn probe` would honour the override and `hlyn.on()` would not,
    # on the same machine. `ready` reports rather than raises; the real refusal
    # still comes from `load` below, with its own message.
    back().ready()

    # Scrub before sealing, not after: if the seal fails halfway, the secrets
    # are already gone rather than left sitting in a half-confined process.
    keep = plan.keep()
    if box:
        keep["TMPDIR"] = box
    if extra is not None:
        keep.update(extra(keep))
    os.environ.clear()
    os.environ.update(keep)
    tempfile.tempdir = box

    if plan.log is False:
        log.off()
    elif isinstance(plan.log, str):
        log.sink(plan.log)
    if found:
        log.emit("exposed", paths=found[:20])

    more: dict[str, object] = {}
    # A gate without a proxy (`watched`), about to be handed this seal.
    minder = sys.modules.get(__name__.rpartition(".")[0] + ".gate")
    watcher = getattr(minder, "pid", None) if getattr(minder, "_handoff", None) is not None else None
    if proxy is not None:
        from . import gate

        port, pid = proxy
        helpers = [pid] if gate.pid is None else [gate.pid, pid]
        level = back().load(plan, tag, port)
        # `net` is in the record already, as the rules' text.
        more = {"proxy": f"127.0.0.1:{port}", "helpers": helpers, "closed": closed}
    else:
        level = back().load(plan, tag) if tag else back().load(plan)
        if watcher is not None:
            more = {"helpers": [watcher]}
        if closed:
            more["closed"] = closed

    _sealed = True
    log.seal(plan, back().__name__, level, box, **more)

    return {"policy": plan, "tmp": box, "level": level, "backend": back().__name__, **more}


def run(fn: Callable[[], Any], policy: object = None, **edits: Any) -> Any:
    """Run `fn` in a confined child and return its result.

    For work that needs a tighter boundary than the caller wants to live with
    for the rest of its life: a single tool call, a single untrusted document.
    The parent is untouched.

    One hazard worth knowing about, because this is also the documented way to
    seal from a process that has threads. `fork` copies the calling thread and
    no others, but it copies every lock in whatever state it was in, so a child
    that needs a lock another thread was holding waits forever. The libraries
    are loaded in the parent below for exactly that reason -- `dlopen` in the
    child would take the loader lock, which is the one most likely to be held.

    When `net` names hosts, the child forks once more (DESIGN-host-allowlisting.md
    5.2): the grandchild is sealed and runs `fn`, and the child becomes its
    gate. The proxy is shared by every call with the same hosts, for the life
    of this process, and each call gets its own port on it (5.8).
    """
    plan = _plan(policy, edits)
    unbuilt(plan)  # in the parent, so the refusal is an exception, not a dead child
    _ready(plan)
    # Before the fork, never after: see the note above.
    back().ready()
    named = plan.hosts()
    watch = not named and watched(plan)
    share = None
    port = 0
    alone = False
    told: int | None = None
    found: list[str] = []
    if watch:
        # Unix sockets before Linux 7.1: the child becomes a gate, as in host
        # mode, with no proxy (`watched`).
        from . import gate

        with _denials(plan) as fd:
            told = os.dup(fd) if fd is not None else None  # the gate's copy
    if named:
        # Imported here, before the fork: the child must not take the
        # import lock another thread might have been holding.
        from . import gate, route

        found = _warn(plan)
        share = route.shared(named, gate=gated())
        with _denials(plan) as fd:
            port = share.lease(fd)
            told = os.dup(fd) if fd is not None and gated() else None  # the gate's copy
    if (named or watch) and sys.platform == "linux":
        # A caller with one thread can have its gate serve in the forked
        # child with no interpreter start (gate.become, `fresh`).
        from .core.landlock import crowd

        alone = len(crowd()) <= 1
        if alone:
            gate.prepare()
    try:
        read, write = os.pipe()
        _flush()
        kid = os.fork()
        if kid == 0:  # child
            os.close(read)
            if share is None:
                def plain() -> None:
                    _seal(plan, found=_warn(plan), closed=_neutral(plan))

                if not watch:
                    _child(fn, plain, write)
                gate.become(lambda: _child(fn, plain, write), forward=False, isolate=False,
                            close=[write], fresh=not alone, log=told)
            pid = share.route.pid

            def sealed() -> None:
                closed = _neutral(plan)
                _seal(plan, _proxied(port), found=found, proxy=(port, pid), closed=closed)

            gate.become(lambda: _child(fn, sealed, write), forward=False, isolate=False,
                        close=[write], fresh=not alone, log=told)

        os.close(write)
        if told is not None:
            os.close(told)
            told = None
        with os.fdopen(read, "rb") as fh:
            body = fh.read()
        _, status = os.waitpid(kid, 0)
    finally:
        if share is not None:
            share.release(port)
        if told is not None:
            os.close(told)

    if not body:
        if os.WIFSIGNALED(status):
            hurt = os.WTERMSIG(status)
            raise Failed(
                f"the confined child was killed by signal {hurt}"
                + (" (SIGSYS: it attempted a refused syscall)" if hurt == 31 else "")
            )
        raise Failed(f"the confined child returned nothing (exit {os.WEXITSTATUS(status)})")

    # The bytes come from a child this process forked moments ago, over a pipe
    # nothing else holds. It is not untrusted input; it is this program's own
    # return value coming back across a process boundary.
    kind, value = pickle.loads(body)  # noqa: S301
    if kind == "ok":
        return value
    raise value


def _flush() -> None:
    """Write out what Python holds for stdout and stderr, as `multiprocessing`
    does around a fork. Before a fork, so the child can't write the parent's
    pending output a second time; before `os._exit` or an exec, which skip the
    interpreter's own flush, so nothing printed into a pipe is lost."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            with contextlib.suppress(Exception):  # closed, or replaced by something odd
                stream.flush()


def _child(fn: Callable[[], Any], seal: Callable[[], object], write: int) -> NoReturn:
    """In the confined child: seal, run `fn`, send back its result or its
    exception, and exit."""
    code = 0
    try:
        seal()
        out: tuple[str, Any] = ("ok", fn())
    except BaseException as exc:  # noqa: BLE001 - report it rather than die silently
        out, code = ("no", exc), 1
    try:
        body = pickle.dumps(out)
    except Exception:  # noqa: BLE001 - any pickling failure, not a known set
        # A result or exception that will not pickle must not look like a
        # crash, which is what an empty pipe would mean.
        body = pickle.dumps(("no", Failed(f"the result could not be returned: {out[0]}")))
    try:
        with os.fdopen(write, "wb") as fh:
            fh.write(body)
    finally:
        _flush()
        os._exit(code)


def spawn(cmd: Sequence[str], policy: object = None, **edits: Any) -> None:
    """Confine this process, then become `cmd`. Does not return.

    Used by the command line wrapper. The program being launched is granted
    execute on itself: asking to run something and forbidding it in the same
    breath is a contradiction, not a policy.

    When `net` names hosts (DESIGN-host-allowlisting.md 5.2), this process
    forks once: the child is sealed and becomes `cmd`, and this process
    becomes its gate -- it passes on every signal it is sent and exits with
    `cmd`'s status, as the container inits `tini` and `dumb-init` do. From
    outside it still "becomes `cmd`": same PID, same signals, same exit
    status. A proxy runs beside it for as long as `cmd` and what it starts.
    """
    plan = _plan(policy, edits)
    unbuilt(plan)
    _ready(plan)
    found = _warn(plan)
    if not plan.hosts():
        if not watched(plan):
            _spawn(cmd, plan, found=found)
            return
        # Unix sockets before Linux 7.1: this process becomes the command's
        # gate, as in host mode, with no proxy (`watched`).
        from . import gate

        _prepare(cmd, plan)  # here, so a bad command is an exception
        with _denials(plan) as fd:
            told = os.dup(fd) if fd is not None else None  # the gate's copy
        _flush()
        gate.become(lambda: _spawn(cmd, plan, found=found), forward=True, isolate=True, log=told)

    from . import gate, route

    run, argv, plan = _prepare(cmd, plan)  # in this process, so a bad command is an exception
    with _denials(plan) as fd:
        way = route.start(plan.hosts(), log=fd, inherit=True, gate=gated())
        told = os.dup(fd) if fd is not None and gated() else None  # the gate's copy
    port = _port(way)

    def body() -> None:
        closed = _neutral(plan)
        _seal(plan, _proxied(port), found=found, proxy=(port, way.pid), closed=closed)
        _flush()
        os.execv(run, argv)  # noqa: S606 - see _spawn

    _flush()
    gate.become(body, forward=True, isolate=True, close=[way.life], log=told)


def _prepare(cmd: Sequence[str] | str, plan: Policy) -> tuple[str, list[str], Policy]:
    """What `spawn` executes, with what arguments, and the policy widened to
    let it run. Raises `Invalid` for a command that can't be found."""
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        raise Invalid("spawn needs a command to run.")

    named = shutil.which(cmd[0])
    if not named:
        raise Invalid(f"{cmd[0]!r} was not found on PATH, so it cannot be run.")
    # Granted by its real path, which is what the kernel checks; run by the
    # path it was found at. The difference matters for a virtualenv: its
    # python is a link, and executing the link's target directly starts the
    # base interpreter without the venv.
    named = os.path.abspath(named)
    where = os.path.realpath(named)

    # A Python other than hlyn's own needs its own files granted, and a
    # launcher (Apple's /usr/bin/python3, pyenv's shims) needs the interpreter
    # it would start. See interpreter.py. The command itself is always granted
    # execute: asking to run it and forbidding it is a contradiction.
    from . import interpreter

    plan, run = interpreter.grants(interpreter.ask(cmd[0], where), plan, where)
    # The same goes for the script a Python command runs: `hlyn run -- python
    # agent.py` asks for agent.py to run, so it may be read. That file only.
    source = interpreter.runs(cmd) if interpreter.python(cmd[0], where) else None
    if source and plan.read is not True:
        plan = plan.with_(read=[*(plan.read or ()), source])
    if run != where:
        return run, [run, *cmd[1:]], plan  # a launcher, followed: see interpreter.py
    line = interpreter.shebang(where)
    if line is not None:
        return _script(plan, list(cmd), named, where, *line)
    return named, list(cmd), plan


def _script(
    plan: Policy, cmd: list[str], named: str, where: str, program: str, args: list[str]
) -> tuple[str, list[str], Policy]:
    """How to run the script `where`, and `plan` widened to let it. The
    kernel would start the interpreter its first line names, which then
    reads the script: asking to run the script asks for both, as a binary's
    execute permission comes with asking to run it. `#!/usr/bin/env NAME` is
    followed to the NAME it starts.

    A Python interpreter is handled as a Python command is (interpreter.py):
    asked where its files are, followed past a launcher (Apple's
    `/usr/bin/python3`, pyenv's shims), and run directly with the script, as
    the kernel would have started it. Anything else is started by the kernel
    from the script, with its interpreter allowed to run.

    Raises `Invalid`, before anything is sealed, when the interpreter the
    line names doesn't exist."""
    from . import interpreter
    from .policy import companion

    typed = cmd[0]
    if not os.path.isfile(program):
        raise Invalid(
            f"can't start {typed}: its first line names {program}, which doesn't exist. Fix that line, "
            f"or name the interpreter yourself: hlyn run -- INTERPRETER {typed}"
        )
    if plan.read is not True:
        plan = plan.with_(read=[*(plan.read or ()), where])
    target, words = program, list(args)
    if os.path.basename(program) == "env":
        command = interpreter.env_command(args)
        found = shutil.which(command[0]) if command else None
        if command and found:
            target, words = os.path.abspath(found), command[1:]
    real = os.path.realpath(target)
    if interpreter.python(target, real):
        plan, run = interpreter.grants(interpreter.ask(target, real), plan, real)
        # By the path the line names, as `_prepare` runs a Python command,
        # unless a launcher was followed: a venv's python is a link, and only
        # through the link does the interpreter know it is in the venv.
        run = run if run != real else target
        options = [word for arg in words for word in arg.split()]
        return run, [run, *options, named, *cmd[1:]], plan
    runs: list[str] = []
    for item in (program, os.path.realpath(program), target, real, companion(real)):
        if item and item not in runs:
            runs.append(item)
    if plan.exec is not True:
        granted = list(plan.exec) if isinstance(plan.exec, tuple) else []
        plan = plan.with_(exec=[*granted, *(item for item in runs if item not in granted)])
    return named, cmd, plan


def _spawn(
    cmd: Sequence[str] | str,
    plan: Policy,
    extra: Extra | None = None,
    tag: str | None = None,
    found: list[str] | None = None,
    proxy: tuple[int, int] | None = None,
) -> None:
    """`spawn`, with the same additions as `_seal`. In host mode (`proxy`
    given) the caller has already arranged the gate; this is the child."""
    run, argv, plan = _prepare(cmd, plan)
    closed = _neutral(plan)
    _seal(plan, extra, tag, found, proxy=proxy, closed=closed)
    _flush()
    # No shell, deliberately: the command is executed as given, so nothing in
    # it is ever interpreted as shell syntax.
    os.execv(run, argv)  # noqa: S606
