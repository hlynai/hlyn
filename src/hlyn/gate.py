"""The gate: the sealed program's unconfined parent (DESIGN-host-allowlisting.md 5.2).

Wherever hlyn forks anyway, the process about to be sealed forks once more:
the child is sealed and carries on, and the parent becomes the gate. On Linux
the gate will answer the kernel's connection checks (phase 4), which needs an
ancestor of the whole sealed tree. On both platforms it is what makes a
forked layout look like the process it replaced:

- **Signals are forwarded.** Every signal the gate can catch is passed to the
  child, the pattern `tini` and `dumb-init` use as a container's init.
- **The exit status is the child's.** An exit code is exited with; a death
  by signal is reproduced by the gate dying of the same signal (with core
  dumps off, so the gate never leaves one of its own).
- **The terminal goes with the child.** A command run from a terminal is put
  in its own process group and given the terminal (tini's `isolate_child`),
  so Ctrl-C reaches it once, not once directly and again through the gate.
  Stopping it (Ctrl-Z) stops the gate too, so the shell sees its job stop;
  continuing the gate hands the terminal back and continues the child.

`become(body, ...)` forks: the child runs `body`, which seals and never
returns; the parent turns into a fresh interpreter running `main` here (5.1),
so none of the caller's threads or locks come with it.

**On Linux the gate also answers the kernel's connection checks** (5.3,
`core/guard.py`). The sealed child hands it the seccomp notification
descriptor over a socket pair made before the fork (`hand`), then closes its
own copy before any agent code runs (5.2, step 5). The gate serves those
notifications and relays signals in one single-threaded loop. When the
command exits while programs it started still use the filter, the gate forks
a successor to keep answering them and exits with the command's status, so
whoever waits on the gate isn't held up by background processes. The
successor is no longer their ancestor: where Yama allows only ancestors to
read memory, they get reduced mode (5.3).

`detached()` starts a gate with no child, for `hlyn.on()`: it answers the
calling process's connections and exits when nothing uses the filter.
"""

from __future__ import annotations

import contextlib
import os
import select
import signal
import socket
import sys
from collections.abc import Callable, Sequence

# `typing` itself costs a helper's start ~5 ms, and every use here is an
# annotation; mypy reads this flag as it reads typing's.
TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import NoReturn

    from .core.guard import Config, Guard

__all__ = ["become", "detached", "drop", "hand", "main", "prepare", "relay"]

# Signals the gate never forwards: the two it can't catch, the one that
# reports on the child itself, and the terminal's stop signals for
# background reads and writes, which only ever concern the gate's own use
# of the terminal. SIGCONT is forwarded, by its own handler.
KEEP = {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD, signal.SIGTTIN, signal.SIGTTOU}

# Whether the gate has work beyond waiting and passing on signals on this
# platform. On Linux it answers the kernel's connection checks (5.3); on
# macOS it has none. A gate that only waits needs no fresh interpreter:
# `waitpid` and `_exit` are safe straight after `fork`, whatever the
# caller's threads held -- the hazard a fresh interpreter avoids (5.1).
DUTY = sys.platform == "linux"

# In the process about to be sealed: its end of the socket pair to its gate,
# and the gate's pid. Set by `become` and `detached`, used once by `hand`.
_handoff: socket.socket | None = None
pid: int | None = None

# How long the sealed process waits for its gate to take the descriptor.
TAKE = 15.0


def _all() -> set[signal.Signals]:
    return set(signal.valid_signals()) - {signal.SIGKILL, signal.SIGSTOP}


def _terminal() -> int | None:
    """Standard input's descriptor, if it is a terminal this process group
    has in the foreground; otherwise None (nothing to hand over)."""
    try:
        if os.isatty(0) and os.tcgetpgrp(0) == os.getpgrp():
            return 0
    except OSError:
        pass
    return None


def _give(tty: int, group: int) -> None:
    """Put `group` in the terminal's foreground. From a background group this
    raises SIGTTOU, which is ignored for the call, as tini does."""
    old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        with contextlib.suppress(OSError):
            os.tcsetpgrp(tty, group)
    finally:
        signal.signal(signal.SIGTTOU, old)


def become(
    body: Callable[[], object],
    *,
    forward: bool,
    isolate: bool,
    close: Sequence[int] = (),
    fresh: bool = True,
    log: int | None = None,
    events: int | None = None,
) -> NoReturn:
    """Fork. The child runs `body`, which must seal and exec or exit; the
    parent becomes the gate for it and exits as the child does.

    `forward` passes signals on (for `spawn` and `hlyn run`, where the
    original process stands for the command). `isolate` gives the child its
    own process group, and the terminal when there is one in the foreground.
    `close` lists descriptors the gate must not keep: whatever the child
    alone should hold, such as the proxy's lifetime pipe.

    `fresh=False` lets the gate answer connection checks in this forked
    process instead of a fresh interpreter, which saves an interpreter start
    per call. Only for a caller that had one thread when it forked (the
    caller says so): then no lock was held by a thread fork didn't copy, the
    hazard a fresh interpreter avoids (5.1). The modules it needs must be
    imported and libseccomp loaded before the fork (`prepare`).

    `log` and `events` are descriptors the gate reports its refusals to
    (`core/guard.Reporter`): hlyn's log, and `hlyn run`'s report pipe. The
    gate takes them over; the child never has them.

    Every signal is blocked across the fork and the exec that follows, so
    one sent in between waits for the gate's handlers instead of killing it
    and leaving the child without a parent.
    """
    import resource  # noqa: F401 - loaded now: relay() needs it, and nothing may be imported after fork

    from . import helpers

    global _handoff, pid

    tty = _terminal() if isolate else None
    agent_end = gate_end = None
    if DUTY:
        # The sealed child's notification descriptor comes back over this
        # (see `hand`). Made before the fork, so neither side can miss it.
        agent_end, gate_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    # Built before the fork: after it, the parent does as little as possible.
    argv = helpers.command("gate", "--child", "0", *(["--forward"] if forward else []),
                          *(["--terminal"] if tty is not None else []),
                          *(["--notify", str(gate_end.fileno())] if gate_end is not None else []),
                          *(["--log", str(log)] if log is not None else []),
                          *(["--events", str(events)] if events is not None else []))
    where = {key: value for key, value in os.environ.items() if key in ("PATH", "LANG", "LC_ALL")}
    if getattr(sys, "frozen", False):
        where = dict(os.environ)
    me = os.getpid()
    before = signal.pthread_sigmask(signal.SIG_BLOCK, _all())
    child = os.fork()
    if child == 0:
        code = 1
        try:
            if gate_end is not None:
                gate_end.close()
                _handoff, pid = agent_end, me
            for fd in (log, events):
                if fd is not None:
                    os.close(fd)
            signal.pthread_sigmask(signal.SIG_SETMASK, before)
            if isolate:
                os.setpgid(0, 0)
                if tty is not None:
                    _give(tty, os.getpgrp())
            body()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        except BaseException:  # noqa: BLE001 - reported, then this child exits
            import traceback

            traceback.print_exc()
        finally:
            os._exit(code)
    if isolate:
        # Both sides set the group, as shells do, so neither order loses.
        with contextlib.suppress(OSError):
            os.setpgid(child, child)
    for fd in close:
        with contextlib.suppress(OSError):
            os.close(fd)
    if not forward and not DUTY:
        # Nothing to do but wait: stay in this process (see DUTY).
        os._exit(relay(child, forward=False, terminal=None))
    if agent_end is not None and gate_end is not None:
        agent_end.close()
        if not fresh:
            import gc

            # No finalizer of the caller's objects may run here: one that
            # closed a descriptor number the gate has since reused would
            # close the gate's socket instead.
            gc.disable()
            guard = _take(gate_end.detach(), _reporter(log, events))
            os._exit(relay(child, forward=forward, terminal=tty, guard=guard))
        gate_end.set_inheritable(True)
        for fd in (log, events):
            if fd is not None:
                os.set_inheritable(fd, True)
    argv[argv.index("--child") + 1] = str(child)
    try:
        os.execve(argv[0], argv, where)  # noqa: S606 - our own helper, argument vector built above
    except OSError:
        # No fresh interpreter to be had: be the gate in this process. The
        # caller's other threads, if any, live on beside it until it exits.
        guard = _take(gate_end.detach(), _reporter(log, events)) if gate_end is not None else None
        os._exit(relay(child, forward=forward, terminal=tty, guard=guard))


def detached(log: int | None = None) -> int:
    """Start a gate with no child, for `hlyn.on()` (5.2), and return its pid.

    It is started detached (a double fork, so the caller's `waitpid(-1)` or
    SIGCHLD handler never sees it) and takes the notification descriptor
    through `hand`, as `become`'s gate does. It exits once nothing uses the
    filter, or at once if the seal never happens. Its refusals go to `log`.
    """
    global _handoff, pid
    import subprocess

    from . import helpers

    agent_end, gate_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    argv = helpers.command("gate", "--child", "0", "--detach", "--notify", str(gate_end.fileno()),
                           *(["--log", str(log)] if log is not None else []))
    try:
        process = subprocess.Popen(  # noqa: S603 - our own helper, argument vector built above
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=[gate_end.fileno(), *([log] if log is not None else [])], start_new_session=True,
            cwd="/",
        )
    except OSError as exc:
        agent_end.close()
        raise _refused(f"the gate would not start ({exc.strerror or exc})") from None
    finally:
        gate_end.close()
    said = process.stdout.readline() if process.stdout is not None else b""
    process.wait()
    try:
        started = int(said)
    except ValueError:
        agent_end.close()
        raise _refused(f"the gate didn't say its pid ({said[:80]!r})") from None
    _handoff, pid = agent_end, started
    return started


def _refused(why: str) -> Exception:
    from .error import Unsupported

    return Unsupported(f"can't start the network gate: {why}. Nothing was sealed.")


def hand(fd: int, config: Config) -> None:
    """In the sealed process: give the gate the notification descriptor `fd`
    and the run's `config`, wait for it to say it has them, and close this
    process's copies. Called straight after the filter loads, before any
    agent code runs: a copy left here would let the agent answer its own
    connection checks (5.2, step 5; matrix row 19).

    Raises `Failed` if there is no gate or it doesn't answer; the network is
    then closed (every connect fails), never open.
    """
    global _handoff
    from .error import Failed

    chan, _handoff = _handoff, None
    try:
        if chan is None:
            raise Failed("no gate was started to answer this process's connections. "
                          "The network is closed; nothing reaches it.")
        chan.settimeout(TAKE)
        try:
            socket.send_fds(chan, [config.dumps()], [fd])
            took = chan.recv(1)
        except OSError as exc:
            raise Failed(f"the gate didn't take the connection checks ({exc}). "
                         "The network is closed; nothing reaches it.") from None
        if took != b"k":
            raise Failed("the gate exited before taking the connection checks. "
                         "The network is closed; nothing reaches it.")
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)
        if chan is not None:
            chan.close()


def _reporter(log: int | None, events: int | None) -> object:
    from .core.guard import Reporter

    return Reporter(log, events) if log is not None or events is not None else None


def _take(fd: int, tell: object = None) -> Guard | None:
    """In the gate: receive the descriptor and config from the sealed
    process, say so, and return the guard that answers them, reporting to
    `tell`. `None` if the process ended without sealing (its end closed with
    nothing sent)."""
    from .core.guard import Config, Guard

    chan = socket.socket(fileno=fd)
    fds: list[int] = []
    try:
        data, fds, _, _ = socket.recv_fds(chan, 65536, 1)
        if not fds:
            return None
        guard = Guard(fds[0], Config.loads(data), tell=tell)  # type: ignore[arg-type]
        chan.sendall(b"k")
        return guard
    except (OSError, ValueError, KeyError):
        # Unanswerable: close the descriptor, so every trapped call fails
        # (ENOSYS) instead of waiting forever. The sealed side gets no "k"
        # and says so.
        for got in fds:
            with contextlib.suppress(OSError):
                os.close(got)
        return None
    finally:
        chan.close()


def drop() -> None:
    """Let go of a gate that won't be handed anything (the seal failed): it
    sees the socket close and exits."""
    global _handoff, pid
    if _handoff is not None:
        _handoff.close()
    _handoff, pid = None, None


def relay(child: int, *, forward: bool, terminal: int | None, guard: Guard | None = None) -> int:
    """Wait for `child`, forwarding signals, and die or exit as it does.
    With `guard`, answer the child's connection checks meanwhile (Linux).

    Returns only when dying by the child's signal didn't take (a signal
    whose default is to be ignored), with 128 + the signal, as shells report.
    """
    group = os.getpgid(child) if terminal is not None else None

    def pass_on(number: int, _frame: object) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child, number)

    def resumed(number: int, _frame: object) -> None:
        # The shell continued this job: give the child back the terminal
        # before waking it, so its first read doesn't stop it again.
        if terminal is not None and group is not None:
            _give(terminal, group)
        pass_on(number, _frame)

    if forward:
        for number in _all() - KEEP:
            with contextlib.suppress(OSError, ValueError):
                signal.signal(number, resumed if number == signal.SIGCONT else pass_on)
    if guard is not None:
        found = _serve(child, forward, guard)
        if found is None:
            return 1  # reaped elsewhere: nothing left to report
        status = found
    else:
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        while True:
            try:
                _, status = os.waitpid(child, os.WUNTRACED)
            except ChildProcessError:
                return 1  # reaped elsewhere: nothing left to report
            if os.WIFSTOPPED(status):
                if forward:
                    # Stop with it, so the shell sees the job stop and takes the
                    # terminal back. SIGCONT on the gate resumes both (above).
                    os.kill(os.getpid(), signal.SIGSTOP)
                continue
            break

    if terminal is not None:
        _give(terminal, os.getpgrp())
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    death = os.WTERMSIG(status)
    import resource

    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # SIGKILL's and SIGSTOP's handlers can't be set, and needn't be: they
    # always take their default action.
    with contextlib.suppress(OSError, ValueError):
        signal.signal(death, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {death})
    os.kill(os.getpid(), death)
    return 128 + death


def _serve(child: int, forward: bool, guard: Guard) -> int | None:
    """Answer connection checks until `child` exits; return its wait status
    (`None` if it was reaped elsewhere). Hands the checks to a successor if
    programs it started still use the filter (see the module docstring)."""
    wake_r, wake_w = os.pipe()
    for fd in (wake_r, wake_w):
        os.set_blocking(fd, False)
    signal.set_wakeup_fd(wake_w)
    signal.signal(signal.SIGCHLD, lambda *_: None)
    signal.pthread_sigmask(signal.SIG_SETMASK, set())
    status: list[int | None] = []

    def done() -> bool:
        while True:
            try:
                found, got = os.waitpid(child, os.WNOHANG | os.WUNTRACED)
            except ChildProcessError:
                status.append(None)
                return True
            if not found:
                return False
            if os.WIFSTOPPED(got):
                if forward:
                    os.kill(os.getpid(), signal.SIGSTOP)
                continue
            status.append(got)
            return True

    guard.serve(stop=done, wake=wake_r)
    signal.set_wakeup_fd(-1)
    for fd in (wake_r, wake_w):
        os.close(fd)
    if not status:
        # Every task using the filter has gone; the child among them.
        try:
            _, got = os.waitpid(child, 0)
        except ChildProcessError:
            return None
        return got
    if _hung(guard.fd):
        guard.finish()  # the command was the last program using the filter
    elif os.fork() == 0:
        # The successor: the command has exited, programs it started have
        # not. Keep answering them; exit when they have all gone. It holds
        # nothing of its caller's: not its terminal, pipes or files.
        for number in _all() - KEEP:
            with contextlib.suppress(OSError, ValueError):
                signal.signal(number, signal.SIG_DFL)
        with contextlib.suppress(OSError):
            os.setsid()
        # Its refusals still go to the log and the report's pipe.
        told = [getattr(guard.tell, name, None) for name in ("log", "events")]
        _only({guard.fd, *guard.waits, *(fd for fd in told if isinstance(fd, int))})
        guard.serve()
        os._exit(0)
    return status[0]


def _only(keep: set[int]) -> None:
    """Close every descriptor but `keep`; standard input, output and error
    become /dev/null."""
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        if fd != null:
            os.dup2(null, fd)
    try:
        held = [int(name) for name in os.listdir("/proc/self/fd")]
    except OSError:
        held = list(range(3, 4096))
    for fd in held:
        if fd > 2 and fd not in keep:
            with contextlib.suppress(OSError):
                os.close(fd)


def prepare() -> None:
    """Load, before a fork, everything a gate serving in the forked process
    needs (see `become`'s `fresh`): after the fork nothing may be imported
    or dlopen'd, since another thread may have held those locks."""
    if DUTY:
        from .core import guard, notify

        del guard
        notify._lib()
        notify._sizes()


def _hung(fd: int) -> bool:
    """Whether no task uses the filter any more (the descriptor hung up)."""
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return any(event & (select.POLLHUP | select.POLLERR) for _, event in poll.poll(0))


def main(argv: Sequence[str] | None = None) -> int:
    """`gate --child PID [--forward] [--terminal] [--notify FD] [--detach]`:
    be the gate for PID (0: none, for `hlyn.on()`)."""
    import argparse

    parser = argparse.ArgumentParser(prog="hlyn gate", description="hlyn's gate (internal).")
    parser.add_argument("--child", type=int, required=True)
    parser.add_argument("--forward", action="store_true")
    parser.add_argument("--terminal", action="store_true")
    parser.add_argument("--notify", type=int, default=None)
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--log", type=int, default=None)
    parser.add_argument("--events", type=int, default=None)
    args = parser.parse_args(argv)
    if args.detach:
        # The classic double fork, with the caller's as the first: say the
        # real pid, then let the first process exit.
        started = os.fork()
        if started:
            os.write(1, f"{started}\n".encode())
            os._exit(0)
        with contextlib.suppress(OSError):
            os.setsid()
        null = os.open(os.devnull, os.O_RDWR)
        os.dup2(null, 1)  # the pipe the pid went out on: let it close
        os.close(null)
    guard = _take(args.notify, _reporter(args.log, args.events)) if args.notify is not None else None
    if args.child == 0:
        if guard is not None:
            guard.serve()
        return 0
    return relay(args.child, forward=args.forward, terminal=0 if args.terminal else None, guard=guard)
