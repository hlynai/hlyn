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
"""

from __future__ import annotations

import contextlib
import os
import signal
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

__all__ = ["become", "main", "relay"]

# Signals the gate never forwards: the two it can't catch, the one that
# reports on the child itself, and the terminal's stop signals for
# background reads and writes, which only ever concern the gate's own use
# of the terminal. SIGCONT is forwarded, by its own handler.
KEEP = {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD, signal.SIGTTIN, signal.SIGTTOU}

# Whether the gate has work beyond waiting and passing on signals on this
# platform. On Linux it will answer the kernel's connection checks (design
# phase 4); on macOS it has none. A gate that only waits needs no fresh
# interpreter: `waitpid` and `_exit` are safe straight after `fork`, whatever
# the caller's threads held -- the hazard a fresh interpreter avoids (5.1).
DUTY = False


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
) -> NoReturn:
    """Fork. The child runs `body`, which must seal and exec or exit; the
    parent becomes the gate for it and exits as the child does.

    `forward` passes signals on (for `spawn` and `hlyn run`, where the
    original process stands for the command). `isolate` gives the child its
    own process group, and the terminal when there is one in the foreground.
    `close` lists descriptors the gate must not keep: whatever the child
    alone should hold, such as the proxy's lifetime pipe.

    Every signal is blocked across the fork and the exec that follows, so
    one sent in between waits for the gate's handlers instead of killing it
    and leaving the child without a parent.
    """
    import resource  # noqa: F401 - loaded now: relay() needs it, and nothing may be imported after fork

    from . import helpers

    tty = _terminal() if isolate else None
    # Built before the fork: after it, the parent does as little as possible.
    argv = helpers.command("gate", "--child", "0", *(["--forward"] if forward else []),
                          *(["--terminal"] if tty is not None else []))
    where = {key: value for key, value in os.environ.items() if key in ("PATH", "LANG", "LC_ALL")}
    if getattr(sys, "frozen", False):
        where = dict(os.environ)
    before = signal.pthread_sigmask(signal.SIG_BLOCK, _all())
    child = os.fork()
    if child == 0:
        code = 1
        try:
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
    argv[argv.index("--child") + 1] = str(child)
    try:
        os.execve(argv[0], argv, where)  # noqa: S606 - our own helper, argument vector built above
    except OSError:
        # No fresh interpreter to be had: be the gate in this process. The
        # caller's other threads, if any, live on beside it until it exits.
        os._exit(relay(child, forward=forward, terminal=tty))


def relay(child: int, *, forward: bool, terminal: int | None) -> int:
    """Wait for `child`, forwarding signals, and die or exit as it does.

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


def main(argv: Sequence[str] | None = None) -> int:
    """`gate --child PID [--forward] [--terminal]`: be the gate for PID."""
    import argparse

    parser = argparse.ArgumentParser(prog="hlyn gate", description="hlyn's gate (internal).")
    parser.add_argument("--child", type=int, required=True)
    parser.add_argument("--forward", action="store_true")
    parser.add_argument("--terminal", action="store_true")
    args = parser.parse_args(argv)
    return relay(args.child, forward=args.forward, terminal=0 if args.terminal else None)
