"""Watch an agent run, then write down what it actually touched.

The hardest part of adopting deny-by-default is not the enforcement. It is
that nobody knows what their agent opens. The honest first policy is therefore
not written, it is observed: run the thing once with nothing confined, record
every path and port it reaches for, and turn that into a starting point someone
can narrow.

    hlyn watch -- python agent.py        run it, then print a policy

    import hlyn.watch
    hlyn.watch.start()                   record in this process
    ...
    hlyn.watch.suggest()                 -> Policy

**This is not a boundary and must never be mistaken for one.** Nothing is
confined while watching; the agent has whatever it had before. The output is a
draft to read and cut down, not a policy to trust -- if the agent was already
doing something it should not, watching it faithfully records that as a grant.

What it sees, and what it does not, stated plainly because the gap matters:

  * It uses CPython's audit hooks, so it observes what *Python* does -- `open`,
    `connect`, `subprocess`, and the rest of PEP 578's events. That covers the
    agent's own code and almost every library it calls.
  * It does not see a C extension that calls `open(2)` directly without going
    through Python, and it does not see inside a child process unless that
    child is also watched. `hlyn watch` arranges the latter for child Pythons;
    nothing can arrange the former.
  * So a policy built from this can be too *narrow*, and the agent will hit a
    refusal the watch run never predicted. That failure is loud, safe, and
    fixable. It is the right direction to be wrong in.

Like confinement itself, this is one-way: CPython does not allow an audit hook
to be removed once installed, so a process that has started watching is
watching until it exits.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from typing import Any

from .policy import Policy, prune, runtime, under

__all__ = ["seen", "start", "suggest", "watching"]


# Where an observation lands: (kind, value). Kept as a plain set so recording
# stays cheap -- this hook runs on every `open` the agent performs, and a watch
# that measurably slows the run is one nobody leaves on long enough to be
# useful.
_seen: set[tuple[str, str]] = set()
_on = False
_out: str | None = None

# Directories with this many distinct files touched are named as a directory in
# the suggested policy rather than file by file. Two is deliberate: one file is
# a file, and a second one in the same place says the agent is working in a
# directory rather than reaching for one thing.
TOGETHER = 2

# The environment variable `hlyn watch` uses to tell a child process where to
# write what it saw.
CHANNEL = "HLYN_WATCH"


def watching() -> bool:
    """True if this process is recording."""
    return _on


def seen() -> list[tuple[str, str]]:
    """Everything observed so far, as (kind, value) pairs."""
    return sorted(_seen)


def _writes(mode: object, flags: object) -> bool:
    """Whether an `open` event is asking to modify the file.

    Both forms have to be read: `io.open` reports a mode string and no useful
    flags, `os.open` reports flags and no mode. Anything ambiguous counts as a
    write, because a path in the write list that only needed reading is a
    policy that is too loose by one line, while the reverse breaks the agent.
    """
    if isinstance(mode, str):
        return any(ch in mode for ch in "wax+")
    if isinstance(flags, int):
        wanted = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
        return bool(flags & wanted)
    return False


def _path(kind: str, value: object) -> None:
    """Record a path observation, or quietly decline to.

    Non-paths are dropped rather than coerced, and the `open` event is why:
    its first argument is a file descriptor when the caller opened one, so an
    `int` arriving here is a number like `3`, not a place. Treating it as a
    path yields a relative grant for a file called "3", whose directory is the
    empty string -- a policy that is both meaningless and refused.
    """
    if isinstance(value, bool) or not isinstance(value, (str, os.PathLike)):
        return
    text = os.fspath(value)
    if text:
        _seen.add((kind, os.path.abspath(text)))


def _port(value: object) -> None:
    """Record a port observation."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536:
        _seen.add(("net", str(value)))


def _hook(event: str, args: tuple[Any, ...]) -> None:
    """The audit hook itself.

    Runs on every audited operation in the process, so it does the least
    possible and never raises. An exception here would propagate into whatever
    the agent was doing, which would make watching more dangerous than not
    watching.
    """
    with contextlib.suppress(Exception):  # a hook that raises breaks the agent it watches
        if event == "open":
            path = args[0] if args else None
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            _path("write" if _writes(mode, flags) else "read", path)
        elif event == "socket.connect":
            where = args[1] if len(args) > 1 else None
            # AF_INET and AF_INET6 both put the port second. A Unix socket
            # address is a path and has no port, so it is skipped: Landlock
            # scoping governs those, and `net` does not describe them.
            if isinstance(where, tuple) and len(where) >= 2:
                _port(where[1])
        elif event in ("subprocess.Popen", "os.exec"):
            _path("exec", args[0] if args else None)
        elif event == "os.system":
            # The command is a shell line, not a path, so the shell itself is
            # what has to be runnable. Recording the line would produce a grant
            # that cannot be enforced.
            _path("exec", "/bin/sh")
        elif event in ("os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.truncate"):
            _path("write", args[0] if args else None)


def start(out: str | None = None) -> None:
    """Begin recording. One-way, and confines nothing.

    `out` names a file to write the observations to when the process exits,
    which is how `hlyn watch` collects from a child it did not import.
    """
    global _on, _out
    if _on:
        return
    _on = True
    _out = out or os.environ.get(CHANNEL) or None
    if _out:
        import atexit

        atexit.register(_save)
    sys.addaudithook(_hook)


def _save() -> None:
    """Write observations out for a parent process to read."""
    if not _out:
        return
    # Never raises: this runs at interpreter shutdown, where an exception is
    # both useless and alarming.
    with contextlib.suppress(Exception), open(_out, "w", encoding="utf-8") as fh:
        json.dump(seen(), fh)


def _load(path: str) -> None:
    """Take observations recorded by another process.

    An unreadable or malformed file means no observations, not a crash: the
    child may have been killed before writing, which is a thing to report as
    "nothing was recorded" rather than a traceback about JSON.
    """
    with contextlib.suppress(Exception), open(path, encoding="utf-8") as fh:
        for kind, value in json.load(fh):
            _seen.add((kind, value))


def _tidy(paths: list[str]) -> tuple[str, ...]:
    """Turn a list of touched files into the shortest honest set of grants.

    Two files in the same directory become the directory. One file stays a
    file. It is a guess either way, which is the whole reason the output is a
    draft: the alternative is naming four hundred stdlib files individually,
    which nobody reads and nobody would keep.
    """
    crowd: dict[str, int] = {}
    for item in paths:
        crowd[os.path.dirname(item)] = crowd.get(os.path.dirname(item), 0) + 1
    out = []
    for item in paths:
        home = os.path.dirname(item)
        # A path with no directory part cannot be collapsed into one. Nothing
        # observed should be relative, and if something is, granting the empty
        # string would be refused by `Policy` several steps later, where it is
        # far harder to trace back to here.
        out.append(home if home and crowd.get(home, 0) >= TOGETHER else item)
    return prune(item for item in out if item)


def _mine(path: str, skip: tuple[str, ...]) -> bool:
    """Whether a path is the agent's business rather than the runtime's.

    Everything the interpreter needs is granted automatically by every policy,
    so listing it again would bury the handful of paths that are actually a
    decision in several hundred that are not.
    """
    return not any(under(path, root) for root in skip)


def suggest(**edits: Any) -> Policy:
    """A policy covering what was observed. A draft, not a verdict.

    Read it, cut it down, and check it in. What comes out is exactly as wide as
    the run that produced it -- a code path not taken is a grant not made, so a
    watch over one happy path will be too narrow for the next failure.
    """
    # The scratch directory is excluded because every policy already provides
    # one: `tmp=True` hands the agent a fresh private directory, so recording
    # the last run's temporary files would grant a path that no longer exists.
    skip = (*runtime(), os.path.abspath(tempfile.gettempdir()))

    reads = [v for k, v in _seen if k == "read" and _mine(v, skip)]
    writes = [v for k, v in _seen if k == "write" and _mine(v, skip)]
    runs = [v for k, v in _seen if k == "exec"]
    net = sorted({int(v) for k, v in _seen if k == "net"})

    # A path opened for writing is already readable under any policy that
    # grants the write, so repeating it in `read` is noise in a document whose
    # whole job is being read.
    kept = _tidy(writes)
    reads = [item for item in reads if not any(under(item, done) for done in kept)]

    plan: dict[str, Any] = {
        "read": _tidy(reads),
        "write": kept,
        "exec": prune(runs) if runs else False,
        "net": tuple(net) if net else False,
    }
    plan.update(edits)
    return Policy(**plan)
