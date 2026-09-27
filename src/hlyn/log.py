"""A structured record of what the boundary did.

One JSON object per line, to stderr by default so nothing needs a writable
path, or to a file when the policy names one.

What this can and cannot see is worth being exact about, because an
observability layer that implies more than it observes is its own kind of lie.

It records what *we* did: the boundary applied, the grants in it, and every
refusal that passes back through this library.

The kernel's own refusals are not something a confined process can see: when
Landlock denies a read, the agent gets `EACCES` straight from the syscall and
no userspace code is consulted, which is why the boundary is cheap and cannot
be talked out of. `hlyn run` hears them from outside instead, and writes a
`deny` record for each as it happens -- see `report.py` and the listeners in
`core/`. `hlyn.on()` has nobody outside to listen, so it records only the seal.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from typing import Any, TextIO

__all__ = ["allow", "deny", "emit", "off", "seal", "sink", "totals"]


_where: TextIO | None = None
_on = True

# How many times each distinct record has been seen. See `_often` for why the
# same refusal repeated four hundred times is not four hundred lines.
_seen: dict[str, int] = {}

# A cap on how many *distinct* records are tracked. A tight policy denies a
# bounded set of things over and over, which is the case this exists for; an
# agent walking a large tree produces unbounded distinct records, and a log
# module must not be the thing that exhausts memory. Past the cap, nothing new
# is tracked and records are written as they arrive.
LIMIT = 10_000


def sink(target: bool | str | TextIO = True) -> None:
    """Choose where records go: stderr, a file path, an open stream, or off."""
    global _where, _on
    if target is False:
        _on = False
        return
    _on = True
    if target is True:
        _where = None  # resolved to stderr at write time
    elif isinstance(target, str):
        # Held open for the life of the process on purpose: this is a sink,
        # not a one-shot write, and reopening per record would lose ordering
        # between agents sharing a file.
        _where = open(target, "a", buffering=1, encoding="utf-8")  # noqa: SIM115
    else:
        _where = target


def off() -> None:
    """Stop recording."""
    global _on
    _on = False


def _often(kind: str, fields: dict[str, Any]) -> int | None:
    """How many times this exact record has been seen, or None to not track it.

    One startup under a tight policy refuses the same handful of things over
    and over -- the same missing config file, on every retry, in every worker.
    Written out in full that is hundreds of identical lines burying the three
    that differ, which is how a log stops being read.

    So a record is written on the 1st, 2nd, 4th, 8th, 16th ... occurrence, and
    counted silently in between. The shape of the problem is still visible, the
    running total is on every line that does get written, and nothing needs to
    survive to the end of the process for the log to be useful -- which matters
    here, because a process refused by seccomp is killed rather than exiting.
    """
    key = json.dumps([kind, fields], sort_keys=True, default=str)
    if key not in _seen and len(_seen) >= LIMIT:
        return None
    count = _seen[key] = _seen.get(key, 0) + 1
    return count


def totals() -> dict[str, int]:
    """Every distinct record seen so far, and how often. For a final rollup."""
    return {key: count for key, count in _seen.items() if count > 1}


def emit(kind: str, **fields: Any) -> None:
    """Write one record. Never raises: logging must not break the agent.

    Repeats are collapsed rather than written out one by one; see `_often`.
    """
    if not _on:
        return

    # Never raises: a record that cannot be written must not take the agent
    # down with it. The boundary is what matters; the log is evidence about it.
    with contextlib.suppress(Exception):
        seen = _often(kind, fields)
        if seen is not None and seen > 1 and seen & (seen - 1):
            return  # not a power of two, so counted and not written
        row: dict[str, Any] = {"t": round(time.time(), 3), "kind": kind, "pid": os.getpid()}
        row.update(fields)
        if seen is not None and seen > 1:
            row["seen"] = seen
        stream = _where if _where is not None else sys.stderr
        stream.write(json.dumps(row, default=str) + "\n")
        stream.flush()


def _shape(value: Any) -> Any:
    """Render a policy field compactly, without leaking a huge path list."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, tuple):
        items = [item if isinstance(item, (str, int)) else str(item) for item in value]
        return items if len(items) <= 12 else [*items[:12], f"+{len(items) - 12} more"]
    return value


def seal(policy: Any, backend: str, level: Any, tmp: str | None = None) -> None:
    """Record the boundary that was applied. The one record that always matters."""
    emit(
        "seal",
        backend=backend.rsplit(".", 1)[-1],
        level=level,
        read=_shape(policy.read),
        write=_shape(policy.write),
        exec=_shape(policy.exec),
        net=_shape(policy.net),
        env=_shape(policy.env),
        tmp=tmp,
    )


def deny(what: str, why: str, **fields: Any) -> None:
    """Record something this library refused."""
    emit("deny", what=what, why=why, **fields)


def allow(what: str, **fields: Any) -> None:
    """Record something this library permitted."""
    emit("allow", what=what, **fields)
