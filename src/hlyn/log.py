"""A structured record of what the boundary did.

One JSON object per line, to stderr by default so nothing needs a writable
path, or to a file when the policy names one.

What this can and cannot see is worth being exact about, because an
observability layer that implies more than it observes is its own kind of lie.

It records what *we* did: the boundary applied, the grants in it, and every
refusal that passes back through this library, including the tool calls that
framework hooks route through it.

It does not see kernel refusals as they happen. When Landlock denies a read the
agent gets `EACCES` directly from the syscall; no userspace code is consulted,
which is exactly why the boundary is cheap and cannot be talked out of. Catching
those as they occur needs `SECCOMP_RET_USER_NOTIF` and a supervisor, which this
version deliberately does not have.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, TextIO

__all__ = ["emit", "sink", "seal", "deny", "allow", "off"]


_where: TextIO | None = None
_on = True


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
        _where = open(target, "a", buffering=1, encoding="utf-8")
    else:
        _where = target


def off() -> None:
    """Stop recording."""
    global _on
    _on = False


def emit(kind: str, **fields: Any) -> None:
    """Write one record. Never raises: logging must not break the agent."""
    if not _on:
        return
    row = {"t": round(time.time(), 3), "kind": kind, "pid": os.getpid(), **fields}
    try:
        stream = _where if _where is not None else sys.stderr
        stream.write(json.dumps(row, default=str) + "\n")
        stream.flush()
    except Exception:
        pass


def _shape(value: Any) -> Any:
    """Render a policy field compactly, without leaking a huge path list."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, tuple):
        return list(value) if len(value) <= 12 else [*value[:12], f"+{len(value) - 12} more"]
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
