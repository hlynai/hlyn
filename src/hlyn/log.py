# SPDX-License-Identifier: Apache-2.0
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
import errno
import json
import os
import stat
import sys
import time
from collections.abc import Iterable
from typing import Any, TextIO

__all__ = ["allow", "deny", "emit", "fileno", "line", "off", "record", "seal", "sink", "totals"]


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


def sink(target: bool | str | TextIO = True, writable: Iterable[str] | bool = ()) -> None:
    """Choose where records go: stderr, a file path, an open stream, or off.

    A path is opened through `record`, which refuses a link, a file with a
    second name, and a file inside `writable` (the agent's write grants).
    """
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
        # between agents sharing a file. A copy of `record`'s descriptor, so
        # every writer in this process writes through the one file checked.
        _where = os.fdopen(os.dup(record(target, writable)), "a", buffering=1, encoding="utf-8")
    else:
        _where = target


# The record's descriptor, per path, opened once by `record`, with the file's
# identity: a process that closes descriptors before sealing (`fds.shut`) may
# reuse the number for something else.
_held: dict[str, int] = {}
_ids: dict[str, tuple[int, int]] = {}
_where_of: dict[str, str] = {}


def record(path: str, writable: Iterable[str] | bool = ()) -> int:
    """The descriptor the record at `path` is written through, opened once.

    Every channel (this module's sink, the proxy's and the gate's denials)
    writes through this one descriptor, so they all write the file that was
    checked, and only it:

    - The folder is opened first and the file opened relative to it with
      `O_NOFOLLOW`: a link as the last component is refused (`ELOOP`), and a
      link swapped in for a folder after the check can't redirect the open,
      since what is checked is the folder actually opened.
    - The opened file must be a regular file with one name (`st_nlink == 1`):
      a hard link elsewhere would be a second way in.
    - The opened folder, by its real path, must be outside every `writable`
      grant: the agent could otherwise unlink the file and leave a forgery.

    Raises `ValueError` (`policy.Invalid`) with what to change.
    """
    from .error import Invalid

    key = os.path.abspath(os.path.expanduser(path))
    if key in _held:
        try:
            info = os.fstat(_held[key])
            if (info.st_dev, info.st_ino) == _ids[key]:
                _outside(path, _where_of[key], writable)  # the grants may be new since
                return _held[key]
        except OSError:
            pass
        # Closed since (or the number reused): open and check it again.
        del _held[key]
    folder, name = os.path.split(key)
    directory = os.open(folder or os.sep, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    fd, made = -1, False
    try:
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            try:
                fd, made = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory), True
            except FileExistsError:
                fd = os.open(name, flags, dir_fd=directory)
        except OSError as error:
            if error.errno == errno.ELOOP:  # O_NOFOLLOW met a link
                raise Invalid(f"log: {path} is a link. hlyn writes the record only to a plain file; "
                              f"name a file, not a link.") from None
            raise
        where = _folder(directory, folder)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Invalid(f"log: {path} is not a regular file. Name a file.")
        if info.st_nlink != 1:
            raise Invalid(f"log: {path} has another name (a hard link), and the agent could write it "
                          f"through that one. Use a new file.")
        _outside(path, where, writable)
    except BaseException:
        if fd >= 0:
            os.close(fd)
            if made:  # don't leave an empty record behind where it was refused
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=directory)
        raise
    finally:
        os.close(directory)
    _held[key], _ids[key], _where_of[key] = fd, (info.st_dev, info.st_ino), where
    return fd


def _outside(path: str, where: str, writable: Iterable[str] | bool) -> None:
    """Refuse a record whose folder (`where`, the one actually opened) the
    agent can write: it could delete the file and leave a forged one."""
    from .error import Invalid
    from .policy import under

    if writable is True:
        raise Invalid(f"log: the agent can write every folder (write=True), so it could replace "
                      f"{path}. Use a narrower write grant, or no log file.")
    root = next((item for item in writable or () if under(where, os.path.realpath(item))), None)
    if root:
        raise Invalid(f"log: {path} is inside {root}, which the agent can write: it could delete the "
                      f"record and leave a forged one in its place. "
                      f"Put the log outside every --write folder.")


def _folder(directory: int, fallback: str) -> str:
    """The real path of an open folder: the one actually opened, whatever a
    name for it leads to now."""
    if sys.platform == "linux":
        with contextlib.suppress(OSError):
            return os.readlink(f"/proc/self/fd/{directory}")
    if sys.platform == "darwin":
        import fcntl

        with contextlib.suppress(OSError, AttributeError):
            found = fcntl.fcntl(directory, fcntl.F_GETPATH, bytes(1024))
            return os.fsdecode(found.split(b"\0", 1)[0])
    return os.path.realpath(fallback)


def off() -> None:
    """Stop recording."""
    global _on
    _on = False


def _often(kind: str, fields: dict[str, Any], seen: dict[str, int] | None = None) -> int | None:
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
    book = _seen if seen is None else seen
    key = json.dumps([kind, fields], sort_keys=True, default=str)
    if key not in book and len(book) >= LIMIT:
        return None
    count = book[key] = book.get(key, 0) + 1
    return count


def line(kind: str, fields: dict[str, Any], seen: dict[str, int], pid: int | None = None) -> str | None:
    """One record as a JSON line, or None when `_often` says to count it only.

    `seen` is the caller's own tally, so a process writing to several logs
    (hlyn's proxy, one per run) collapses repeats per log. `emit` is this
    with the module's own tally and sink.
    """
    count = _often(kind, fields, seen)
    if count is not None and count > 1 and count & (count - 1):
        return None  # not a power of two, so counted and not written
    row: dict[str, Any] = {"t": round(time.time(), 3), "kind": kind, "pid": pid or os.getpid()}
    row.update(fields)
    if count is not None and count > 1:
        row["seen"] = count
    return json.dumps(row, default=str)


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
        text = line(kind, fields, _seen)
        if text is None:
            return
        stream = _where if _where is not None else sys.stderr
        stream.write(text + "\n")
        stream.flush()


def fileno() -> int | None:
    """The descriptor records go to, for handing to a helper process.

    `None` when recording is off. Raises `ValueError` when the sink is a
    stream with no descriptor (an `io.StringIO`), which another process
    cannot write to.
    """
    if not _on:
        return None
    stream = _where if _where is not None else sys.stderr
    try:
        return int(stream.fileno())
    except (AttributeError, OSError, ValueError):
        raise ValueError("the log is an in-memory stream") from None


def _shape(value: Any) -> Any:
    """Render a policy field compactly, without leaking a huge path list."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, tuple):
        items = [item if isinstance(item, (str, int)) else str(item) for item in value]
        return items if len(items) <= 12 else [*items[:12], f"+{len(items) - 12} more"]
    return value


def seal(policy: Any, backend: str, level: Any, tmp: str | None = None, **more: Any) -> None:
    """Record the boundary that was applied. The one record that always matters.

    `more` carries what host mode adds (design 4.6): the proxy's address, the
    helpers' pids, and whether its denials can reach this log.
    """
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
        effective=_effective(policy),
        **more,
    )


def _effective(policy: Any) -> dict[str, Any]:
    """Every path the kernel was told to allow, in full: what was typed plus
    what hlyn adds on its own (the runtime, the network's files, `tmp`). The
    typed fields above say what was asked for; this says what was granted, so
    a reader of the record never has to trust that the two are the same."""
    out: dict[str, Any] = {}
    for name in ("reads", "writes"):
        try:
            found = getattr(policy, name)()
        except Exception as error:  # noqa: BLE001 - the record must still be written
            found = f"unknown: {error}"
        out[name.removesuffix("s")] = found if found is True or isinstance(found, str) else list(found)
    return out


def deny(what: str, why: str, **fields: Any) -> None:
    """Record something this library refused."""
    emit("deny", what=what, why=why, **fields)


def allow(what: str, **fields: Any) -> None:
    """Record something this library permitted."""
    emit("allow", what=what, **fields)
