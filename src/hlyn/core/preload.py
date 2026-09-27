# SPDX-License-Identifier: Apache-2.0
"""Hearing refusals on Linux: a preloaded library and a named pipe.

Landlock's own records go to kernel audit, which needs root and is usually
missing in containers; a seccomp supervisor would sit on every `open`. So
`hlyn run` preloads `libhlyn_report.so` (built from `native/report`) into the
command and everything it starts. It wraps the C library calls the boundary
can refuse and, when one fails with `EACCES` or `EPERM`, writes one line to a
named pipe this side owns. A call that succeeds costs one comparison.

What it cannot hear, so the report never implies otherwise: statically linked
programs (most Go binaries) do not load it; a program that clears its own
environment stops passing it on; `system()` and `popen()` start their shell
through glibc internals it cannot see.

What it hears comes from inside the confined program, which can write anything
to its end of the pipe. Every line is parsed strictly, bounded in size and
number, and then checked against the policy by `Report` before it is believed.
"""

from __future__ import annotations

import contextlib
import os
import re
import select
import shutil
import tempfile
from collections.abc import Mapping

from ..policy import Policy
from ..report import Denial

__all__ = ["Listener", "find", "parse", "static"]

NAME = "libhlyn_report.so"
VAR = "HLYN_REPORT"  # must match native/report/src/send.rs
ALL = "HLYN_REPORT_ALL"  # likewise: tell allowed calls too (hlyn watch)

# Bounds on what one run will take from the pipe. A record is at most
# PIPE_BUF bytes by construction; anything longer without a newline is not a
# record and is thrown away.
LINE = 4096
LINES = 100_000

KINDS = frozenset({"read", "write", "exec", "net", "bind"})
OP = re.compile(rb"^[a-z_0-9]{1,24}$")
ESCAPE = re.compile(rb"%([0-9A-F]{2})")
WELL = re.compile(rb"(?:[^%]|%[0-9A-F]{2})*", re.DOTALL)


def find() -> str | None:
    """Where the reporting library is, if it was built or installed."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    places = [os.path.join(here, NAME)]  # installed alongside the package
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        places.append(os.path.join(os.path.dirname(shim), NAME))
    places.append(os.path.join(root, "native", "report", "target", "release", NAME))  # built here
    for place in places:
        if os.path.isfile(place):
            return os.path.realpath(place)
    return None


def static(path: str) -> bool:
    """True if `path` is an ELF program with no dynamic loader.

    Such a program never loads the reporter, so a run of one hears nothing --
    which the report should say, rather than let silence read as "nothing was
    blocked". Only the ELF header and program headers are read.
    """
    import struct

    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if len(head) < 64 or head[:4] != b"\x7fELF" or head[4] != 2:  # 64-bit only
                return False
            order = "<" if head[5] == 1 else ">"
            phoff, = struct.unpack_from(order + "Q", head, 32)
            size, count = struct.unpack_from(order + "HH", head, 54)
            if not 0 < count <= 128 or size < 4:
                return False
            fh.seek(phoff)
            table = fh.read(size * count)
    except OSError:
        return False
    kinds = [struct.unpack_from(order + "I", table, i * size)[0] for i in range(len(table) // size)]
    return 3 not in kinds  # PT_INTERP


def _widen(value: tuple[str, ...] | bool, item: str) -> tuple[str, ...] | bool:
    if value is True:
        return True
    return (*(value or ()), item)


def _unescape(field: bytes) -> bytes | None:
    """Undo the library's `%XX` escaping, or None if the field is malformed."""
    if b"%" not in field:
        return field
    # A `%` that does not start a valid escape did not come from the library.
    if not WELL.fullmatch(field):
        return None
    return ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), field)


def parse(line: bytes, uses: bool = False) -> Denial | None:
    """One record, or None for anything that is not exactly one.

    `hlyn1 kind op errno target pid comm cut count`, tab-separated. A refusal
    carries errno 1 or 13; with `uses` (`hlyn watch`), only a call that was
    allowed (errno 0) is accepted instead, so neither kind can pass for the
    other.
    """
    fields = line.split(b"\t")
    if len(fields) != 9 or fields[0] != b"hlyn1":
        return None
    _, kind, op, err, target, pid, comm, cut, count = fields
    try:
        name = kind.decode("ascii")
    except UnicodeDecodeError:
        return None
    if name not in KINDS or not OP.match(op):
        return None
    if err not in ((b"0",) if uses else (b"1", b"13")) or cut not in (b"0", b"1"):
        return None
    if not (pid.isdigit() and len(pid) <= 10 and count.isdigit() and len(count) <= 10):
        return None
    who = _unescape(comm)
    what = _unescape(target)
    if who is None or what is None or len(who) > 64 or not what:
        return None
    return Denial(
        kind=name,
        target=os.fsdecode(what),
        op=op.decode("ascii"),
        by=os.fsdecode(who),
        pid=int(pid),
        count=max(1, int(count)),
        source="program",
    )


class Listener:
    """Reads refusal records from a named pipe the command writes to."""

    source = "program"
    tag: str | None = None

    def __init__(self, uses: bool = False) -> None:
        self.uses = uses  # hlyn watch: hear what was allowed, not what was refused
        self.why: str | None = None
        self.lib = find()
        self.box: str | None = None
        self.pipe: str | None = None
        self._r = -1
        self._w = -1
        self._rest = b""
        self._lines = 0
        if self.lib is None:
            self.why = (
                f"{NAME} was not found; build it with `cargo build --release` in native/report"
            )
            return
        try:
            self.box = tempfile.mkdtemp(prefix="hlyn-report-")  # 0700
            self.pipe = os.path.join(self.box, "pipe")
            os.mkfifo(self.pipe, 0o600)
            self._r = os.open(self.pipe, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            # Held open for the whole run. Writers come and go, one per
            # record; without a writer of our own, the reading end would see
            # end-of-file between records and select would spin on it.
            self._w = os.open(self.pipe, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            # Writers never block, so a full pipe loses records. 64 KiB is the
            # default -- a few hundred records -- which a burst from many
            # threads outruns between two reads. 1 MiB is the most an
            # unprivileged process may ask for.
            with contextlib.suppress(OSError, AttributeError):
                import fcntl

                fcntl.fcntl(self._r, fcntl.F_SETPIPE_SZ, 1 << 20)  # type: ignore[attr-defined,unused-ignore]  # Linux only
        except OSError as exc:
            self.why = f"the report pipe could not be created ({exc.strerror})"
            self.close()
            self.lib = None

    def grant(self, plan: Policy) -> Policy:
        """The library must be readable to load, and the pipe writable.

        Both are single files hlyn created or ships, and both appear in the
        seal record like any other grant.
        """
        if self.lib is None or self.pipe is None:
            return plan
        return plan.with_(read=_widen(plan.read, self.lib), write=_widen(plan.write, self.pipe))

    def env(self, keep: Mapping[str, str]) -> dict[str, str]:
        if self.lib is None or self.pipe is None:
            return {}
        theirs = keep.get("LD_PRELOAD")
        out = {
            "LD_PRELOAD": f"{self.lib}:{theirs}" if theirs else self.lib,
            VAR: self.pipe,
        }
        if self.uses:
            out[ALL] = "1"
        return out

    def start(self) -> None:
        pass

    def fileno(self) -> int | None:
        return self._r if self._r >= 0 else None

    def read(self) -> list[Denial]:
        out: list[Denial] = []
        if self._r < 0:
            return out
        for _ in range(64):  # bounded work per wake-up; the loop comes back
            try:
                chunk = os.read(self._r, 65536)
            except BlockingIOError:
                break
            except OSError:
                break
            if not chunk:
                break
            data = self._rest + chunk
            *lines, self._rest = data.split(b"\n")
            if len(self._rest) > LINE:
                self._rest = b""
            for line in lines:
                if self._lines >= LINES:
                    continue  # keep draining so writers never stall
                self._lines += 1
                found = parse(line, self.uses)
                if found is not None:
                    out.append(found)
        return out

    def finish(self) -> list[Denial]:
        """What is still in the pipe once the command has exited."""
        out = self.read()
        if self._r >= 0:
            # A child that outlived the command may be mid-write; a moment is
            # enough for what was already on its way.
            with contextlib.suppress(OSError):
                select.select([self._r], [], [], 0.05)
            out.extend(self.read())
        return out

    def close(self) -> None:
        for fd in (self._r, self._w):
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self._r = self._w = -1
        if self.box:
            shutil.rmtree(self.box, ignore_errors=True)
            self.box = None
