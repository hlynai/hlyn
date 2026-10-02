# SPDX-License-Identifier: Apache-2.0
"""Descriptors the launcher handed down (FINDINGS.md, "Inherited file descriptors").

Landlock and Seatbelt check opening a path, not using a descriptor that is
already open. A file outside every grant, or a connected unix socket (to
`docker.sock`, to `ssh-agent`), that the launcher left open at descriptor 9
works after the seal. So before sealing, the command's own process drops
what it was handed:

- `hlyn run` and `hlyn.spawn` end in an exec, which already closes every
  descriptor Python made (they are close-on-exec). What survives is what the
  launcher left inheritable, so `shut` closes exactly those, as
  `subprocess`'s `close_fds` does, except the ones named in `keep`.
- `hlyn.run(fn)` has no exec: `fn` can use any descriptor the caller held.
  `shut(everything=True)` puts /dev/null over each one instead of closing it
  (as `route.neutralise` does for sockets), so the number stays taken and a
  Python object that closes it later closes the /dev/null copy, never a file
  that reused the number.
- `hlyn.on()` can't take descriptors from its caller, who still needs them:
  `outside` finds the ones that point outside the grants, and `warning`
  says so.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from .error import Invalid
from .policy import under

if TYPE_CHECKING:
    from .policy import Policy

__all__ = ["Handed", "Inherited", "keeps", "numbers", "outside", "shut", "warning"]

_PATH = 50  # fcntl.F_GETPATH on macOS: the path a descriptor was opened as


class Inherited(UserWarning):
    """`hlyn.on()` found open descriptors that point outside the grants.

    A warning, not a refusal: the caller may need them. They would keep
    working after the seal. Filter it like any other
    (`warnings.simplefilter("ignore", hlyn.Inherited)`), or make it an error.
    """


class Handed:
    """One open descriptor that points outside the grants."""

    __slots__ = ("fd", "what")

    def __init__(self, fd: int, what: str) -> None:
        self.fd, self.what = fd, what

    def __str__(self) -> str:
        return f"fd {self.fd} {self.what}"


def numbers() -> list[int]:
    """Every descriptor number this process holds (the listing's own may be
    among them, already closed: callers skip what fails)."""
    where = "/dev/fd" if sys.platform == "darwin" else "/proc/self/fd"
    try:
        return sorted(int(name) for name in os.listdir(where) if name.isdigit())
    except OSError:
        # Unlistable, as inside another hlyn seal (no /proc): ask every
        # descriptor number this process may hold instead.
        import resource

        return list(range(min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 65536)))


def keeps(fds: Iterable[int] | int | None) -> tuple[int, ...]:
    """`fds` checked, for a launcher that means to hand them on (`--keep-fd`,
    `keep_fds=`): whole numbers above 2 that are open now. Raises `Invalid`,
    before anything is changed, saying what to do."""
    if fds is None:
        return ()
    items = [fds] if isinstance(fds, int) else list(fds)
    out: list[int] = []
    for fd in items:
        if isinstance(fd, bool) or not isinstance(fd, int):
            raise Invalid(f"keep_fds takes descriptor numbers (whole numbers), not {fd!r}.")
        if fd < 3:
            raise Invalid(f"descriptor {fd} is stdin, stdout or stderr: those always pass. Name 3 and up.")
        try:
            os.fstat(fd)
        except OSError:
            raise Invalid(
                f"descriptor {fd} isn't open, so there is nothing to keep. Open it before starting, "
                f"for example: hlyn run --keep-fd {fd} -- CMD {fd}<FILE"
            ) from None
        if fd not in out:
            out.append(fd)
    return tuple(out)


def shut(keep: Iterable[int] = (), everything: bool = False) -> int:
    """In a process about to seal: drop the descriptors above 2 that the
    launcher handed down, except `keep`. Returns how many.

    By default only inheritable ones are closed (the rest end at the exec,
    and hlyn's own are among them). `everything` covers the rest too, by
    putting /dev/null over them; then `keep` must name every descriptor
    hlyn still needs.
    """
    kept = {0, 1, 2, *keep}
    found = 0
    null = os.open(os.devnull, os.O_RDWR) if everything else -1
    try:
        for fd in numbers():
            if fd in kept or fd == null:
                continue
            try:
                inherit = os.get_inheritable(fd)  # fails for the listing's own, already closed
                if everything:
                    os.dup2(null, fd, inheritable=inherit)
                elif inherit:
                    os.close(fd)
                else:
                    continue
            except OSError:
                continue
            found += 1
    finally:
        if null >= 0:
            os.close(null)
    return found


def _opened(fd: int) -> str | None:
    """The path `fd` was opened as, or None (a deleted file, no listing)."""
    try:
        if sys.platform == "darwin":
            import fcntl

            raw = fcntl.fcntl(fd, _PATH, b"\0" * 1024)
            return raw.split(b"\0", 1)[0].decode(errors="replace") or None
        return os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ImportError):
        return None


def outside(plan: Policy) -> list[Handed]:
    """Open descriptors above 2 that reach what `plan` doesn't grant: a
    regular file opened for reading outside the read grants (or for writing
    outside the write grants), and any unix socket. Landlock and Seatbelt
    don't look at either again after the open (see the top of this file).

    Directories (a path opened through one is still checked), pipes,
    terminals and devices are left out: pipes and terminals can't be judged
    from here, so this is a list of what is known to leak, not a proof of
    the rest.
    """
    import fcntl

    reads, writes = plan.reads(), plan.writes()
    found: list[Handed] = []
    for fd in numbers():
        if fd < 3:
            continue
        try:
            mode = os.fstat(fd).st_mode
            if stat.S_ISREG(mode):
                flags = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
            elif stat.S_ISSOCK(mode):
                flags = -1
            else:
                continue
        except OSError:
            continue  # the listing's own descriptor, closed since
        if flags == -1:
            said = _socket(fd)
            if said:
                found.append(Handed(fd, said))
            continue
        path = _opened(fd)
        real = os.path.realpath(path) if path else None
        reading, writing = flags in (os.O_RDONLY, os.O_RDWR), flags in (os.O_WRONLY, os.O_RDWR)
        bad = []
        for need, grants, word in ((reading, reads, "read"), (writing, writes, "write")):
            if not need or grants is True:
                continue
            if real is None or not any(under(real, os.path.realpath(item)) for item in grants):
                bad.append(word)
        if bad:
            found.append(Handed(fd, f"file {path or '(deleted)'} (open to {' and '.join(bad)})"))
    return found


def _socket(fd: int) -> str | None:
    """`unix socket PATH` for a unix socket. None for other families: IP
    sockets are `route.sockets`'s, and `on()` refuses them."""
    import socket  # on first use: `import hlyn` loads no socket module (tests/test_imports.py)

    sock = socket.socket(fileno=os.dup(fd))
    try:
        if sock.family != socket.AF_UNIX:
            return None
        with contextlib.suppress(OSError):
            name = sock.getpeername()
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            if name:
                return f"unix socket {name}"
            return "unix socket (to another process)"
        return "unix socket"
    finally:
        sock.close()


def warning(found: Sequence[Handed]) -> str:
    """What `on()` says about `found`: the answer first, then what to do."""
    many = len(found) > 1
    shown = ", ".join(str(item) for item in found[:5])
    shown += f" and {len(found) - 5} more" if len(found) > 5 else ""
    return (
        f"hlyn: {len(found)} open descriptor{'s' if many else ''} point{'' if many else 's'} outside the "
        f"grants ({shown}).\n"
        f"  {'They' if many else 'It'} would keep working after the seal. Close "
        f"{'them' if many else 'it'} first (os.close(fd)), or use hlyn.run(fn) or hlyn run, which "
        f"close them in the child.\n"
        f"  Run with PYTHONWARNINGS=ignore::hlyn.Inherited to stop this warning."
    )
