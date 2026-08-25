"""Filesystem, execution, and network confinement on macOS, via Seatbelt.

`sandbox_init` is the only real option here. Apple deprecated it in 10.8 and
never replaced it for this use, while continuing to rely on it: it confines
every Mac App Store app and Chrome's renderer. Deprecated is not the same as
absent, so the backend verifies at import time that it still enforces rather
than trusting the header.

Two traps shape this file.

First, profile paths must be fully resolved. `/var` is a symlink to `/private/var`
and `/tmp` to `/private/tmp`, and Seatbelt matches after resolution, so a rule
written against the unresolved path silently never matches. It does not error;
it just fails to apply, which is the worst way for a security rule to fail.

Second, `(deny default)` on its own kills the interpreter, because Python needs
Mach lookups and sysctl reads long before it reaches any user code. The base
allowances below are the minimum that leaves a working interpreter.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from collections.abc import Iterable

from ..error import Failed, Invalid, Unsupported
from ..policy import Policy

__all__ = ["load", "probe", "profile", "ready", "seal"]


# The interpreter cannot start without these. They grant no access to user
# data: process-fork and signalling itself are self-directed, and metadata
# reads expose names and sizes rather than contents.
BASE: tuple[str, ...] = (
    "(allow process-fork)",
    "(allow signal (target self))",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow file-read-metadata)",
    # The root directory node itself, and nothing inside it. A freshly exec'd
    # process resolves every path from `/`, and a `subpath` rule on a child
    # never matches the root node, so without this a spawned program dies in
    # dyld with SIGABRT and no diagnostic at all. Grants only the top-level
    # directory names, which are identical on every Mac; reaching anything
    # underneath still needs its own rule.
    '(allow file-read* (literal "/"))',
)


_lib: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    """Load libSystem, which carries `sandbox_init`."""
    global _lib
    if _lib is not None:
        return _lib
    found = ctypes.util.find_library("System")
    if not found:
        raise Unsupported("libSystem could not be found, so Seatbelt is unavailable.")
    _lib = ctypes.CDLL(found, use_errno=True)
    _lib.sandbox_init.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    _lib.sandbox_init.restype = ctypes.c_int
    _lib.sandbox_free_error.argtypes = [ctypes.c_char_p]
    _lib.sandbox_free_error.restype = None
    return _lib


def ready() -> bool:
    """True if confinement can be applied here."""
    if sys.platform != "darwin":
        return False
    try:
        lib()
    except Unsupported:
        return False
    return True


def probe() -> dict[str, object]:
    """What this machine can actually enforce, without enforcing anything."""
    import platform as system

    out = {
        "platform": "darwin",
        "machine": system.machine(),
        "kernel": system.release(),
        "seatbelt": ready(),
        "enforce": ready(),
        # Seatbelt confines the filesystem, execution, and the network, but has
        # no equivalent of Landlock's scoping, so isolation between agents on
        # one machine is weaker here than on Linux. Said plainly rather than
        # left for someone to discover.
        "scope": False,
        "ports": ready(),
    }
    if not out["enforce"]:
        out["why"] = "sandbox_init is unavailable"
    return out


# -- building the profile ---------------------------------------------------


def real(path: str) -> str:
    """Resolve a path the way Seatbelt will when it matches rules against it."""
    return os.path.realpath(path)


def quote(path: str) -> str:
    """Render a path as an SBPL string literal."""
    if '"' in path or "\\" in path:
        # SBPL has no dependable escape for these, and a mangled rule is a rule
        # that silently does not apply.
        raise Invalid(f"path contains a character the sandbox cannot express: {path!r}")
    return f'"{path}"'


def where(paths: Iterable[str], refused: list[str] | None = None) -> list[str]:
    """Render path filters, matching a whole tree or a single file.

    `subpath` covers a directory and everything under it. For a plain file it
    matches nothing useful, so files get `literal` instead.

    A path that does not exist is collected in `refused` rather than skipped,
    so `profile` can refuse the whole policy the way the Linux backend does. A
    typo in a security policy must not be silently dropped on one platform and
    refused on the other -- policies are written on macOS and deployed on
    Linux, and a rule that vanishes on the machine it was authored on is one
    nobody finds out about until it matters.
    """
    out = []
    for path in paths:
        item = real(path)
        if not os.path.exists(item):
            if refused is not None:
                refused.append(path)
            continue
        kind = "subpath" if os.path.isdir(item) else "literal"
        out.append(f"({kind} {quote(item)})")
    return out


def profile(policy: Policy) -> str:
    """The SBPL text enforcing `policy`.

    Returned as a string so it can be inspected and tested without applying it.
    Confinement is one-way; being able to read the profile first is the only
    way to check it without spending the process.
    """
    lines = ["(version 1)", "(deny default)", *BASE]
    refused: list[str] = []

    reads = policy.reads()
    if reads is True:
        lines.append("(allow file-read*)")
    else:
        for item in where(reads, refused):
            lines.append(f"(allow file-read* {item})")

    writes = policy.writes()
    if writes is True:
        lines.append("(allow file-write*)")
    else:
        for item in where(writes, refused):
            lines.append(f"(allow file-write* {item})")

    runs = policy.runs()
    if runs is True:
        lines.append("(allow process-exec)")
    elif runs:
        for item in where(runs, refused):
            lines.append(f"(allow process-exec {item})")

    if refused:
        # Same refusal as the Linux backend, for the same reason: a path the
        # policy names and the sandbox cannot see is a grant the reader
        # believes in and the kernel never hears about.
        raise Invalid(
            "these paths do not exist, so they cannot be granted: "
            + "; ".join(sorted(set(refused)))
            + ". Create them, or remove them from the policy."
        )

    if policy.net is True:
        lines.append("(allow network*)")
    elif isinstance(policy.net, tuple) and policy.net:
        # Outbound only, matching the Linux backend: binding a port accepts
        # inbound connections, which an agent should have to ask for.
        for port in policy.net:
            lines.append(f'(allow network-outbound (remote tcp "*:{port}"))')

    return "\n".join(lines)


# -- applying it ------------------------------------------------------------


def load(policy: Policy) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible."""
    if sys.platform != "darwin":
        raise Unsupported("Seatbelt is a macOS facility.")

    api = lib()
    text = profile(policy).encode()
    err = ctypes.c_char_p()
    rc = api.sandbox_init(text, 0, ctypes.byref(err))
    if rc != 0:
        detail = err.value.decode(errors="replace") if err.value else "no detail given"
        if err.value:
            api.sandbox_free_error(err)
        raise Failed(
            f"the kernel refused the sandbox profile: {detail}. "
            "The process is NOT confined."
        )
    return 1


seal = load
