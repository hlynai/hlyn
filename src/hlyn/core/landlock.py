"""Filesystem, network-port, and inter-agent confinement, via Landlock.

The kernel enforces this. The struct layouts, ABI detection, and access-bit
masking are handled by the upstream Landlock crate, reached through a small
C-ABI shim; see `native/`. Nothing security-critical is decided in this file.

Landlock is what makes the policy deny-by-default: every right the kernel
understands is *handled*, and only the paths named here are granted back.
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Sequence
from typing import Any

from ..error import Failed, Invalid, Unsupported
from ..policy import Policy

__all__ = ["abi", "load", "ready", "seal"]


# flags, matching native/src/lib.rs
SIGNAL = 1 << 0
UNIX = 1 << 1
NET = 1 << 2

# return codes, matching native/src/lib.rs
NOT = 0
SOME = 1
FULL = 2

# Failure codes, matching native/src/lib.rs. ERULE is named because it is the
# one the caller can usually act on, and it gets a second look in `_blame`.
ERULE = -3

WHY = {
    -1: "the shim was called with arguments it could not read",
    -2: "the ruleset could not be built",
    ERULE: "a path in the policy could not be opened",
    -4: "the kernel refused to apply the ruleset",
}


class Plan(ctypes.Structure):
    """Mirror of `struct Plan` in the shim. Field order is load-bearing."""

    _fields_ = [
        ("reads", ctypes.POINTER(ctypes.c_char_p)),
        ("nreads", ctypes.c_size_t),
        ("writes", ctypes.POINTER(ctypes.c_char_p)),
        ("nwrites", ctypes.c_size_t),
        ("execs", ctypes.POINTER(ctypes.c_char_p)),
        ("nexecs", ctypes.c_size_t),
        ("binds", ctypes.POINTER(ctypes.c_uint16)),
        ("nbinds", ctypes.c_size_t),
        ("connects", ctypes.POINTER(ctypes.c_uint16)),
        ("nconnects", ctypes.c_size_t),
        ("flags", ctypes.c_uint32),
    ]


_lib: ctypes.CDLL | None = None


def _where() -> list[str]:
    """Places the shim may live, most specific first."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    out = []
    override = os.environ.get("HLYN_SHIM")
    if override:
        out.append(override)
    out.append(os.path.join(here, "libhlyn.so"))  # installed alongside the package
    out.append(os.path.join(root, "native", "target", "release", "libhlyn.so"))  # built here
    return out


def lib() -> ctypes.CDLL:
    """Load the shim once, or explain exactly why confinement is unavailable."""
    global _lib
    if _lib is not None:
        return _lib

    tried = _where()
    for path in tried:
        if not os.path.exists(path):
            continue
        try:
            _lib = ctypes.CDLL(path)
            break
        except OSError:
            continue
    if _lib is None:
        raise Unsupported(
            "the Landlock shim could not be found, so filesystem confinement "
            "cannot be applied. Looked in:\n  " + "\n  ".join(tried) + "\n"
            "Build it with `cargo build --release` in native/, or set HLYN_SHIM "
            "to its path. Refusing to continue unconfined."
        )

    _lib.hlyn_abi.argtypes = []
    _lib.hlyn_abi.restype = ctypes.c_int32
    _lib.hlyn_seal.argtypes = [ctypes.POINTER(Plan)]
    _lib.hlyn_seal.restype = ctypes.c_int32
    return _lib


def abi() -> int:
    """The Landlock ABI the running kernel speaks. Zero means none."""
    if sys.platform != "linux":
        return 0
    try:
        return int(lib().hlyn_abi())
    except Unsupported:
        return 0


def ready() -> bool:
    """True if filesystem confinement can be applied here."""
    return abi() > 0


# -- turning a policy into a plan -------------------------------------------


def _paths(value: tuple[str, ...] | bool, refused: list[tuple[str, str]]) -> list[bytes]:
    """Encode a grant as paths. `True` means the whole tree.

    Each path is probed with the same open the shim will perform, rather than
    with `os.path.exists`. They disagree in exactly the case that matters: a
    file inside a directory the caller cannot search exists perfectly well and
    still cannot be opened, and reporting that as "does not exist" sends the
    reader looking for a typo instead of at the permissions.
    """
    if value is True:
        return [b"/"]
    if value is False or not value:
        return []
    out = []
    for item in value:
        try:
            fd = os.open(item, os.O_PATH)
        except OSError as exc:
            why = exc.strerror or (os.strerror(exc.errno) if exc.errno else "cannot be opened")
            refused.append((item, why))
            continue
        os.close(fd)
        out.append(os.fsencode(item))
    return out


def _blame(groups: Sequence[tuple[str, list[bytes]]]) -> str:
    """Which granted path the kernel would not open, and what it said.

    The shim answers with one code for every rule failure, which is the right
    shape for a C ABI and the wrong shape for a person: "a path could not be
    opened" does not say which path, and a policy naming forty of them is then
    a guessing game. Rather than widen the ABI to carry a string back, the same
    open is repeated here once the shim has already failed -- the happy path
    pays nothing, and the failing path gets the name and the reason.

    Best effort. If nothing fails the second time, the cause was transient or
    was something other than an open, and the caller gets the plain message.
    """
    for field, items in groups:
        for item in items:
            try:
                fd = os.open(item, os.O_PATH)
            except OSError as exc:
                where = os.fsdecode(item)
                return f" The path {field} names, {where!r}, could not be opened: {exc.strerror}."
            else:
                os.close(fd)
    return ""


def _array(items: Sequence[bytes]) -> tuple[Any, int]:
    """A C array of string pointers, or NULL when empty."""
    if not items:
        return None, 0
    block = (ctypes.c_char_p * len(items))(*items)
    return block, len(items)


def _ports(items: Sequence[int]) -> tuple[Any, int]:
    if not items:
        return None, 0
    block = (ctypes.c_uint16 * len(items))(*items)
    return block, len(items)


def crowd() -> list[str]:
    """Every thread in this process, by task id.

    Read from `/proc/self/task` rather than counted with `threading`, because
    `threading` only knows about threads Python created. A thread started by a
    C extension -- CUDA, OpenMP, gRPC, a native HTTP client -- is invisible to
    it and just as unconfined. Nothing is sealed yet at this point, so `/proc`
    is readable here even though the policy will not grant it.
    """
    try:
        return sorted(os.listdir("/proc/self/task"))
    except OSError:
        # No /proc to ask. Fall back to what Python knows, which is a floor
        # rather than an answer, and better than assuming the process is alone.
        import threading

        return [str(n) for n in range(threading.active_count())]


def _alone() -> None:
    """Refuse to seal a process that has threads this cannot reach.

    `landlock_restrict_self` applies the domain to the *calling thread*, and
    Linux credentials are per-task, so a thread that already exists keeps the
    access it had. seccomp has `TSYNC` and covers every thread; Landlock has no
    equivalent, and there is no way to make another thread run code on demand.

    The result would be a process whose main thread is confined and whose
    logging handler, connection pool or async executor is not -- confinement
    that reports success while a hole stays open, which is the one outcome this
    package treats as worse than refusing. So it refuses.

    The fix is nearly always to seal earlier. `hlyn.on()` belongs at the top of
    the program, before anything starts a thread.
    """
    tasks = crowd()
    if len(tasks) <= 1:
        return

    import threading

    named = [t.name for t in threading.enumerate() if t is not threading.current_thread()]
    who = ", ".join(named[:4]) if named else "started by a native library, not by Python"
    if len(named) > 4:
        who += f", +{len(named) - 4} more"

    raise Unsupported(
        f"this process has {len(tasks)} threads, and Landlock can only confine the one "
        f"that calls it -- the rest ({who}) would keep the access they already have. "
        f"Refusing rather than reporting a boundary that is not there. "
        f"Call hlyn.on() before anything starts a thread, usually the first line of the "
        f"program; or use hlyn.run(fn), which forks a single-threaded child and confines "
        f"that instead."
    )


def load(policy: Policy) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible.

    Returns the Landlock ABI that was in force. Raises rather than return if
    the kernel applied less than was asked for: a caller that believes it is
    confined and is not is the single worst outcome this package can produce.
    """
    api = lib()
    _alone()

    refused: list[tuple[str, str]] = []
    reads = _paths(policy.reads(), refused)
    writes = _paths(policy.writes(), refused)
    runs = _paths(policy.runs(), refused)
    if refused:
        # A typo in a security policy must never be silently dropped, so this
        # refuses rather than granting what it can. The reason comes from the
        # kernel, so "no such file" and "permission denied" read differently
        # and the caller knows which one to go and fix.
        raise Invalid(
            "these paths could not be opened, so they cannot be granted: "
            + "; ".join(f"{path} ({why})" for path, why in sorted(set(refused)))
            + ". Create them, fix their permissions, or remove them from the policy."
        )

    # Signals and abstract sockets are confined to this agent by default. They
    # are the two channels that would otherwise let one compromised agent reach
    # a sibling without touching the filesystem or the network.
    flags = SIGNAL | UNIX

    binds: tuple[int, ...] = ()
    connects: tuple[int, ...] = ()
    if policy.net is not True:
        # Anything other than "wide open" means Landlock handles the network.
        # With net=False that leaves no port rules at all, which denies every
        # TCP bind and connect here as well as in the syscall filter.
        flags |= NET
        if isinstance(policy.net, tuple):
            # Named ports grant outbound reach only. Binding a port accepts
            # inbound connections, which is a listener an agent should have to
            # ask for separately rather than receive by implication.
            #
            # These rules bind TCP alone. Landlock's network access covers TCP
            # bind and connect and nothing else, so UDP is unrestricted here
            # and traffic can still leave over DNS or QUIC. It is not an
            # oversight: seccomp cannot read a UDP port number any more than it
            # can read a host name, so the only reachable alternative is
            # refusing all of UDP, which breaks every hostname lookup. `net`
            # set to False closes both by refusing the socket outright.
            connects = policy.net

    ra, na = _array(reads)
    wa, nw = _array(writes)
    xa, nx = _array(runs)
    ba, nb = _ports(binds)
    ca, nc = _ports(connects)

    plan = Plan(
        reads=ra, nreads=na,
        writes=wa, nwrites=nw,
        execs=xa, nexecs=nx,
        binds=ba, nbinds=nb,
        connects=ca, nconnects=nc,
        flags=flags,
    )

    got = int(api.hlyn_seal(ctypes.byref(plan)))

    if got == FULL:
        return abi()
    if got == SOME:
        raise Failed(
            "the kernel enforced only part of this policy, so the boundary is "
            "weaker than you asked for. Landlock ABI "
            f"{abi()} is older than the version these rules need "
            "(6, Linux 6.12). The process IS confined, but not fully. Upgrade "
            "the kernel, or narrow the policy to what this one supports."
        )
    if got == NOT:
        raise Failed(
            "this kernel applied no Landlock restrictions at all. Filesystem "
            "confinement is unavailable, so the process is NOT confined by "
            "this layer. Landlock needs Linux 5.13 or newer with the LSM enabled."
        )
    said = "landlock: " + WHY.get(got, f"unknown failure ({got})")
    if got == ERULE:
        said += _blame([("read", reads), ("write", writes), ("exec", runs)])
    raise Failed(said)


# `seal` reads better at the call site in the orchestrator; `load` matches the
# name used by the syscall backend. Both are the same one-way operation.
seal = load
