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

WHY = {
    -1: "the shim was called with arguments it could not read",
    -2: "the ruleset could not be built",
    -3: "a path in the policy could not be opened",
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


def _paths(value: tuple[str, ...] | bool, missing: list[str]) -> list[bytes]:
    """Encode a grant as paths. `True` means the whole tree."""
    if value is True:
        return [b"/"]
    if value is False or not value:
        return []
    out = []
    for item in value:
        if not os.path.exists(item):
            missing.append(item)
            continue
        out.append(os.fsencode(item))
    return out


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


def load(policy: Policy) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible.

    Returns the Landlock ABI that was in force. Raises rather than return if
    the kernel applied less than was asked for: a caller that believes it is
    confined and is not is the single worst outcome this package can produce.
    """
    api = lib()

    missing: list[str] = []
    reads = _paths(policy.reads(), missing)
    writes = _paths(policy.writes(), missing)
    runs = _paths(policy.runs(), missing)
    if missing:
        raise Invalid(
            "these paths do not exist, so they cannot be granted: "
            + ", ".join(sorted(set(missing)))
            + ". Create them first, or remove them from the policy."
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
    raise Failed("landlock: " + WHY.get(got, f"unknown failure ({got})"))


# `seal` reads better at the call site in the orchestrator; `load` matches the
# name used by the syscall backend. Both are the same one-way operation.
seal = load
