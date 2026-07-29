"""The Linux backend: Landlock for the filesystem, seccomp for the syscalls.

Neither half is sufficient alone. Landlock decides which paths, ports, and
neighbouring agents are reachable, and is deny-by-default. seccomp shuts the
doors that would let a process step around Landlock entirely -- io_uring above
all, plus ptrace, namespaces, and module loading.

Order matters. Landlock goes first because it has to open a descriptor for
every granted path, which is easier to reason about before the syscall filter
is in place. seccomp goes last and seals the result.
"""

from __future__ import annotations

import platform

from ..policy import Policy
from . import landlock, seccomp

__all__ = ["load", "ready", "seal", "probe"]


def ready() -> bool:
    """True only if both halves can be applied.

    Deliberately an `and`. Half a boundary is not a boundary, and reporting
    readiness on the strength of one half would let a caller believe in
    confinement that is not there.
    """
    return landlock.ready() and seccomp.ready()


def probe() -> dict:
    """What this machine can actually enforce, without enforcing anything."""
    abi = landlock.abi()
    filter = seccomp.ready()
    out = {
        "platform": "linux",
        "machine": platform.machine(),
        "kernel": platform.release(),
        "landlock": abi,
        "seccomp": filter,
        "enforce": bool(abi) and filter,
        "scope": abi >= 6,  # signals and abstract sockets between agents
        "ports": abi >= 4,  # network rules at all
    }
    missing = []
    if not abi:
        missing.append("Landlock is unavailable; Linux 5.13 or newer is needed")
    elif abi < 6:
        missing.append(
            f"Landlock ABI {abi} cannot confine signals or abstract sockets "
            "between agents; Linux 6.12 or newer is needed"
        )
    if not filter:
        missing.append("libseccomp is not installed, so syscalls cannot be filtered")
    if missing:
        out["why"] = "; ".join(missing)
    return out


def load(policy: Policy) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible."""
    abi = landlock.load(policy)
    seccomp.load(policy)
    return abi


seal = load
