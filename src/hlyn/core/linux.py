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

import os
import platform

from ..error import Unsupported
from ..policy import Policy
from . import landlock, seccomp

__all__ = ["load", "probe", "ready", "seal"]


def ready() -> bool:
    """True only if both halves can be applied.

    Deliberately an `and`. Half a boundary is not a boundary, and reporting
    readiness on the strength of one half would let a caller believe in
    confinement that is not there.
    """
    return landlock.ready() and seccomp.ready()


def probe() -> dict[str, object]:
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


# getsockopt(SOL_SOCKET, SO_DOMAIN) reports the address family of an existing
# socket. Linux-only, which is why it lives here.
DOMAIN = 39
INET = (2, 10, 17)  # AF_INET, AF_INET6, AF_PACKET


def wired() -> list[int]:
    """Network sockets this process already holds.

    Closing the network stops new ones being made and stops an existing one
    being bound or connected. Neither touches a socket that is *already*
    connected: `write` on it is an ordinary write, and no filter here can tell
    that descriptor from a file. So the honest thing is to look before sealing.
    """
    import socket

    out: list[int] = []
    try:
        held = os.listdir("/proc/self/fd")
    except OSError:
        return out
    for name in held:
        try:
            fd = int(name)
            kind = socket.socket(fileno=fd).getsockopt(socket.SOL_SOCKET, DOMAIN)
        except (OSError, ValueError):
            continue  # not a socket, or already gone
        if kind in INET:
            out.append(fd)
    return out


def load(policy: Policy) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible."""
    if policy.net is False:
        open_sockets = wired()
        if open_sockets:
            raise Unsupported(
                f"the network is closed by this policy, and {len(open_sockets)} network "
                f"socket(s) are already open (fd {', '.join(map(str, sorted(open_sockets)))}). "
                f"An open connection keeps working after sealing -- writing to it is an "
                f"ordinary write, and nothing here can tell that descriptor from a file. "
                f"Refusing rather than reporting a closed network with a live connection "
                f"through it. Close them before calling hlyn.on(), or use hlyn.run(fn)."
            )
    abi = landlock.load(policy)
    seccomp.load(policy)
    return abi


seal = load
