# SPDX-License-Identifier: Apache-2.0
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

from ..error import Invalid, Unsupported
from ..policy import Policy
from ..report import Listener
from . import guard, landlock, notify, preload, seccomp

__all__ = ["listen", "load", "probe", "ready", "seal"]


def ready() -> bool:
    """True only if both halves can be applied.

    Deliberately an `and`. Half a boundary is not a boundary, and reporting
    readiness on the strength of one half would let a caller believe in
    confinement that is not there.
    """
    return landlock.ready() and seccomp.ready()


# Whether this backend enforces host entries in `net` (DESIGN-host-allowlisting.md
# 5.3): Landlock allows no TCP port, and the gate answers every connect by
# swapping in a connection to the proxy, or refusing.
HOSTS = True

# Whether host mode puts the gate in front of the proxy: every connection
# reaches it through the gate, which writes a PROXY v2 header first (5.5).
GATE = True

# The proxy's connect timeout, which bounds a direct connection's wait for
# its verdict (5.3). Matches proxy.Limits.connect's default.
CONNECT = 10.0


def probe() -> dict[str, object]:
    """What this machine can actually enforce, without enforcing anything.

    `ready` -- and every real seal -- needs ABI 6, unconditionally: `load`
    always asks for signal and abstract-socket scoping, whatever the policy
    says, so a kernel offering less refuses every single seal, not merely
    ones that name cross-agent isolation. `scope` and `ports` therefore rise
    and fall with `enforce` rather than with their own, lower thresholds --
    the finer-grained thresholds describe what Landlock the *kernel* could in
    principle do, not what this version of hlyn will actually attempt on it.
    """
    abi = landlock.abi()
    filter = seccomp.ready()
    ok = landlock.ready()  # == abi >= 6; see landlock.ready's docstring
    out = {
        "platform": "linux",
        "machine": platform.machine(),
        "kernel": platform.release(),
        "landlock": abi,
        "seccomp": filter,
        "enforce": ok and filter,
        "scope": ok,  # signals and abstract sockets between agents
        "ports": ok,  # network rules at all
        # Host names in `net`: the notify API and no other listener here.
        "hosts": ok and filter and notify.ready() and not seccomp.busy(),
        # Socket files outside the write grants refused: by the kernel itself
        # from Landlock ABI 9 (the shim's `bonus`), before that by hlyn's gate
        # in every mode but an open network (`watched`, guard's pinned swap).
        "sockets": False,
        "socket_check": None,
        # Whether `hlyn run` can list what was blocked: needs the preloaded
        # reporting library. Not part of `enforce` -- the boundary holds
        # either way; only the explanation is missing.
        "report": preload.find() is not None,
    }
    if ok and filter:
        if abi >= 9:
            out["sockets"], out["socket_check"] = True, "kernel"
        elif out["hosts"]:  # the same needs as host mode's gate: notify, no other listener
            out["sockets"], out["socket_check"] = True, "gate"
    missing = []
    if not abi:
        missing.append("Landlock is unavailable; Linux 5.13 or newer is needed")
    elif abi < 6:
        missing.append(
            f"Landlock ABI {abi} is too old: hlyn always confines signals and "
            "abstract sockets between agents, which needs ABI 6, so no policy "
            "can be sealed on this kernel (Linux 6.12 or newer is needed)"
        )
    if not filter:
        missing.append("libseccomp is not installed, so syscalls cannot be filtered")
    elif not notify.ready():
        missing.append("libseccomp is older than 2.5.0, so host names in net can't be enforced; "
                       "use ports (--net 443) or upgrade libseccomp")
    elif seccomp.busy():
        missing.append("host names in net can't be enforced here: " + seccomp.BUSY)
    if missing:
        out["why"] = "; ".join(missing)
    if out["hosts"]:
        scope = ptrace()
        if scope is not None and scope >= 2:
            out["reduced"] = (
                f"kernel.yama.ptrace_scope is {scope}, so hlyn's gate can't read connection "
                f"addresses: only programs that use HTTPS_PROXY reach hosts, and address, "
                f"localhost and unix-socket entries don't work. Set it to 1 for those"
            )
    return out


def ptrace() -> int | None:
    """Yama's `ptrace_scope`, or None without Yama. At 0 and 1 the gate may
    read its descendants' memory (full mode); at 2 and 3 it may not (5.3)."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


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

    This only ever looks. `socket.socket(fileno=...)` *takes ownership* of the
    descriptor, so a wrapper left to fall out of scope closes the socket it was
    built to inspect -- silently, and for every socket in the process, not just
    the ones reported. That would close local IPC to enforce a network policy,
    which is the exact bug `WIRE` in the syscall filter was emptied to fix.
    Every wrapper below is therefore detached before it is dropped.
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
        except ValueError:
            continue
        try:
            sock = socket.socket(fileno=fd)
        except (OSError, ValueError):
            continue  # not a socket, or already gone
        try:
            kind = sock.getsockopt(socket.SOL_SOCKET, DOMAIN)
        except OSError:
            continue
        finally:
            sock.detach()  # hand the descriptor back; never close it
        if kind in INET:
            out.append(fd)
    return out


# Whether `ready_hosts` found no listener in this process's filter chain.
# Forked children inherit the chain and this flag with it, so `load` in the
# child needn't fork to ask again; every entry point asks afresh.
_checked = False


def ready_hosts() -> None:
    """Refuse host mode here, naming the fix, before any helper starts: the
    notify API is missing, or this process is inside another listener."""
    global _checked
    notify._lib()
    _checked = False
    if seccomp.busy():
        raise Unsupported(seccomp.BUSY + " Nothing was sealed.")
    _checked = True


def watched(policy: Policy) -> bool:
    """Whether sealing `policy` here needs a gate for unix sockets although
    `net` names no hosts: the network is off or limited to ports, and
    Landlock can't check socket files (ABI 9, Linux 7.1). Before that a
    confined program reached any unix socket on the machine, among them the
    user's systemd bus and docker.sock, each a way to run code outside the
    sandbox (FINDINGS.md, "Checking the eight decisions").

    False where no gate can be installed: libseccomp before 2.5, or this
    process already inside a notification listener (the kernel allows one
    per process tree: an outer hlyn in host mode, whose gate then checks
    this process's unix sockets by its own rules). The seal says which
    applies (`jail._seal`). Asked by each entry point before it starts
    anything; a forked child keeps the answer."""
    if policy.net is True or policy.hosts():
        return False
    if landlock.abi() >= 9:
        return False
    return notify.ready() and not seccomp.busy()


def load(policy: Policy, tag: str | None = None, port: int | None = None) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible.

    `tag` is unused here. On Linux, refusals are reported from inside the
    confined programs rather than by the kernel; see `listen`.

    `port` is the proxy's port, which a policy naming hosts requires. The
    notification descriptor the filter returns then goes to the gate this
    process was given (`gate.become` or `gate.detached`) before this
    returns, so no agent code ever holds it (5.2, step 5).
    """
    from .. import gate

    named = policy.hosts()
    if named:
        # Everything that could refuse host mode is asked before the first
        # rule is applied, so a refusal leaves the process untouched.
        if port is None:
            raise Invalid("net names hosts, so sealing needs the proxy's port. Start it with route.start().")
        notify._lib()  # raises, naming the fix, if libseccomp is too old
        if not _checked and seccomp.busy():
            raise Unsupported(seccomp.BUSY + " Nothing was sealed.")
        if gate._handoff is None:
            raise Unsupported("net names hosts, but no gate was started to answer this process's "
                              "connections (hlyn.on, run, spawn and hlyn run start one). Nothing was sealed.")
        writes = policy.writes()
        config = guard.Config(port=port, rules=named, writes=writes, connect=CONNECT)
    # Unix sockets without hosts (`watched`): the entry point started a gate
    # when it was needed and possible; that decision is read here, from
    # whether there is a gate to hand to.
    watch = not named and policy.net is not True and gate._handoff is not None
    if watch:
        config = guard.Config(port=0, rules=(), writes=policy.writes(), connect=CONNECT,
                              mode="off" if policy.net is False else "ports")
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
    fd = seccomp.load(policy, watch=watch)
    if fd is not None:
        gate.hand(fd, config)
    return abi


seal = load


def listen() -> Listener:
    """How `hlyn run` hears what this backend refused: a preloaded library."""
    return preload.Listener()
