# SPDX-License-Identifier: Apache-2.0
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
import os
import re
import sys
from collections.abc import Iterable

from ..error import Failed, Invalid, Unsupported
from ..policy import Policy
from ..report import SERVICES, Listener

__all__ = ["HOSTS", "hosts", "listen", "load", "probe", "profile", "ready", "seal"]

# Whether this backend enforces host entries in `net` (DESIGN-host-allowlisting.md
# 5.4): Seatbelt allows only the proxy's port, and the proxy checks the rest.
HOSTS = True


# The interpreter cannot start without these. They grant no access to user
# data: process-fork is self-directed, and metadata reads expose names and
# sizes rather than contents.
BASE: tuple[str, ...] = (
    "(allow process-fork)",
    # Signals within this environment: the process, its children and theirs, and
    # back. Nothing outside it -- not hlyn, not an unrelated process, not a
    # second agent sealed by the same policy (each seal is its own environment).
    # That is Landlock's signal scope on Linux. `(target self)` alone left an
    # agent unable to stop what it started: `Popen.terminate()` and
    # `subprocess.run(timeout=...)` failed (tests/test_signals.py).
    "(allow signal (target same-sandbox))",
    "(allow sysctl-read)",
    # System services: a measured allowlist (`MACH`, `services`), or all of
    # them with an open network (`(allow mach-lookup)`, added by `profile`).
    "(allow file-read-metadata)",
    # The root directory node itself, and nothing inside it. A freshly exec'd
    # process resolves every path from `/`, and a `subpath` rule on a child
    # never matches the root node, so without this a spawned program dies in
    # dyld with SIGABRT and no diagnostic at all. Grants only the top-level
    # directory names, which are identical on every Mac; reaching anything
    # underneath still needs its own rule.
    '(allow file-read* (literal "/"))',
    # The notification centre's shared memory, read-only. Every process that
    # links Foundation maps it at startup; without it each launch logs a
    # denial and carries on.
    '(allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))',
    # The system log's socket, which carries a program's syslog() messages
    # to the system log; refusing it only turns every such call into a
    # denial. Mach services are a measured allowlist (`MACH` below) unless
    # the network is open; the system log's service isn't on it.
    '(allow network-outbound (remote unix-socket (path-literal "/private/var/run/syslog")))',
    # Controlling the terminal the agent was started on: its mode (raw for
    # every full-screen program: Claude Code, vim, less), size and foreground
    # group. Refused, `tcgetpgrp(0)` failed with EPERM and Claude Code's
    # input was never read (FINDINGS.md, "hlyn claude"). Except TIOCSTI,
    # which types into the terminal for the shell to read after the agent
    # exits: the deny comes after the allow, so it wins. Measured: a
    # deny-default profile refuses TIOCSTI even without this line (some other
    # operation gates it; not identified), so this is the second guard.
    '(allow file-ioctl (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$"))',
    "(deny file-ioctl (ioctl-command #x80017472))",
)

# The system resolver's socket. Every name lookup on macOS goes through it.
RESOLVER = "/private/var/run/mDNSResponder"

# The Mach allowlist for every mode but an open network (DESIGN-host-
# allowlisting.md 5.4, gap 8.3). Every entry is measured, and checked for work
# done on the caller's behalf (tools/hostlab/hostmode.py, machlab.py;
# FINDINGS.md, "macOS host mode", "which Mach services programs need").
# curl, Python, Node, git, Java and clang need none at all. Left out on
# purpose: the pasteboard and the notification centre, which carried data
# between two separately sealed agents (measured), and everything unmeasured.
#   - opendirectoryd.libinfo answers user and group lookups. Without it
#     `pwd.getpwuid()` fails, which breaks real programs. It resolves no host
#     names (those still go to the refused mDNSResponder socket; measured).
#     Residual: on a Mac bound to a network directory, a user lookup reaches
#     that directory's server.
#   - cfprefsd serves preferences. Without it CoreFoundation reads the plist
#     files itself, and every run reports those reads. It checks the caller's
#     environment for both reading and writing (measured: `defaults read` and
#     `defaults write` of a domain outside the grants both fail under the
#     seal), and does no network work.
#   - opendirectoryd.membership answers group-membership checks; Swift and
#     swiftc need it (measured). Same daemon and residual as libinfo.
MACH: tuple[str, ...] = (
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
)

# The keychain's service. Measured: it returns an item only from a keychain
# file the caller may read, but it also lets a caller lock every one of the
# user's keychains. So it comes with a readable keychain file and not
# otherwise (`keychains`).
KEYCHAIN = "com.apple.SecurityServer"


def keychains(policy: Policy) -> bool:
    """Whether `policy` lets the program read a keychain file."""
    reads = policy.reads()
    if reads is True:
        return True
    places = [real(os.path.expanduser("~/Library/Keychains")), "/Library/Keychains"]
    for item in reads:
        path = real(item)
        if path.endswith((".keychain", ".keychain-db")):
            return True
        if any(path == place or path.startswith(place + "/") or place.startswith(path.rstrip("/") + "/")
               for place in places):
            return True
    return False

# Unix sockets never reachable in host mode, whatever folders are granted
# (5.3, 5.6): the program behind each acts for its caller, on the network or
# the machine. Written as regexes over the resolved path, and placed after
# every allow so they win.
REFUSED: tuple[str, ...] = (
    # The system resolver: any name, attacker-chosen ones included, and the
    # answer carries data out one DNS label at a time.
    f"^{re.escape(RESOLVER)}$",
    # Container runtimes (docker.sock, docker.raw.sock, docker-cli.sock,
    # containerd.sock, podman.sock, crio.sock): an agent that reaches one
    # controls the machine.
    r"/(docker|containerd|podman|crio)[^/]*\.sock$",
    # Docker Desktop, Colima, OrbStack, Lima and Rancher Desktop keep their
    # API sockets in these folders under other names too.
    r"^/Users/[^/]+/Library/Containers/com\.docker\.docker/",
    r"^/Users/[^/]+/\.(colima|orbstack|lima|rd)/",
)


_lib: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    """Load libSystem, which carries `sandbox_init`."""
    global _lib
    if _lib is not None:
        return _lib
    try:
        # By its fixed path (macOS keeps it in the dyld cache, so the file may not
        # exist on disk, but dlopen finds it): `ctypes.util` costs about 4 ms to
        # import (it pulls in subprocess), and it is only the fallback.
        _lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError:
        from ctypes.util import find_library

        found = find_library("System")
        if not found:
            raise Unsupported("libSystem could not be found, so Seatbelt is unavailable.") from None
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
        # Signals are scoped to each agent's environment, as Landlock scopes them
        # (`(target same-sandbox)`), and macOS has no abstract sockets. System
        # services are the measured allowlist unless the network is open, so
        # the pasteboard no longer carries data between agents (measured,
        # tests/test_mach.py); an open network allows every service.
        "scope": ready(),
        "scope_why": "with --net-any every system service, the pasteboard included, is shared",
        "ports": ready(),
        # Host names in `net`: the proxy (5.5) behind a profile that allows
        # only its port (5.4).
        "hosts": ready(),
        # Socket files: the profile allows them only in write-granted folders
        # (host mode) or with the whole network, and Seatbelt checks the path
        # the kernel uses, so there is no race to win.
        "sockets": ready(),
        # Whether `hlyn run` can list what was blocked. Read from the system
        # log, so it needs nothing built or installed.
        "report": os.access("/usr/bin/log", os.X_OK),
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
        raise Invalid(f"path contains a character the environment cannot express: {path!r}")
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


def posix() -> list[str]:
    """POSIX semaphores and shared memory under the names Python's
    `multiprocessing` makes (`/mp-XXXX`, `/psm_XXXX`), and no others (`shm`;
    FINDINGS.md, "multiprocessing"). Measured: the prefix filter works. A
    program naming its own object, `SharedMemory(name="x")`, is still refused.
    """
    return [
        '(allow ipc-posix-sem (ipc-posix-name-prefix "/mp-"))',
        '(allow ipc-posix-shm (ipc-posix-name-prefix "/psm_"))',
    ]


def profile(policy: Policy, tag: str | None = None, port: int | None = None) -> str:
    """The SBPL text enforcing `policy`.

    Returned as a string so it can be inspected and tested without applying it.
    Confinement is one-way; being able to read the profile first is the only
    way to check it without spending the process.

    `tag` is appended by the kernel to every refusal it reports for this
    process and its children, which is how `hlyn run` picks this run's
    refusals out of the system log. It changes nothing about what is allowed.

    `port` is the local proxy's port, which a policy naming hosts requires:
    see `hosts` for what that mode grants.
    """
    named = bool(policy.hosts())
    if named and port is None:
        raise Invalid("net names hosts, so the profile needs the proxy's port. Start it with route.start().")
    deny = f"(deny default (with message {quote(tag)}))" if tag else "(deny default)"
    lines = ["(version 1)", deny, *BASE, *services(policy), *start()]
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

    if policy.shm:
        lines.extend(posix())

    if refused:
        # Same refusal as the Linux backend, for the same reason: a path the
        # policy names and the environment cannot see is a grant the reader
        # believes in and the kernel never hears about.
        raise Invalid(
            "these paths do not exist, so they cannot be granted: "
            + "; ".join(sorted(set(refused)))
            + ". Create them, or remove them from the policy."
        )

    if named and port is not None:
        lines.extend(hosts(policy, port, tag))
    elif policy.net is True:
        lines.append("(allow network*)")
    elif isinstance(policy.net, tuple) and policy.net:
        # Outbound only, matching the Linux backend: binding a port accepts
        # inbound connections, which an agent should have to ask for.
        for number in policy.net:
            lines.append(f'(allow network-outbound (remote tcp "*:{number}"))')
        # macOS resolves names through this daemon rather than by sending DNS
        # itself. Without it, allowing port 443 still cannot reach a host by
        # name. Granting it is not a closed door, though: it answers whatever
        # name the caller asks for, chosen name included, so data can leave
        # one DNS label at a time (DNS tunnelling) even though every TCP
        # connect is still checked against the port list. Verified live
        # (FINDINGS.md, "the blanket mach-lookup grant"): port mode is not a
        # boundary against exfiltration by DNS. Host allowlisting's proxy,
        # which resolves names itself and never grants this socket, is what
        # closes it (DESIGN-host-allowlisting.md 5.4, 5.6).
        lines.append(f'(allow network-outbound (remote unix-socket (path-literal "{RESOLVER}")))')

    if not policy.net or named:
        # Host mode refuses them too: its allowlist above leaves them out,
        # and this says so in the log, so the report can explain (5.4).
        # net=False (or an empty port list, which forbids the same thing):
        # HTTPS is impossible either way, so refusing these two services costs
        # nothing while closing two routes past the environment that the blanket
        # `(allow mach-lookup)` in BASE otherwise leaves open. Both verified
        # live under shipped net=False (FINDINGS.md, "the blanket mach-lookup
        # grant"):
        #   - trustd fetches whatever certificate-issuer URL a checked
        #     certificate names, attacker-chosen included, for any caller
        #     that verifies a certificate through Security.framework (Swift
        #     URLSession, Go's crypto/x509 on macOS).
        #   - dnssd.service resolves whatever name a caller asks for, which
        #     carries data out over DNS even though no TCP connect is ever
        #     allowed to complete.
        # These rules must come after the `(allow mach-lookup)` above so they
        # win: SBPL applies the rules for one operation in order and the last
        # match decides it, the same pattern the RESOLVER deny in the design
        # doc's example profile relies on. This is
        # DESIGN-host-allowlisting.md gap 8.3's first phase: the blanket grant
        # otherwise stays for now (every other service), and the full
        # allowlist for every mode is later work.
        # An explicit deny is logged with the run's tag only when it carries
        # the message itself (measured: without it the report never hears of
        # the refusal, so it could not say what to do).
        said = f" (with message {quote(tag)})" if tag else ""
        for name in SERVICES:
            lines.append(f'(deny mach-lookup{said} (global-name "{name}"))')

    return "\n".join(lines)


def start() -> list[str]:
    """The folder the program starts in, itself only: its path and the names
    in it, never a file in it or a folder below it. macOS reports a folder's
    path (getcwd) only to a program that may read the folder, so without it
    `os.getcwd()`, Node, git and shells fail in a folder the policy doesn't
    grant (measured, FINDINGS.md); Linux needs nothing for it. `literal`
    matches that one folder."""
    try:
        here = real(os.getcwd())
    except OSError:
        return []
    return [f"(allow file-read-data (literal {quote(here)}))"]


def services(policy: Policy) -> list[str]:
    """The system services (Mach) `policy` allows: all of them with an open
    network; otherwise `MACH`, plus trustd and dnssd with ports (which
    already allow HTTPS to any host, so they add no new reach: decision 3),
    plus the keychain's service with a readable keychain file."""
    if policy.net is True:
        return ["(allow mach-lookup)"]
    names = list(MACH)
    if isinstance(policy.net, tuple) and policy.net and not policy.hosts():
        names += list(SERVICES)
    if keychains(policy):
        names.append(KEYCHAIN)
    return [f'(allow mach-lookup (global-name "{name}"))' for name in names]


def hosts(policy: Policy, port: int, tag: str | None = None) -> list[str]:
    """The network rules of host mode (DESIGN-host-allowlisting.md 5.4).

    TCP goes to the proxy's port and to each `localhost:PORT` entry, and
    nowhere else: Seatbelt's host token takes only `*` or `localhost`, so
    remote address entries are reachable only through the proxy. `localhost`
    here also matches ::1, ::ffff:127.0.0.1 and this machine's own addresses
    (measured); the proxy refuses a port something listens on at those.

    Unix sockets need a *write* grant on their folder, since connecting sends
    data to whatever listens there. `REFUSED` comes last so it wins over
    those grants. No DNS, no UDP, no bind: nothing else is allowed.
    """
    out = [f'(allow network-outbound (remote tcp "localhost:{port}"))']
    for rule in policy.hosts():
        if rule.kind == "localhost" and rule.port != port:
            out.append(f'(allow network-outbound (remote tcp "localhost:{rule.port}"))')
    writes = policy.writes()
    if writes is True:
        out.append("(allow network-outbound (remote unix-socket))")
    else:
        for item in where(writes):
            out.append(f"(allow network-outbound (remote unix-socket {item}))")
    said = f" (with message {quote(tag)})" if tag else ""
    for pattern in REFUSED:
        out.append(f'(deny network-outbound{said} (remote unix-socket (regex #"{pattern}")))')
    return out


# -- applying it ------------------------------------------------------------


def load(policy: Policy, tag: str | None = None, port: int | None = None) -> int:
    """Apply `policy` to the calling process. One-way, and irreversible.

    `tag` marks this process's refusals in the system log, and `port` is the
    proxy's port in host mode; see `profile`.
    """
    if sys.platform != "darwin":
        raise Unsupported("Seatbelt is a macOS facility.")

    api = lib()
    text = profile(policy, tag, port).encode()
    err = ctypes.c_char_p()
    rc = api.sandbox_init(text, 0, ctypes.byref(err))
    if rc != 0:
        detail = err.value.decode(errors="replace") if err.value else "no detail given"
        if err.value:
            api.sandbox_free_error(err)
        raise Failed(
            f"the kernel refused the environment profile: {detail}. "
            "The process is NOT confined."
        )
    return 1


seal = load


def listen() -> Listener:
    """How `hlyn run` hears what this backend refused: the system log."""
    from .oslog import Listener

    return Listener()
