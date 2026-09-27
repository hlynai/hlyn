"""What the boundary refused, in words someone can act on.

When the kernel refuses a call, the program gets `Operation not permitted` and
nothing else hears about it. If the program swallows the error, falls back or
retries, the person running it sees an agent behaving oddly and no reason why
-- and reaches for `--preset debug`, which turns the product off. `hlyn run`
therefore listens for refusals while the command runs and, at the end, says
what was blocked and which flag would allow it:

    hlyn: blocked 2 things
      read   /etc/app/config.json   allow with --read /etc/app/config.json
      net    TCP 5432 (127.0.0.1)   allow with --net 5432

This module is the platform-neutral half: it turns raw refusals into that
list. How refusals are heard differs per platform and lives with each backend
(`core/oslog.py` on macOS, `core/preload.py` on Linux); both hand over
`Denial` records and nothing else.

Three rules shape it.

**Suggest, never grant.** A refusal can be the boundary working: a
prompt-injected agent reaching for `~/.ssh` is refused on purpose, and turning
that into a one-paste grant would hand the attacker the key. So credentials are
named as credentials and get no suggested flag.

**Believe nothing the policy already allows.** On Linux the records come from
inside the confined program, which can write anything to its end of the pipe.
Every refusal is checked against the policy and against the file's own
permissions before it is shown, so a record claiming a path was blocked when
the policy grants it -- or when nobody could open it, confined or not -- is
dropped rather than turned into advice.

**Everything shown came from outside.** Paths and process names are sanitised
before they reach a terminal, so a file named with escape sequences cannot
repaint the user's screen.
"""

from __future__ import annotations

import os
import shlex
import shutil
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy import Policy, under
from .secret import credential, secret

__all__ = [
    "HOSTED", "SERVICES", "WHY", "Denial", "Entry", "Listener", "Quiet", "Report",
    "credential", "removed", "safe", "secret",
]


# ---------------------------------------------------------------------------
# what a listener hands over
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Denial:
    """One refusal, as heard.

    `kind` is the policy field that would allow it -- read, write, exec, net --
    or `bind` for listening on a port, or `other` for something no field
    covers. `target` is a path, `PORT ADDRESS` for IP, `unix:PATH` for a local
    socket, or `socket:N` for a socket that could not be created at all.
    """

    kind: str
    target: str
    op: str = ""
    by: str = ""
    pid: int = 0
    count: int = 1
    # "kernel": from the OS; "program": from inside the agent; "proxy": from
    # hlyn's proxy (host mode), where `op` is its reason (4.6's `why`) and
    # `allow` the flag it suggests, checked before use (see `_host`).
    source: str = "kernel"
    allow: str = ""


class Listener(Protocol):
    """How a backend hears refusals. See `core/oslog.py` and `core/preload.py`.

    Used in this order: `grant` and `env` shape the child before it seals,
    `start` runs before the fork, `read` whenever `fileno` is readable,
    `finish` once the command has exited, `close` always.
    """

    source: str
    tag: str | None
    why: str | None

    def grant(self, plan: Policy) -> Policy: ...
    def env(self, keep: Mapping[str, str]) -> dict[str, str]: ...
    def start(self) -> None: ...
    def fileno(self) -> int | None: ...
    def read(self) -> list[Denial]: ...
    def finish(self) -> list[Denial]: ...
    def close(self) -> None: ...


class Quiet:
    """A listener that hears nothing, and says why."""

    source = "none"
    tag: str | None = None

    def __init__(self, why: str | None = None) -> None:
        self.why = why

    def grant(self, plan: Policy) -> Policy:
        return plan

    def env(self, keep: Mapping[str, str]) -> dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def fileno(self) -> int | None:
        return None

    def read(self) -> list[Denial]:
        return []

    def finish(self) -> list[Denial]:
        return []

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# judgements about a single target
# ---------------------------------------------------------------------------

# Probes every program makes and nothing can act on: the dynamic loader
# looking for DTrace on macOS, CPython listing its open descriptors before
# starting a subprocess (it falls back to closing them one by one), and
# CPython's allocator reading the kernel's overcommit setting during
# interpreter start-up on Linux -- still happens with `-I -S`, before any
# user or site code runs, so it is not something the program did. Exact
# paths only, so a real read beneath either is still reported.
NOISE: frozenset[tuple[str, str]] = frozenset({
    ("read", "/dev/dtracehelper"),
    ("read", "/dev/fd"),
    ("read", "/proc/sys/vm/overcommit_memory"),
})

# macOS services refused under net=False because each one goes on the network
# for its caller (FINDINGS.md, "the blanket mach-lookup grant"). The profile
# in core/mac.py refuses exactly these; the report says what each one does.
SERVICES: dict[str, str] = {
    "com.apple.trustd.agent": "checks certificates, and fetches URLs named inside them",
    "com.apple.dnssd.service": "looks up host names",
}

# The same services when `net` names hosts, where no flag lifts the refusal
# (DESIGN-host-allowlisting.md 5.4): what to tell the user instead.
HOSTED: dict[str, str] = {
    "com.apple.trustd.agent": (
        "this program checks certificates through macOS's trustd, which fetches URLs on its "
        "behalf and would carry data past --net. It can't run with --net hosts on macOS yet"
    ),
    "com.apple.dnssd.service": (
        "this program looked up a host name itself. With --net hosts the proxy looks up names: "
        "it has to use HTTPS_PROXY"
    ),
}

# What each of the proxy's reasons (4.6) means, for the report.
WHY: dict[str, str] = {
    "not-listed": "",
    "private-address": "the name resolves to a private address, never reached by name",
    "sni-mismatch": "its TLS named a different host than it asked for, so hlyn closed the connection",
    "dns": "DNS: with --net hosts the proxy looks up names, so programs never need it",
    "resolve-failed": "the name didn't resolve",
    "direct": "connected directly instead of through HTTPS_PROXY",
    "busy": "the proxy was at its limit of connections at once",
}

def _refused(path: str) -> bool:
    """Whether host mode refuses a unix socket at `path` whatever the grants
    (the macOS profile's list, core/mac.py `REFUSED`)."""
    import re

    from .core.mac import REFUSED

    real = os.path.realpath(path)
    return any(re.search(pattern, real) for pattern in REFUSED)


def removed(plan: Policy, env: Mapping[str, str]) -> list[str]:
    """Environment variables `plan` strips, secret-looking names first.

    Names only, never values. hlyn's own variables are left out: they are how
    it finds its libraries, not something the agent was using.
    """
    if plan.env is True:
        return []
    keep = plan.keep(env)
    gone = [name for name in env if name not in keep and not name.startswith("HLYN_") and name != "_"]
    return sorted(gone, key=lambda name: (not secret(name), name))


def safe(text: str) -> str:
    """`text` with anything a terminal would interpret made visible instead.

    Covers control characters, escape sequences, bidirectional overrides and
    the undecodable bytes a path can carry. What remains is exactly what
    `str.isprintable` accepts, plus the ordinary space.
    """
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def tilde(path: str) -> str:
    """`path` with the home directory written as `~`, the way people type it."""
    home = os.path.expanduser("~")
    if home not in ("", "/") and under(path, home):
        return "~" + path[len(home.rstrip(os.sep)):]
    return path


def flag(name: str, value: str) -> str:
    """A flag as it would be typed, quoted if the shell needs it.

    `~` is left unquoted so it reads naturally; hlyn expands it itself, so the
    flag works whether or not the shell does.
    """
    shown = tilde(value)
    quoted = shlex.quote(shown)
    if quoted != shown and (
        shown == "~" or (shown.startswith("~/") and shlex.quote(shown[2:]) == shown[2:])
    ):
        quoted = shown
    return f"{name} {quoted}"


# Calls that act on a directory entry rather than the file: removing, making,
# renaming or linking one needs write on the directory that holds it.
ENTRY = frozenset({
    "unlink", "rmdir", "rename", "mkdir", "link", "symlink",
    "file-write-create", "file-write-unlink",
})

# Socket families, as `socket:N` reports them.
FAMILY = {2: "IPv4", 10: "IPv6", 17: "raw packets", 16: "netlink", 31: "Bluetooth", 40: "vsock"}


# ---------------------------------------------------------------------------
# a refusal, understood
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Entry:
    """One line of the report: a refused target and what would allow it."""

    kind: str
    target: str  # as shown
    allow: str | None  # the flag that allows it, if there is one to suggest
    note: str = ""  # said instead of, or as well as, a flag
    credential: bool = False
    count: int = 0
    by: set[str] = field(default_factory=set)
    source: str = "kernel"
    # Worth listing when the command failed, not worth a report of its own
    # when it succeeded: see `Report._listing`.
    quiet: bool = False
    counts: dict[Any, int] = field(default_factory=dict)  # see `Report.add`
    folded: int = 0

    def json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "allow": self.allow,
            "note": self.note or None,
            "credential": self.credential,
            "quiet": self.quiet,
            "count": self.count,
            "by": sorted(self.by),
            "source": self.source,
        }


ORDER = {"read": 0, "write": 1, "exec": 2, "net": 3, "bind": 4, "other": 5}

# How many distinct refusals one run keeps. An agent walking a tree it cannot
# read produces them without end, and a report is not the place to find out
# how much memory that takes.
LIMIT = 1000

# How many lines the human report shows before pointing at --json.
ROWS = 20


class Report:
    """Everything refused during one run, grouped, checked and explained.

    `plan` is the policy the user asked for -- not the one with hlyn's own
    listening grants added -- because it is the one suggestions extend.
    """

    def __init__(
        self,
        plan: Policy,
        env: Mapping[str, str] | None = None,
        which: Callable[[str], str | None] = shutil.which,
        cwd: str | None = None,
    ) -> None:
        self.plan = plan
        self.cwd = os.path.realpath(cwd or os.getcwd())
        self.env = removed(plan, os.environ if env is None else env)
        self.which = which
        self.entries: dict[tuple[str, str], Entry] = {}
        self.dropped = 0  # refusals the policy explains away: see `verify`
        self.system = 0  # refusals of OS plumbing no flag allows: see `judge`
        self.more = 0  # distinct refusals past LIMIT
        self.why: str | None = None  # set when listening was degraded
        self._reads = plan.reads()
        self._writes = plan.writes()
        self._runs = plan.runs()

    # -- taking denials in -------------------------------------------------

    def add(self, denial: Denial) -> Entry | None:
        """File one refusal. Returns its entry, or None if it was dropped."""
        made = self.judge(denial)
        if made is None:
            self.dropped += 1
            return None
        key = (made.kind, made.target)
        entry = self.entries.get(key)
        if entry is None:
            if len(self.entries) >= LIMIT:
                self.more += 1
                return None
            entry = self.entries[key] = made
        if denial.by:
            entry.by.add(safe(denial.by)[:32])
        seen = max(1, denial.count)
        if denial.source == "program":
            # Running totals per process and target (1, 2, 4, 8 ...), so the
            # largest heard is that process's total.
            which = (denial.pid, denial.target)
            entry.counts[which] = max(entry.counts.get(which, 0), seen)
        else:
            # One event per refusal, or a batch the OS folded together.
            entry.counts[0] = entry.counts.get(0, 0) + seen
        if len(entry.counts) > 256:
            # A fork-heavy retry loop: fold the oldest total into a plain sum
            # rather than keep one per process forever.
            first = next(iter(entry.counts))
            entry.folded += entry.counts.pop(first)
        entry.count = entry.folded + sum(entry.counts.values())
        return entry

    def judge(self, denial: Denial) -> Entry | None:
        """What a refusal means and how to allow it, or None to drop it."""
        kind, target = denial.kind, denial.target
        if denial.source == "proxy":
            return self._host(denial)
        if kind in ("read", "write", "exec"):
            return self._path(denial)
        if kind == "net" and target.startswith("socket:"):
            return self._socket(denial)
        if kind == "net" and target.startswith("unix:"):
            return self._local(denial)
        if kind in ("net", "bind"):
            return self._port(denial)
        if kind == "system" and denial.op == "mach-lookup" and target in HOSTED and self.plan.hosts():
            return Entry("net", f"macOS service {target}", None, HOSTED[target], source=denial.source)
        if kind == "system" and denial.op == "mach-lookup" and target in SERVICES:
            # Not plumbing: a service that would reach the network for the
            # program. Refused only while the network is off, so naming a
            # port (which allows HTTPS) lifts it.
            return Entry("net", f"macOS service {target}", "--net 443",
                         f"{SERVICES[target]} on the program's behalf; refused while net is off",
                         source=denial.source)
        if kind == "system":
            # The OS's own plumbing (macOS): counted, shown with --json, left
            # out of the list, since no flag allows it and a list full of
            # unactionable lines teaches people to stop reading it.
            self.system += 1
            return None
        text = safe(f"{denial.op} {target}".strip())
        return Entry("other", text, None, "not something a policy field allows", source=denial.source)

    def _path(self, denial: Denial) -> Entry | None:
        kind, raw = denial.kind, denial.target
        if kind == "exec" and "/" not in raw:
            found = self.which(raw)
            if not found:
                return None  # nothing by that name, so nothing was refused
            raw = found
        if not raw.startswith("/"):
            return None  # relative to a descriptor that could not be named
        path = os.path.normpath(raw)
        if kind == "exec":
            path = os.path.realpath(path)
        if (kind, path) in NOISE:
            return None
        if not self.verify(kind, path, denial.op):
            return None

        target = safe(tilde(path))
        if under(path, "/proc"):
            # Closed on purpose: /proc/self/environ still holds every variable
            # the scrub removed (see `policy.runtime`). And a grant would not
            # follow the process anyway -- /proc/self names a different file
            # in every process. CPython reads /proc/self/stat on each fork and
            # carries on, so this is quiet unless the command failed.
            return Entry(kind, target, None,
                         "under /proc, which hlyn keeps closed: it holds the environment hlyn removed",
                         quiet=True, source=denial.source)
        if kind == "write" and "/__pycache__/" in path:
            # Python caching compiled bytecode beside a module it imported.
            # Refused, it compiles in memory and carries on; allowing it would
            # mean write access to the installed packages.
            return Entry(kind, target, None, "Python's bytecode cache: it runs fine without it",
                         quiet=True, source=denial.source)
        if kind == "read" and os.path.isdir(path):
            listing = self._listing(path, target, denial.source)
            if listing is not None:
                return listing
        if credential(path):
            return Entry(
                kind, target, None,
                "a credential: not suggested. Grant it yourself only if the agent should have it",
                credential=True, source=denial.source,
            )
        grant = path
        if kind == "write" and (denial.op in ENTRY or not os.path.exists(path)):
            # Making or removing an entry needs the directory, and a path that
            # does not exist cannot be granted at all.
            grant = os.path.dirname(path) or "/"
            if credential(grant):
                return Entry(kind, target, None, "inside a credential directory: not suggested",
                             credential=True, source=denial.source)
        return Entry(kind, target, flag(f"--{kind}", grant), source=denial.source)

    def _listing(self, path: str, target: str, source: str) -> Entry | None:
        """A refused listing of the start folder, a folder above it, or home.

        Programs do this on their own while starting -- macOS Python lists the
        working directory and the home folder on every launch, then carries
        on -- so it is not worth a report when the command succeeded. And a
        read grant is a whole tree, so suggesting `--read ~` to allow a
        listing would grant everything in the home folder to fix nothing.
        """
        real = os.path.realpath(path)
        home = os.path.realpath(os.path.expanduser("~"))
        if real == self.cwd:
            return Entry("read", target, flag("--read", path),
                         "the folder it was started in", quiet=True, source=source)
        if under(self.cwd, real) or real == home:
            where = "your home folder" if real == home else "a folder above the one it started in"
            return Entry("read", target, None,
                         f"{where}: listing only; a grant would expose everything inside",
                         quiet=True, source=source)
        return None

    def _host(self, denial: Denial) -> Entry | None:
        """A block by hlyn's proxy (host mode, 4.6). Its words are checked,
        not trusted: the proxy reads what the agent sends, so a suggested flag
        is used only if it parses as an entry and says exactly that."""
        from .error import Invalid
        from .hosts import parse

        why = denial.op
        if why not in WHY:
            return None
        target = safe(denial.target)[:300] or "a connection"
        allow = denial.allow if denial.allow.startswith("--net ") else None
        if allow is not None:
            try:
                allow = allow if parse(allow[len("--net "):]).flag() == allow else None
            except Invalid:
                allow = None
        if why in ("sni-mismatch", "resolve-failed", "busy", "dns"):
            allow = None  # nothing to add to net would fix these
        return Entry("net", target, allow, WHY[why], source="proxy")

    def _port(self, denial: Denial) -> Entry | None:
        head, _, rest = denial.target.partition(" ")
        if not head.isdigit():
            return None
        port = int(head)
        net = self.plan.net
        anywhere = rest in ("", "*", "0.0.0.0", "::")  # noqa: S104 - read from a report, not bound
        shown = f"TCP {port}" + ("" if anywhere else f" ({safe(rest)})")
        if self.plan.hosts():
            # Host mode: a program connected directly rather than through the
            # proxy. On macOS only localhost entries are reachable that way
            # (5.4), so that is the only flag that could help.
            local = rest in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1")
            if local:
                return Entry("net", shown, f"--net localhost:{port}", WHY["direct"], source=denial.source)
            return Entry("net", shown, None,
                         WHY["direct"] + "; on macOS a program must use the proxy for anything but "
                         "localhost entries", source=denial.source)
        if denial.op in ("sendto", "sendmsg"):
            # TCP Fast Open, which hlyn refuses whenever ports are named: Linux
            # before 7.2 lets it past Landlock's port rules, allowed port or not.
            if net is True:
                return None
            return Entry("net", f"TCP Fast Open to port {port}" + ("" if anywhere else f" ({safe(rest)})"),
                         "--net-any",
                         "Fast Open gets past port rules, so only the whole network allows it; "
                         "without it the program can connect normally", source=denial.source)
        if denial.kind == "bind":
            if net is True:
                return None
            return Entry("bind", f"listen on {port}", "--net-any",
                         "listening for connections needs the whole network", source=denial.source)
        if net is True:
            return None
        if isinstance(net, tuple) and port in net:
            if denial.source == "program":
                return None  # a TCP port the policy allows: not hlyn's refusal
            # macOS names ports as TCP rules, so a refusal on an allowed port
            # is another protocol -- UDP, usually DNS or QUIC.
            return Entry("net", f"UDP or other traffic to port {port}", "--net-any",
                         "only the whole network allows traffic other than TCP", source=denial.source)
        return Entry("net", shown, f"--net {port}", source=denial.source)

    def _socket(self, denial: Denial) -> Entry | None:
        try:
            family = int(denial.target.partition(":")[2])
        except ValueError:
            return None
        name = FAMILY.get(family, f"family {family}")
        if family in (2, 10, 17):
            if self.plan.net is not False:
                return None  # the network is open, so something else refused it
            return Entry("net", f"any network ({name})", "--net-any",
                         "or --net PORT for just the port it needs", source=denial.source)
        return Entry("other", f"a {name} socket", None, "hlyn never allows this kind of socket",
                     source=denial.source)

    def _local(self, denial: Denial) -> Entry | None:
        where = denial.target[len("unix:"):]
        if where.startswith("@"):
            return Entry("other", f"local socket {safe(where)}", None,
                         "belongs to a process outside this agent; hlyn never allows reaching it",
                         source=denial.source)
        if denial.source == "program":
            # Landlock does not govern connecting to a socket file on the
            # kernels hlyn supports, so a refusal here is the file's own
            # permissions -- or the agent's word, which is not enough.
            return None
        if self.plan.net is True:
            return None
        if self.plan.hosts():
            # Host mode: a unix socket needs a write grant on its folder
            # (5.3, 5.4), except the always-refused ones.
            if _refused(where):
                return Entry("net", f"local socket {safe(tilde(where))}", None,
                             "never reachable with --net hosts: the program behind it acts for you, "
                             "on the network or the machine. Use --net-any if you mean it",
                             source=denial.source)
            return Entry("net", f"local socket {safe(tilde(where))}",
                         flag("--write", os.path.dirname(where) or "/"),
                         "connecting to a local socket needs write access to its folder",
                         source=denial.source)
        return Entry("net", f"local socket {safe(tilde(where))}", "--net-any",
                     "on macOS only the whole network allows local sockets", source=denial.source)

    def verify(self, kind: str, path: str, op: str) -> bool:
        """Whether a refusal of `path` can have come from this policy.

        False when the policy grants it (so the refusal came from somewhere
        else, or was invented), and when the file's own permissions refuse
        this unconfined process too (so allowing it in the policy would change
        nothing).
        """
        grants = {"read": self._reads, "write": self._writes, "exec": self._runs}[kind]
        if grants is True:
            return False
        real = os.path.realpath(path)
        if grants and any(under(real, os.path.realpath(item)) for item in grants):
            return False
        mode = {"read": os.R_OK, "write": os.W_OK, "exec": os.X_OK}[kind]
        if os.path.exists(real) and not (kind == "write" and op in ENTRY):
            return os.access(real, mode)
        parent = os.path.dirname(real)
        return not os.path.isdir(parent) or os.access(parent, os.W_OK | os.X_OK)

    # -- saying it -----------------------------------------------------------

    def items(self) -> list[Entry]:
        return sorted(
            self.entries.values(),
            key=lambda e: (not e.credential, e.quiet, ORDER.get(e.kind, 9), e.target),
        )

    def json(self, code: int | None = None) -> dict[str, Any]:
        return {
            "exit": code,
            "blocked": [entry.json() for entry in self.items()],
            "more": self.more,
            "system": self.system,
            "removed_env": self.env,
            "why": self.why,
        }

    def text(self, code: int, cmd: Iterable[str] = ()) -> str:
        """The report for a person, or "" when there is nothing worth saying.

        A failed run gets everything that might explain it. A successful run
        that was refused something gets the list too, because a program that
        quietly worked around a refusal is behaving differently from the one
        that was tested. A successful run with nothing refused prints nothing.
        """
        import signal

        cmd = list(cmd)
        items = self.items()
        if not code:
            items = [e for e in items if not e.quiet]
        out: list[str] = []

        if code == -signal.SIGSYS:
            out.append(
                "hlyn: the kernel stopped the command: it made a system call hlyn never allows "
                "(e.g. ptrace, io_uring, mount, loading kernel modules)."
            )
        elif items:
            said = f"signal {-code}" if code < 0 else f"code {code}"
            count = len(items) + self.more
            things = f"{count} thing{'s' if count != 1 else ''}"
            if code:
                out.append(f"hlyn: the command exited with {said}. hlyn blocked {things}:")
            else:
                out.append(
                    f"hlyn: the command finished, but hlyn blocked {things} it may have worked around:"
                )
            out.extend(self._rows(items, cmd))
            if self.more:
                out.append(f"  and {self.more} more refusals past the first {LIMIT}, not listed.")
            combined = [e.allow for e in items if e.allow and not e.quiet]
            unique = list(dict.fromkeys(combined))
            if len(unique) > 1:
                out.append(f"  to allow all of these: {' '.join(unique)}")
            if any(e.kind == "net" and e.allow and e.allow.startswith("--net ") and not e.allow[6:].isdigit()
                   for e in items):
                # 4.6: the agent picks where it tries to go.
                out.append("  Only allow hosts you recognise: an injected agent chooses where it "
                           "tries to go.")
        elif code:
            said = f"signal {-code}" if code < 0 else f"code {code}"
            out.append(f"hlyn: the command exited with {said}.")
            if self.why:
                out.append(f"      Blocked actions could not be listed: {self.why}.")
            out.append(
                "      If it was blocked, the error above names the path, program or port.\n"
                "      Allow it with --read, --write, --exec or --net."
            )
            if cmd and os.path.basename(cmd[0]).startswith("python"):
                out.append(f"      Or draft the policy it needs with: hlyn watch -- {shlex.join(cmd)}")

        if code and code != -signal.SIGSYS and self.env:
            out.append(self._removed())
        if items and self.why:
            out.append(f"hlyn: this list may be incomplete: {self.why}.")
        return "\n".join(out) + "\n" if out else ""

    def _group(self, items: list[Entry]) -> list[Entry]:
        """Entries sharing one suggested flag, folded into a single line.

        A program refused 6,400 files in one folder needs one line saying so,
        not 6,400 lines saying `--write` that folder again.
        """
        out: list[Entry] = []
        together: dict[tuple[str, str, bool], list[Entry]] = {}
        for e in items:
            if e.kind not in ("read", "write", "exec"):
                # Only paths fold: "N paths under X" means nothing for a
                # socket or a service, and their flags may name no folder.
                out.append(e)
            elif e.allow and not e.quiet:
                together.setdefault((e.kind, e.allow, False), []).append(e)
            elif e.quiet and not e.allow and e.note:
                # The same harmless thing, many times: one line.
                together.setdefault((e.kind, e.note, True), []).append(e)
            else:
                out.append(e)
        for (kind, said, quiet), group in together.items():
            if len(group) == 1:
                out.append(group[0])
                continue
            if quiet:
                paths = [os.path.expanduser(e.target) for e in group]
                try:
                    where = safe(tilde(os.path.commonpath(paths)))
                except ValueError:
                    where = "several places"
                merged = Entry(kind, f"{len(group)} paths under {where}", None, said, quiet=True,
                               source=group[0].source)
            else:
                where = said.split(" ", 1)[1]
                merged = Entry(kind, f"{len(group)} paths under {where}", said, source=group[0].source)
            for e in group:
                merged.by |= e.by
                merged.count += e.count
            out.append(merged)
        return sorted(out, key=lambda e: (not e.credential, e.quiet, ORDER.get(e.kind, 9), e.target))

    def _rows(self, items: list[Entry], cmd: list[str]) -> list[str]:
        items = self._group(items)
        hidden = max(0, len(items) - ROWS)
        items = items[:ROWS]
        width = min(max(len(e.target) for e in items), 44)
        mine = self._names(cmd)
        rows = []
        for e in items:
            said = f"allow with {e.allow}" if e.allow else e.note
            if e.allow and e.note:
                said += f" ({e.note})"
            extra = []
            # Only processes other than the command itself are named: saying
            # "by python" on every line of a Python agent's report is noise.
            others = sorted(name for name in e.by if not self._same(name, mine))
            if others:
                extra.append("by " + ", ".join(others[:3]) + (" and others" if len(others) > 3 else ""))
            if e.count > 1:
                extra.append(f"{e.count}+ times" if e.source == "program" else f"{e.count} times")
            tail = f"  [{'; '.join(extra)}]" if extra else ""
            rows.append(f"  {e.kind:<6} {e.target:<{width}}  {said}{tail}")
        if hidden:
            lines = f"line{'s' if hidden != 1 else ''}"
            rows.append(f"  and {hidden} more {lines}. Add --json to see all of them.")
        return rows

    def _names(self, cmd: list[str]) -> set[str]:
        """What the command's own process can be called in a report.

        The kernel names a process after its executable, cut to 15 characters,
        and macOS after the bundle (`Python` for `python3`), so `python3` may
        appear as `python3.13` or `Python`.
        """
        if not cmd:
            return set()
        names = {os.path.basename(cmd[0])}
        found = self.which(cmd[0])
        if found:
            names.add(os.path.basename(os.path.realpath(found)))
        return {name[:15].lower() for name in names if name}

    @staticmethod
    def _same(name: str, mine: set[str]) -> bool:
        low = name.lower()
        return any(low == m or m.startswith(low) or low.startswith(m) for m in mine)

    def _removed(self) -> str:
        names = self.env
        secrets = [n for n in names if secret(n)]
        shown = secrets[:3] or names[:3]
        lead = "including" if secrets else "e.g."
        example = shown[0]
        count = len(names)
        return (
            f"hlyn: removed {count} environment variable{'s' if count != 1 else ''} "
            f"({lead} {', '.join(safe(n) for n in shown)}).\n"
            f"      Keep one with --env NAME, e.g. --env {safe(example)}"
        )
