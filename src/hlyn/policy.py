"""What an agent may read, write, run, and reach.

Deny by default: an empty policy grants nothing except the interpreter's own
files, without which the process cannot survive its next import.

Nothing here touches the kernel. This module decides *intent*; the backends in
`core/` translate intent into enforcement. Keeping the two apart means a policy
can be inspected, diffed, and tested on any machine, including ones that cannot
enforce it.
"""

from __future__ import annotations

import os
import site
import sys
import sysconfig
from dataclasses import dataclass, replace
from typing import Callable, Iterable, Mapping

from .error import Invalid, Unsupported

__all__ = ["Policy", "preset", "register", "presets", "runtime", "SAFE"]


# Environment variables kept when `env` scrubbing is on. Locale, paths, and the
# temp directory: enough for the interpreter and the C library to behave, and
# nothing shaped like a credential. Anything else must be named explicitly.
SAFE: tuple[str, ...] = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "PATH",
    "PWD",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
)


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------


def _one(item: object, field: str) -> str:
    """Turn a single path-ish value into an absolute path string."""
    if isinstance(item, bool) or not isinstance(item, (str, os.PathLike)):
        raise Invalid(
            f"{field}: expected a path, got {type(item).__name__} ({item!r}). "
            f"Use {field}=True to allow everything or {field}=False to allow nothing."
        )
    text = os.fspath(item)
    if not text:
        raise Invalid(f"{field}: empty path. Remove it, or use {field}=False.")
    return os.path.abspath(os.path.expanduser(text))


def paths(value: object, field: str) -> tuple[str, ...] | bool:
    """Normalise a filesystem option to `True`, `False`, or a tuple of paths.

    Accepts a bool, `None`, a single path, or any iterable of paths, so callers
    can write the obvious thing and get the same result either way.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (str, os.PathLike)):
        return (_one(value, field),)
    if isinstance(value, Iterable):
        out = tuple(_one(item, field) for item in value)
        return prune(out)
    raise Invalid(f"{field}: expected a path, a list of paths, or a bool, got {value!r}.")


def ports(value: object, field: str = "net") -> tuple[int, ...] | bool:
    """Normalise a network option to `True`, `False`, or a tuple of TCP ports.

    Host names are rejected rather than accepted-and-ignored. The kernel cannot
    filter by host: Landlock matches ports, and a classic seccomp filter cannot
    dereference the `sockaddr` pointer passed to `connect`. Accepting
    `net=["api.openai.com"]` here would imply an enforcement that does not
    exist, which is the one failure mode a containment layer must never have.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int):
        value = (value,)
    if isinstance(value, (str, os.PathLike)):
        value = (value,)
    if not isinstance(value, Iterable):
        raise Invalid(f"{field}: expected a port, a list of ports, or a bool, got {value!r}.")

    out: list[int] = []
    for item in value:
        if isinstance(item, bool):
            raise Invalid(f"{field}: expected a port number, got {item!r}.")
        if isinstance(item, str):
            if not item.isdigit():
                raise Unsupported(
                    f"{field}: host names are not enforceable yet, so {item!r} is refused "
                    f"rather than silently ignored. The kernel filters ports, not hosts. "
                    f"Use net=False to block all network access, net=True to allow it, or "
                    f"name the ports, e.g. net=[443]."
                )
            port = int(item)
        elif isinstance(item, int):
            port = item
        else:
            # Accept anything that converts to a whole number exactly, so a
            # numpy integer or a Decimal works. Refuse anything that would have
            # to be rounded: `int(1.5)` is 1, so accepting it would open a port
            # the caller never named -- the same quiet substitution that host
            # names are refused for above.
            try:
                port = int(item)
            except (TypeError, ValueError):
                raise Invalid(
                    f"{field}: expected a port number, got {item!r} "
                    f"({type(item).__name__})."
                ) from None
            if port != item:
                raise Invalid(
                    f"{field}: {item!r} is not a whole port number. Rounding it to "
                    f"{port} would grant a different port than the one named."
                )
        if not 0 < port < 65536:
            raise Invalid(f"{field}: {port} is not a port number (1-65535).")
        out.append(port)
    return tuple(sorted(set(out)))


def names(value: object, field: str = "env") -> tuple[str, ...] | bool:
    """Normalise an environment option to `True`, `False`, or a tuple of names."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, Iterable):
        raise Invalid(f"{field}: expected a name, a list of names, or a bool, got {value!r}.")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise Invalid(f"{field}: expected an environment variable name, got {item!r}.")
        out.append(item)
    return tuple(sorted(set(out)))


def under(path: str, root: str) -> bool:
    """True if `path` is `root` or sits beneath it."""
    if path == root:
        return True
    return path.startswith(root.rstrip(os.sep) + os.sep)


def prune(items: Iterable[str]) -> tuple[str, ...]:
    """Drop paths already covered by an ancestor in the same set.

    Purely a simplification: granting `/usr` and `/usr/lib` is the same as
    granting `/usr`. A smaller rule set is cheaper for the kernel and far
    easier for a human to audit in the log.
    """
    kept = sorted(set(items))
    out: list[str] = []
    for item in kept:
        if not any(under(item, done) for done in out):
            out.append(item)
    return tuple(out)


# ---------------------------------------------------------------------------
# what the interpreter itself needs
# ---------------------------------------------------------------------------


def _roots() -> tuple[str, ...]:
    """The directory trees that belong to the interpreter, not to the user."""
    out: set[str] = set()
    for item in (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        sys.base_exec_prefix,
    ):
        if item:
            out.add(os.path.abspath(item))
    if sys.executable:
        out.add(os.path.dirname(os.path.abspath(os.path.realpath(sys.executable))))
    try:
        config = sysconfig.get_paths()
    except Exception:  # a broken sysconfig must not stop us from confining
        config = {}
    for key in ("stdlib", "platstdlib", "purelib", "platlib", "data"):
        item = config.get(key)
        if item:
            out.add(os.path.abspath(item))
    try:
        out.update(os.path.abspath(item) for item in site.getsitepackages())
    except Exception:
        pass
    try:
        user = site.getusersitepackages()
    except Exception:
        user = None
    if isinstance(user, str) and user:
        out.add(os.path.abspath(user))
    return tuple(out)


def _lib() -> tuple[str, ...]:
    """Shared libraries and loader data, per platform."""
    if sys.platform == "darwin":
        return (
            "/usr/lib",
            "/usr/share/icu",
            "/usr/share/zoneinfo",
            "/System/Library",
            "/private/var/db/dyld",
            "/System/Volumes/Preboot/Cryptexes/OS",
        )
    return (
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/local/lib64",
        "/usr/share/zoneinfo",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/localtime",
    )


def _dev() -> tuple[str, ...]:
    """Character devices the runtime reads."""
    return ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full")


def _sink() -> tuple[str, ...]:
    """Character devices the runtime writes to.

    Only the discard device. Already-open descriptors such as stdout survive
    confinement untouched, so ordinary printing keeps working without a grant.
    """
    return ("/dev/null",)


def _items(value: tuple[str, ...] | bool) -> tuple[str, ...]:
    """The explicit entries of a field, or nothing if it is a plain bool."""
    return value if isinstance(value, tuple) else ()


def loader() -> tuple[str, ...]:
    """Directories holding the dynamic loader.

    Running a dynamically linked program needs execute permission on the ELF
    interpreter as well as on the program, so granting it only on the named
    binary fails with a bare `Permission denied` from `execve`.

    Scoped to the library directories on purpose. Handing execute to the whole
    of `sys.prefix` would cover its `bin/` as well, quietly making every tool
    shipped with the interpreter runnable. Shared libraries and C extension
    modules are unaffected: they are mapped, not executed, and load without
    this.
    """
    out = {item for item in _lib() if os.path.exists(item)}
    where = sysconfig.get_config_var("LIBDIR")
    if isinstance(where, str) and where and os.path.exists(where):
        out.add(os.path.abspath(where))
    if sys.platform == "darwin":
        # A framework build ships bin/pythonX.Y as a stub that immediately
        # re-execs the real interpreter inside Resources/Python.app. Granting
        # execute on the name in bin/ is therefore not enough, and the failure
        # is a bare `posix_spawn: ... Undefined error: 0`. Resources is named
        # specifically so that bin/ stays non-executable.
        inner = os.path.join(sys.prefix, "Resources")
        if os.path.exists(inner):
            out.add(inner)
    return prune(out)


def runtime() -> tuple[str, ...]:
    """Paths the interpreter must read to survive deny-by-default.

    Computed from the live interpreter, never hardcoded, so this is correct
    inside a virtualenv, a container, a Homebrew prefix, or a framework build.

    Deliberately excluded:

    `/proc` — `/proc/self/environ` exposes the environment block captured at
    exec time, which does *not* change when `os.environ` is scrubbed. Granting
    `/proc/self` would hand back every secret the `env` control just removed.

    The working directory and the running script's directory — that is the
    user's data, not the runtime's. A policy that silently read it would make
    `hlyn.on()` far more permissive than it looks.
    """
    out: set[str] = set(_roots())

    # Import-path entries that belong to the interpreter. Entries outside these
    # roots are the user's own code and are not granted here.
    for item in sys.path:
        if not item or not os.path.isabs(item):
            continue
        item = os.path.abspath(item)
        if any(under(item, root) for root in out):
            out.add(item)

    if sys.executable:
        out.add(os.path.abspath(sys.executable))
    out.update(_lib())
    out.update(_dev())

    return prune(item for item in out if os.path.exists(item))


# ---------------------------------------------------------------------------
# the policy itself
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Policy:
    """A single, immutable statement of what an agent is allowed to do.

    Every field takes the same three shapes: `False` to allow nothing, `True`
    to allow everything, or an explicit list. Defaults are the strictest
    setting that still leaves a working interpreter.

        Policy()                                    # nothing but the runtime
        Policy(read=["/src"], write=["/out"])       # named directories
        Policy(net=[443], exec=False)               # ports, no new programs

    Frozen on purpose. A policy that can be edited after it has been checked
    is a policy that can be edited by whatever compromised the agent.
    """

    read: tuple[str, ...] | bool = ()
    write: tuple[str, ...] | bool = ()
    exec: tuple[str, ...] | bool = False
    net: tuple[int, ...] | bool = False
    env: tuple[str, ...] | bool = False
    tmp: bool | str = True
    log: bool | str = True

    def __post_init__(self) -> None:
        put = object.__setattr__  # frozen dataclass, so assign through the base
        put(self, "read", paths(self.read, "read"))
        put(self, "write", paths(self.write, "write"))
        put(self, "exec", paths(self.exec, "exec"))
        put(self, "net", ports(self.net))
        put(self, "env", names(self.env))
        if not isinstance(self.tmp, (bool, str)):
            raise Invalid(f"tmp: expected a bool or a directory, got {self.tmp!r}.")
        if not isinstance(self.log, (bool, str)):
            raise Invalid(f"log: expected a bool or a file path, got {self.log!r}.")

    # -- derived views ------------------------------------------------------
    #
    # The four dimensions stay independent: granting write everywhere does not
    # quietly grant read everywhere. Only explicitly named paths cross over,
    # because a caller who writes `write=["/out"]` expects to read back what
    # they wrote, and a named executable has to be readable to be run.

    def reads(self) -> tuple[str, ...] | bool:
        """Everything readable, including the interpreter's own files."""
        if self.read is True:
            return True
        out = list(runtime())
        out.extend(_items(self.read))
        out.extend(_items(self.write))
        out.extend(_items(self.exec))
        if isinstance(self.tmp, str):
            out.append(os.path.abspath(self.tmp))
        return prune(out)

    def writes(self) -> tuple[str, ...] | bool:
        """Everything writable. The discard device is always included."""
        if self.write is True:
            return True
        out = list(_items(self.write))
        out.extend(item for item in _sink() if os.path.exists(item))
        if isinstance(self.tmp, str):
            out.append(os.path.abspath(self.tmp))
        if isinstance(self.log, str):
            out.append(os.path.abspath(self.log))
        return prune(out)

    def runs(self) -> tuple[str, ...] | bool:
        """Paths that may be executed, plus what the loader needs to start them."""
        if self.exec is True:
            return True
        if not self.exec:
            return False
        return prune(list(self.exec) + list(loader()))

    def keep(self, source: Mapping[str, str] | None = None) -> dict[str, str]:
        """The environment the agent should be left with.

        API keys sitting in `os.environ` are the first thing an injected agent
        reaches for, so scrubbing to an allowlist is the cheapest high-value
        control available.
        """
        source = os.environ if source is None else source
        if self.env is True:
            return dict(source)
        allow = set(SAFE)
        if isinstance(self.env, tuple):
            allow.update(self.env)
        return {key: value for key, value in source.items() if key in allow}

    def with_(self, **edits: object) -> "Policy":
        """A copy with fields replaced. The original is untouched."""
        return replace(self, **edits)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------

# Presets are callables, not constants, because several of them depend on the
# working directory, which is not known at import time.
presets: dict[str, Callable[[], Policy]] = {}


def register(name: str, make: Callable[[], Policy]) -> None:
    """Add a preset. Adding one is a drop-in; nothing else needs to change."""
    if not name or not isinstance(name, str):
        raise Invalid(f"preset name must be a non-empty string, got {name!r}.")
    presets[name] = make


def preset(name: str) -> Policy:
    """Look up a preset by name."""
    try:
        make = presets[name]
    except KeyError:
        known = ", ".join(sorted(presets))
        raise Invalid(f"unknown preset {name!r}. Known presets: {known}.") from None
    return make()


register("strict", lambda: Policy(tmp=False))
register("coder", lambda: Policy(read=[os.getcwd()], write=[os.getcwd()], exec=True))
register("web", lambda: Policy(net=True))
register("data", lambda: Policy(read=[os.getcwd()], write=[os.getcwd()]))
# `debug` deliberately confines almost nothing. It exists to answer "what does
# my agent actually touch?" before a real policy is written, and is the one
# preset that must never be mistaken for protection.
register("debug", lambda: Policy(read=True, write=True, exec=True, net=True, env=True))
