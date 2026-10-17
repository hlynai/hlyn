# SPDX-License-Identifier: Apache-2.0
"""What an agent may read, write, run, and reach.

Deny by default: an empty policy grants nothing except the interpreter's own
files, without which the process cannot survive its next import.

Nothing here touches the kernel. This module decides *intent*; the backends in
`core/` translate intent into enforcement. Keeping the two apart means a policy
can be inspected, diffed, and tested on any machine, including ones that cannot
enforce it.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import site
import sys
import sysconfig
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Literal

from .error import Invalid
from .hosts import Rule
from .hosts import parse as hostparse

__all__ = ["SAFE", "Policy", "preset", "presets", "programs", "register", "runtime"]


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


# Where Linux keeps POSIX semaphores and shared memory (`shm`).
SHM = "/dev/shm"  # noqa: S108 - a grant, not scratch space

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


# Grant fields a `with_` copy carries over as already resolved.
_KEPT: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar("hlyn_kept", default=frozenset())


def real(value: tuple[str, ...] | bool) -> tuple[str, ...] | bool:
    """The same grants by real path: each link resolved to what it names."""
    if isinstance(value, bool):
        return value
    return prune(os.path.realpath(item) for item in value)


def linked(value: object) -> list[tuple[str, str]]:
    """(typed, real) for each typed path that resolves somewhere else through
    a link the user made. The system's own aliases (macOS `/tmp`, `/var`,
    `/etc`; Linux `/bin`, `/lib` and the like) are not counted: they are where
    the OS keeps those folders, not a redirection."""
    out: list[tuple[str, str]] = []
    if isinstance(value, bool) or value is None:
        return out
    for item in [value] if isinstance(value, (str, os.PathLike)) else list(value):  # type: ignore[call-overload]
        typed = os.path.abspath(os.path.expanduser(os.fspath(item)))
        target = os.path.realpath(typed)
        if target != typed and target != _system_alias(typed):
            out.append((os.fspath(item), target))
    return out


# Top-level folders the OS itself makes links: macOS's /tmp, /var and /etc
# (into /private), merged-/usr Linux's /bin, /sbin and /lib*.
ALIASES = frozenset({"/tmp", "/var", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64"})  # noqa: S108


def _system_alias(path: str) -> str:
    """`path` with only the system's own top-level aliases resolved."""
    parts = path.split(os.sep)
    if len(parts) > 1 and parts[1]:
        top = os.sep + parts[1]
        if os.path.islink(top) and top in ALIASES:
            return os.path.join(os.path.realpath(top), *parts[2:])
    return path


def ports(value: object, field: str = "net") -> tuple[int, ...] | tuple[Rule, ...] | bool:
    """Normalise a network option: `True`, `False`, ports, or hosts.

    A list holds either TCP ports (`[443]`) or host entries
    (`["api.openai.com", "localhost:5432"]`; see `hosts.parse` for the
    grammar), never both: a bare port already reaches every host on it, so the
    hosts would restrict nothing. Host entries come back as `hosts.Rule`s in
    canonical form, sorted so equal policies compare equal.

    Named ports are **TCP only**, and this is worth reading twice, because it
    is the one place where naming a port grants more than it appears to.
    Landlock's network rules cover TCP bind and connect; UDP is outside them,
    so `net=[443]` leaves UDP open. Traffic can still leave over DNS or QUIC,
    and a port reaches every host on it. `net=False` blocks the lot. Host
    entries close UDP and every host not listed: the connections go through
    a local proxy, and on Linux a gate process checks each one
    (DESIGN-host-allowlisting.md, section 5).
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, str, os.PathLike, Rule)):
        value = (value,)
    if not isinstance(value, Iterable):
        raise Invalid(
            f"{field}: expected a port, a host, a list of either, or a bool, got {value!r}."
        )

    out: list[int] = []
    named: list[Rule] = []
    for item in value:
        if isinstance(item, bool):
            raise Invalid(f"{field}: expected a port number or a host, got {item!r}.")
        if isinstance(item, Rule):
            named.append(item)
            continue
        text = os.fspath(item) if isinstance(item, os.PathLike) else item
        if isinstance(text, str):
            if not text.isdigit():
                named.append(hostparse(text, field))
                continue
            port = int(text)
        elif isinstance(item, int):
            port = item
        else:
            # Accept anything that converts to a whole number exactly, so a
            # numpy integer or a Decimal works. Refuse anything that would have
            # to be rounded: `int(1.5)` is 1, so accepting it would open a port
            # the caller never named.
            try:
                port = int(item)
            except (TypeError, ValueError):
                raise Invalid(
                    f"{field}: expected a port number or a host, got {item!r} "
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

    if out and named:
        some = ", ".join(str(p) for p in sorted(set(out))[:3])
        host = named[0]
        raise Invalid(
            f"{field} mixes ports ({some}) and hosts ({host}). A bare port reaches every "
            f"host on it, so the hosts would restrict nothing. Use hosts only "
            f"({host.flag()}; port 443 is the default) or ports only (--net {some.split(',')[0]})."
        )
    if named:
        return tuple(sorted(set(named), key=str))
    return tuple(sorted(set(out)))


def plain(value: object) -> object:
    """A field as a file or JSON holds it: tuples as lists, host rules as text."""
    if isinstance(value, tuple):
        return [str(item) if isinstance(item, Rule) else item for item in value]
    return value


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
    except Exception:  # noqa: BLE001 - a broken sysconfig must not stop us confining
        config = {}
    for key in ("stdlib", "platstdlib", "purelib", "platlib", "data"):
        found = config.get(key)
        if found:
            out.add(os.path.abspath(found))
    # A site layout this cannot read must not stop the process being
    # confined; the worst case is a narrower policy, which is the safe way to
    # be wrong.
    with contextlib.suppress(Exception):
        out.update(os.path.abspath(item) for item in site.getsitepackages())
    try:
        user = site.getusersitepackages()
    except Exception:  # noqa: BLE001 - same reason: a narrower policy, not a crash
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
            # The system's time zone data, root-owned. /usr/share/zoneinfo and
            # /etc/localtime both lead here; granting only zoneinfo left ICU's
            # copy beside it (icutz) refused, and Claude Code's runtime (Bun)
            # was killed (SIGKILL, before its first request) without it.
            "/private/var/db/timezone",
            "/System/Library",
            "/private/var/db/dyld",
            # The whole cryptex volume, not just OS/: dyld probes Rosetta's
            # cryptex on every launch, arm64 or not. System binaries, sealed.
            "/System/Volumes/Preboot/Cryptexes",
            # Locale data every process's C library reads at startup, and the
            # file telling the logging system which messages to keep. Both
            # found by listing what a bare `python3 -c pass` was refused.
            "/usr/share/locale",
            "/Library/Preferences/Logging",
            # Homebrew's installed software, which Homebrew's Pythons link
            # against (OpenSSL, SQLite, libffi...). Packages only: Cellar holds
            # no configuration or data -- those live in etc/ and var/, which
            # stay closed. Skipped where Homebrew is not installed.
            "/opt/homebrew/Cellar",
            "/usr/local/Cellar",
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
    out: tuple[str, ...] = ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full")
    if sys.platform == "darwin":
        # Opened by macOS path lookup to avoid triggering automounts. Reading
        # it yields nothing; being refused it makes every launch log a denial.
        out += ("/dev/autofs_nowait",)
    return out


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
        #
        # Both prefixes: inside a virtualenv, `sys.prefix` is the venv and
        # only `sys.base_prefix` is the framework that holds Resources/.
        for prefix in {sys.prefix, sys.base_prefix}:
            inner = os.path.join(prefix, "Resources")
            if os.path.exists(inner):
                out.add(inner)
    return prune(out)


def companion(program: str) -> str | None:
    """A second program that `program` needs to run, or None.

    macOS's `/bin/sh` runs the shell the system selects. And macOS framework
    Python again (see `loader`): `.../Versions/X.Y/bin/pythonX.Y`
    re-execs `.../Versions/X.Y/Resources/Python.app`. `loader` covers the
    interpreter hlyn itself runs on; this covers the one a command names,
    which can be a different installation entirely.
    """
    if sys.platform != "darwin":
        return None
    real = os.path.realpath(program)
    if real == "/bin/sh":
        # A stub that runs the shell /private/var/select/sh points at (bash
        # unless the machine was changed), and fails if it may not.
        shell = os.path.realpath("/private/var/select/sh")
        return shell if os.path.isfile(shell) and shell != real else None
    version, sep, _ = real.partition("/bin/")  # .../Python.framework/Versions/X.Y
    frame = os.path.dirname(version).rsplit("/", 2)[-2:]
    # Python.framework from python.org and Homebrew; Python3.framework from
    # Apple's Command Line Tools.
    if not sep or frame not in (["Python.framework", "Versions"], ["Python3.framework", "Versions"]):
        return None
    inner = os.path.join(version, "Resources", "Python.app")
    return inner if os.path.isdir(inner) else None


def programs() -> tuple[str, ...]:
    """Where programs live, for `exec=True` to be able to run any of them.

    A program has to be readable to be executed -- the kernel reads the ELF,
    and `execve` returns `EACCES` without it. For named grants that costs
    nothing, because `reads()` already adds every path in `exec`. For
    `exec=True` there are no named paths to add, so this is the set.

    It is these directories rather than `/` on purpose, and that distinction is
    the whole fix for a real hole: granting read over `/` to make `exec=True`
    work is what silently made every `read` list meaningless. The system's
    program directories are not where secrets are. `/etc/shadow`, `~/.ssh` and
    `/root` stay refused, which is the point.
    """
    out = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/libexec",
        "/usr/local/bin",
        "/usr/local/sbin",
        *loader(),
    }
    return prune(item for item in out if os.path.exists(item))


def runtime() -> tuple[str, ...]:
    """Paths the interpreter must read to survive deny-by-default.

    Computed from the live interpreter, never hardcoded, so this is correct
    inside a virtualenv, a container, a Homebrew prefix, or a framework build.

    Deliberately excluded:

    `/proc` — `/proc/self/environ` exposes the environment block captured at
    exec time, which does *not* change when `os.environ` is scrubbed. Granting
    `/proc/self` would hand back every secret the `env` control just removed.

    That exclusion has a cost worth knowing about before it bites: **GPU
    workloads need `/proc` writable**. CUDA writes thread names to
    `/proc/<pid>/task/<tid>/comm`, so a sealed process doing local inference or
    training fails in a way that points nowhere near this file. The fix is to
    say so in the policy, `Policy(write=["/proc"])`, and the price is that
    `/proc/self/environ` becomes readable again — so scrub the environment at
    the source rather than relying on `env` alone if you take that route.

    The working directory and the running script's directory — that is the
    user's data, not the runtime's. A policy that silently read it would make
    `hlyn.on()` far more permissive than it looks.
    """
    out: set[str] = set(_roots())

    # Import-path entries that belong to the interpreter. Entries outside these
    # roots are the user's own code and are not granted here.
    for entry in sys.path:
        if not entry or not os.path.isabs(entry):
            continue
        item = os.path.abspath(entry)
        if any(under(item, root) for root in out):
            out.add(item)

    if sys.executable:
        out.add(os.path.abspath(sys.executable))
    out.update(_lib())
    out.update(_dev())
    out.update(item for item in (*SSLCONF, *RELEASE) if os.path.isfile(item))
    if sys.platform == "darwin":
        # CoreFoundation reads this one-line encoding preference in every
        # process that uses it. The file itself only, not the home directory.
        out.add(os.path.expanduser("~/.CFUserTextEncoding"))

    return prune(item for item in out if os.path.exists(item))


# Name lookup: the resolver's configuration, the hosts file, and the tables
# `getaddrinfo` consults to turn "https" into 443.
LOOKUP: tuple[str, ...] = (
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
)

# Certificate authorities, as each distribution lays them out. Named narrowly:
# `/etc/ssl` and `/etc/pki/tls` also hold `private/`, where keys live.
TRUST: tuple[str, ...] = (
    "/etc/ssl/certs",                   # Debian, Ubuntu, Alpine, Arch
    "/etc/ssl/cert.pem",                # Alpine, macOS, BSD-style layouts
    "/etc/ssl/ca-bundle.pem",           # SUSE
    "/etc/pki/tls/certs",               # Fedora, RHEL
    "/etc/pki/tls/cert.pem",
    "/etc/pki/ca-trust",                # Fedora, RHEL: where the above point
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",       # Debian: where /etc/ssl/certs points
    "/usr/local/share/ca-certificates",
    "/var/lib/ca-certificates",         # SUSE
    # Homebrew's bundle, which its OpenSSL's cert.pem points at, for programs
    # linked against Homebrew's OpenSSL rather than the system's.
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl@3/certs",
    "/usr/local/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/certs",
)

# Which OS and version this is. Public, and read by programs as they start:
# pip's user agent reads /etc/debian_version through `distro` and stops if
# the file exists but can't be read; installers and `platform` read
# os-release. Granted whatever the policy, the files only.
RELEASE: tuple[str, ...] = (
    "/etc/os-release", "/usr/lib/os-release",
    "/etc/lsb-release", "/etc/debian_version", "/etc/redhat-release", "/etc/fedora-release",
    "/etc/centos-release", "/etc/system-release", "/etc/SuSE-release", "/etc/alpine-release",
    "/etc/arch-release", "/etc/gentoo-release",
)

# OpenSSL's configuration files. A program linked against OpenSSL (or
# LibreSSL) reads its one when it starts, network or not, and some won't start
# if it exists but can't be read: Homebrew's Node exits with "OpenSSL
# configuration error". Public configuration, granted whatever the policy;
# the files only, since the folders that hold them also hold `private/`.
SSLCONF: tuple[str, ...] = (
    "/etc/ssl/openssl.cnf",                               # Debian, Ubuntu, Alpine, macOS
    "/etc/pki/tls/openssl.cnf",                           # Fedora, RHEL
    "/usr/lib/ssl/openssl.cnf",                           # Debian's OPENSSLDIR, a link to the first
    "/opt/homebrew/etc/openssl@3/openssl.cnf",            # Homebrew, Apple silicon
    "/opt/homebrew/etc/openssl@1.1/openssl.cnf",
    "/usr/local/etc/openssl@3/openssl.cnf",               # Homebrew, Intel
    "/usr/local/etc/openssl@1.1/openssl.cnf",
)

# Linuxbrew's, on Linux only. On macOS `/home` is an automount point, and
# looking for a file under it asks automountd: 15-25 ms per path, which made
# `on()` with a port 50 ms slower (measured 2026-09-28).
if sys.platform == "linux":
    TRUST += (
        "/home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem",
        "/home/linuxbrew/.linuxbrew/etc/openssl@3/cert.pem",
    )
    SSLCONF += ("/home/linuxbrew/.linuxbrew/etc/openssl@3/openssl.cnf",)


def network() -> tuple[str, ...]:
    """Files a program reads to use the network at all: name lookup and TLS trust.

    Granted whenever `net` is not False. Without them a policy that allows
    port 443 still cannot make an HTTPS request: the resolver cannot read
    `/etc/resolv.conf` and reports a *name resolution* failure, and no
    certificate authority loads, so every handshake fails verification. Neither
    error mentions a path, which is what makes this worth granting by default.

    Everything here is public system configuration. The interpreter's own
    OpenSSL is asked where it looks, so a Homebrew, conda or custom build is
    covered as well as the distribution's.
    """
    import ssl

    out: set[str] = {*LOOKUP, *TRUST}
    # The interpreter's own compiled-in locations, checked to hold only
    # certificates. Never `SSL_CERT_FILE`/`SSL_CERT_DIR` (nor the `cafile` and
    # `capath` answers, which are those two variables): the environment can
    # point them anywhere (`SSL_CERT_DIR=~/.ssh`), and a folder that was clean
    # when checked can change before the agent reads it. `trust_copy` hands the
    # agent a private copy of what they name instead.
    named: set[str] = set()
    with contextlib.suppress(Exception):
        found = ssl.get_default_verify_paths()
        named.update(item for item in (found.openssl_cafile, found.openssl_capath) if item)
    out.update(item for item in named if _certs(item))
    return prune(os.path.abspath(item) for item in out if os.path.exists(item))


def scratch(path: str) -> str:
    """Make sure a caller-named `tmp` folder is fit to be the agent's scratch
    space, creating it if missing; return its real path.

    `tmp` is a read and write grant the agent gets whole, and hlyn writes
    files into it (the certificate copy, the blocked list). So it must be a
    folder this user owns that no one else can write (a shared folder could
    hold names planted for hlyn to write through), and not the home folder, a
    folder above it, `/`, or a place keys live. Checked on the folder opened,
    not on its name.
    """
    from .secret import credential

    typed = os.path.abspath(os.path.expanduser(path))
    with contextlib.suppress(FileExistsError):
        os.mkdir(typed, 0o700)
    folder = os.open(typed, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    try:
        info = os.fstat(folder)
    finally:
        os.close(folder)
    real = os.path.realpath(typed)
    home = os.path.realpath(os.path.expanduser("~"))
    why = ""
    if info.st_uid != os.getuid():
        why = "it belongs to another user"
    elif info.st_mode & 0o022:
        why = "other users can write it, so names in it could be planted for hlyn to write through"
    elif real == os.sep or under(home, real):
        why = "it is your home folder or holds it"
    elif credential(real):
        why = "keys or tokens live there"
    if why:
        raise Invalid(
            f"tmp: {path} can't be the agent's scratch folder: {why}. Name a new folder of your own "
            f"(hlyn creates it), or leave tmp unset for a fresh private one."
        )
    return real


def trusted(path: str) -> bool:
    """True if `path` is inside one of the system's own trust stores."""
    real = os.path.realpath(path)
    return any(under(real, os.path.realpath(root)) for root in TRUST)


def trust_copy(env: dict[str, str], box: str | None) -> dict[str, str]:
    """`env` with `SSL_CERT_FILE`/`SSL_CERT_DIR` pointed at a private copy.

    A custom trust store (a corporate proxy's CA) has to keep working, but the
    folder it names is the user's: granting it would hand the agent whatever is
    in it, and whatever is put in it later, through a symlink swap, a new file
    or a race with the check. So it is never granted. Each named file is read
    once, checked to hold only certificates or revocation lists, and those
    same bytes are written into the agent's private scratch folder; the
    variable then names the copy. What the agent reads is exactly what was
    checked. Paths inside the system's own stores are left alone (already
    granted). Raises `Invalid` with what to change when a location holds
    anything else. With no scratch folder (`tmp=False`) the variable is
    dropped instead, so the system's authorities are used.
    """
    out = dict(env)
    for name, kind in (("SSL_CERT_FILE", "file"), ("SSL_CERT_DIR", "dir")):
        value = env.get(name)
        if not value:
            continue
        items = [item for item in value.split(os.pathsep) if item]
        if all(trusted(item) for item in items):
            continue
        if box is None:
            # No scratch folder to copy into (`tmp=False`, or hlyn's own proxy
            # sealing itself): drop the variable. Nothing is granted, and the
            # program falls back to the system's certificate authorities.
            del out[name]
            continue
        copies: list[tuple[str, bytes]] = []
        for item in items:
            copies.extend(_cert_copies(name, item))
        if kind == "file":
            target = os.path.join(box, "hlyn-certs.pem")
            _write(target, b"".join(data for _, data in copies))
            out[name] = target
        else:
            target = os.path.join(box, "hlyn-certs")
            try:
                os.mkdir(target, 0o700)  # new, not a planted folder or link
            except FileExistsError:
                raise Invalid(
                    f"tmp: {target} already exists, so hlyn won't put the certificate copies there. "
                    f"Give the agent a new, empty scratch folder (or leave tmp unset)."
                ) from None
            for base, data in copies:
                _write(os.path.join(target, base), data)
            out[name] = target
    return out


def _cert_copies(name: str, item: str) -> list[tuple[str, bytes]]:
    """The checked contents of one `SSL_CERT_*` entry, as (file name, bytes)."""
    real = os.path.realpath(item)
    if os.path.isfile(real):
        files = [(os.path.basename(item), real)]
    elif os.path.isdir(real):
        try:
            entries = sorted(os.scandir(real), key=lambda entry: entry.name)
        except OSError as error:
            raise Invalid(f"{name}: {item} can't be read ({error.strerror}).") from None
        if len(entries) > CERT_FILES:
            raise Invalid(
                f"{name}: {item} holds more than {CERT_FILES} entries; point it at certificates only."
            )
        files = []
        for entry in entries:
            if not entry.is_file():  # a folder, a dangling link, a socket
                raise Invalid(
                    f"{name}: {item} holds {entry.name}, which is not a certificate file. "
                    f"Point {name} at a folder of certificates only, or unset it."
                )
            files.append((entry.name, entry.path))
    else:
        raise Invalid(f"{name}: {item} does not exist. Fix the path, or unset {name}.")
    out: list[tuple[str, bytes]] = []
    for base, path in files:
        data = _cert_bytes(path)
        if data is None:
            raise Invalid(
                f"{name}: {path} holds something besides certificates (a key, text outside the "
                f"BEGIN/END blocks, or a damaged block). hlyn won't hand it to the agent. Point {name} at "
                f"certificates only, or unset it."
            )
        out.append((base, data))
    return out


def _cert_bytes(path: str) -> bytes | None:
    """The certificates and revocation lists in the file, read once and rebuilt
    from what was parsed; None if it holds anything else.

    Only the blocks themselves reach the copy, re-encoded from their decoded
    bytes, never the text around them: a bundle with a certificate and then
    `TOKEN=...` gives a copy with the certificate alone. Each block must be a
    known label, matched at both ends, with a body that is base64 and decodes
    to DER (a SEQUENCE); a key, an encrypted block or a damaged one refuses the
    whole file. Text between blocks (comments, OpenSSL's "explanatory text",
    which macOS's own bundle has) is dropped.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read(CERT_BYTES + 1)
    except OSError:
        return None
    if len(data) > CERT_BYTES:
        return None
    return pem_blocks(data)


def pem_blocks(data: bytes, strict: bool = False) -> bytes | None:
    """`data` rebuilt from its certificate and CRL blocks alone, or None if a
    block is anything else (see `_cert_bytes`). `strict` also refuses text
    between blocks other than `#` comments and blank lines: for a file granted
    as it is rather than copied, where that text would be readable."""
    import base64
    import binascii

    out: list[bytes] = []
    label: bytes | None = None
    body: list[bytes] = []
    for raw in data.splitlines():
        line = raw.strip()
        if label is None:
            if not (line.startswith(b"-----BEGIN ") and line.endswith(b"-----")):
                if line.startswith(b"-----") or (strict and line and not line.startswith(b"#")):
                    return None
                continue
            label = line[len(b"-----BEGIN "):-len(b"-----")]
            if label not in CERT_LABELS:
                return None
            body = []
            continue
        if line == b"-----END " + label + b"-----":
            try:
                der = base64.b64decode(b"".join(body), validate=True)
            except (binascii.Error, ValueError):
                return None
            if len(der) < 2 or der[0] != 0x30:  # DER: a SEQUENCE
                return None
            encoded = base64.encodebytes(der).replace(b"\n", b"")
            lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
            out.append(b"-----BEGIN " + label + b"-----\n" + b"\n".join(lines)
                       + b"\n-----END " + label + b"-----\n")
            label = None
            continue
        if not line or line.startswith(b"-----") or b":" in line:  # headers mean encryption
            return None
        body.append(line)
    if label is not None or not out:
        return None
    return b"".join(out)


def _write(path: str, data: bytes) -> None:
    """Write a new file only this user can read. Never through a link, and never
    into a file that already exists: `O_EXCL` refuses both, so a planted name
    (a link, or a hard link to a file elsewhere) can't be truncated."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Invalid(
            f"tmp: {path} already exists, so hlyn won't write the certificate copy there. "
            f"Give the agent a new, empty scratch folder (or leave tmp unset)."
        ) from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# A certificate file is small; a folder of them a few hundred files.
CERT_BYTES = 4 << 20
CERT_FILES = 2000
CERT_LABELS = frozenset({b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CRL"})


def _cert_file(path: str) -> bool:
    """True if `path` is a PEM file of certificates or revocation lists only,
    comments aside: it is granted as it is, so nothing else may be in it."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(CERT_BYTES + 1)
    except OSError:
        return False
    return len(data) <= CERT_BYTES and pem_blocks(data, strict=True) is not None


def _certs(path: str) -> bool:
    """True if `path` may be granted as a trust store: inside a known one, a
    certificate file, or a folder holding only certificate files (OpenSSL's
    hashed links included, and the revocation lists beside them)."""
    real = os.path.realpath(path)
    if any(under(real, os.path.realpath(root)) for root in TRUST):
        return True
    if os.path.isfile(real):
        return _cert_file(real)
    if not os.path.isdir(real):
        return False
    try:
        entries = list(os.scandir(real))
    except OSError:
        return False
    if not entries or len(entries) > CERT_FILES:
        return False
    for entry in entries:
        if not entry.is_file():  # a subfolder would be granted with it
            return False
        if not _cert_file(entry.path):
            return False
    return True


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
        Policy(net=["api.openai.com"])              # one host, over HTTPS
        Policy(net=[443], exec=False)               # a port: every host on it

    Frozen on purpose. A policy that can be edited after it has been checked
    is a policy that can be edited by whatever compromised the agent.

    One caveat, stated here because it is the only field that grants more than
    it reads: naming *ports* in `net` restricts **TCP only**, and reaches every
    host on them. UDP stays open, so traffic can still leave over DNS or QUIC.
    Naming hosts closes both; `net=False` closes everything. See `ports`.
    """

    read: tuple[str, ...] | bool = ()
    write: tuple[str, ...] | bool = ()
    exec: tuple[str, ...] | bool = False
    net: tuple[int, ...] | tuple[Rule, ...] | bool = False
    env: tuple[str, ...] | bool = False
    tmp: bool | str = True
    log: bool | str = True
    shm: bool = False

    def __post_init__(self) -> None:
        put = object.__setattr__  # frozen dataclass, so assign through the base
        # Every path grant is stored by real path: the kernel grants what a link
        # points at (Landlock opens it, Seatbelt resolves it), so the policy,
        # `hlyn show` and the seal record name that, not the link. `linked` lists
        # the ones that were links, for the CLI to say so; `jail._unchanged`
        # checks them again just before the seal.
        kept = _KEPT.get()
        for field in ("read", "write", "exec"):
            value = paths(getattr(self, field), field)
            put(self, field, value if field in kept else real(value))
        put(self, "net", ports(self.net))
        put(self, "env", names(self.env))
        if not isinstance(self.tmp, (bool, str)):
            raise Invalid(f"tmp: expected a bool or a directory, got {self.tmp!r}.")
        if isinstance(self.tmp, str):
            # A read and write grant like any other: by real path.
            typed = _one(self.tmp, "tmp")
            put(self, "tmp", typed if "tmp" in kept else os.path.realpath(typed))
        if not isinstance(self.log, (bool, str)):
            raise Invalid(f"log: expected a bool or a file path, got {self.log!r}.")
        if not isinstance(self.shm, bool):
            raise Invalid(f"shm: expected true or false, got {self.shm!r}.")
        if isinstance(self.log, str):
            self._record_out_of_reach(self.log)

    def _record_out_of_reach(self, where: str) -> None:
        """Refuse a log inside a folder the agent can write.

        The descriptor hlyn writes through survives the seal, but the name does
        not: an agent that can write the folder can unlink the file (hlyn keeps
        writing to the unlinked one), rename it, or put its own file or a link
        at that path, and whoever opens the path later reads the forgery. So the
        folder must be outside every grant.
        """
        path = os.path.abspath(os.path.expanduser(where))
        # The file itself, not only its folder: a link (or a second name, a
        # hard link) can put the record inside a writable grant while its
        # folder is outside. `log.record` checks the opened file again.
        if os.path.islink(path):
            raise Invalid(
                f"log: {where} is a link (to {os.path.realpath(path)}). hlyn writes the record "
                f"only to a plain file, so it can't be redirected. Name a file, not a link."
            )
        with contextlib.suppress(OSError):
            if os.stat(path).st_nlink > 1:
                raise Invalid(
                    f"log: {where} has another name (a hard link), and the agent could write it "
                    f"through that one. Use a new file."
                )
        folder = os.path.realpath(os.path.dirname(path))
        granted = self.writes()
        if granted is True:
            root = "every folder (write=True)"
        else:
            root = next((item for item in granted if under(folder, os.path.realpath(item))), "")
        if root:
            raise Invalid(
                f"log: {where} is inside {root}, which the agent can write: it could delete the "
                f"record and leave a forged one in its place. Put the log outside every --write folder."
            )

    # -- derived views ------------------------------------------------------
    #
    # The four dimensions stay independent: granting write everywhere does not
    # quietly grant read everywhere. Only explicitly named paths cross over,
    # because a caller who writes `write=["/out"]` expects to read back what
    # they wrote, and a named executable has to be readable to be run.

    def reads(self) -> tuple[str, ...] | Literal[True]:
        """Everything readable, including the interpreter's own files."""
        if self.read is True:
            return True
        out = list(runtime())
        out.extend(_items(self.read))
        out.extend(_items(self.write))
        out.extend(_items(self.exec))
        # `exec=True` names nothing, so nothing above makes a program readable,
        # and a program that cannot be read cannot be executed. The program
        # directories are added rather than `/`; see `programs`.
        if self.exec is True:
            out.extend(programs())
        if self.net is not False:
            out.extend(network())
        if isinstance(self.tmp, str):
            out.append(os.path.abspath(self.tmp))
        if self.shm and os.path.isdir(SHM):
            out.append(SHM)
        return prune(out)

    def writes(self) -> tuple[str, ...] | Literal[True]:
        """Everything writable. The discard device is always included.

        The log file is deliberately **not** here. It is opened before the seal
        and the descriptor survives it, so writing the record needs no grant --
        and granting it would hand the agent write access to the record of
        what it did, which defeats the point of keeping the record at all.
        """
        if self.write is True:
            return True
        out = list(_items(self.write))
        out.extend(item for item in _sink() if os.path.exists(item))
        if isinstance(self.tmp, str):
            out.append(os.path.abspath(self.tmp))
        if self.shm and os.path.isdir(SHM):
            # POSIX semaphores and shared memory are files here on Linux
            # (macOS has no such folder: mac.py allows the operations instead).
            # Granting the folder also exposes every other program's segment
            # in it, which is why `shm` is off unless asked for.
            out.append(SHM)
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

    def hosts(self) -> tuple[Rule, ...]:
        """The host entries `net` names, or `()` when it is off, open, or ports."""
        if isinstance(self.net, tuple) and self.net and isinstance(self.net[0], Rule):
            return self.net
        return ()

    def with_(self, **edits: object) -> Policy:
        """A copy with fields replaced. The original is untouched.

        Grants not being replaced keep the real paths they were resolved to
        when this policy was built: resolving them again here would follow a
        link swapped in since, and `jail._unchanged` could then no longer see
        that the folder shown is not the folder about to be sealed.
        """
        token = _KEPT.set(frozenset({"read", "write", "exec", "tmp"}) - set(edits))
        try:
            return replace(self, **edits)  # type: ignore[arg-type]
        finally:
            _KEPT.reset(token)


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
register("coder", lambda: Policy(read=(os.getcwd(),), write=(os.getcwd(),), exec=True))
register("web", lambda: Policy(net=True))
register("data", lambda: Policy(read=(os.getcwd(),), write=(os.getcwd(),)))
# `debug` deliberately confines almost nothing. It exists to answer "what does
# my agent actually touch?" before a real policy is written, and is the one
# preset that must never be mistaken for protection.
register("debug", lambda: Policy(read=True, write=True, exec=True, net=True, env=True))
