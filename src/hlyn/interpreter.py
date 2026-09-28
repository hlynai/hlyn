# SPDX-License-Identifier: Apache-2.0
"""Running a Python other than the one hlyn runs on.

`policy.runtime()` grants the files *hlyn's own* interpreter needs. `hlyn run
-- python agent.py` often names a different one: hlyn installed with pipx and
the agent in a project venv, or Homebrew's 3.12 beside a python.org 3.14, or
Apple's `/usr/bin/python3`. That interpreter's standard library, packages and
shared library were never granted, and it dies before running a line --
Homebrew's aborts outright.

So before sealing, the command's interpreter is asked where its files are, and
those are granted for reading. Asking means running it, and it is run
**confined**: it may read, but not write, not reach the network, and not keep
any secret from the environment. Its answer is then checked before anything is
granted -- only absolute paths that exist, never `/`, a top-level folder, the
home folder, anything above the working directory, or a credential -- so even
an interpreter that lies can widen the policy only to more interpreter-shaped
folders.

Launchers are followed. Apple's `/usr/bin/python3`, pyenv's and asdf's shims
are small programs that start the real interpreter somewhere else; the answer
names it, and that is what gets run, so the grants match what actually runs.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import select
import shutil
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass

from .policy import Policy, companion, under
from .secret import credential

__all__ = ["Answer", "ask", "env_command", "env_program", "runs", "sane", "script", "shebang"]

# Interpreter names: python, python3, python3.12, python3.13t, pypy3.10.
NAME = re.compile(r"^(python|pypy)(\d+(\.\d+)*)?t?$")

# What the interpreter is asked. -I -S: no site, no .pth files, no user
# environment, so nothing from the project runs; only the interpreter itself.
QUESTION = (
    "import json,sys,sysconfig;p=sysconfig.get_paths();v=sysconfig.get_config_var;"
    "print(json.dumps({'exe':sys.executable,'paths':[sys.prefix,sys.base_prefix,sys.exec_prefix,"
    "sys.base_exec_prefix]+[p.get(k) for k in ('stdlib','platstdlib','purelib','platlib')]"
    "+[v('LIBDIR'),v('LIBPL')]}))"
)

WAIT = 5.0  # seconds; an interpreter starts in well under one
MOST = 1 << 16  # bytes of answer read; a real one is a few hundred

# Folders too broad to grant whole, whatever an interpreter says.
BROAD = frozenset({
    "/", "/usr", "/usr/local", "/usr/lib", "/usr/lib64", "/opt", "/var", "/etc",
    "/home", "/Users", "/Library", "/System", "/private", "/private/var",
    "/tmp", "/private/tmp",  # noqa: S108 - refused as grants, not used as scratch space
    "/Applications",
})


WIDE = BROAD | {os.path.realpath(item) for item in BROAD}


@dataclass(frozen=True)
class Answer:
    """What asking an interpreter found out."""

    reads: tuple[str, ...] = ()  # folders to grant for reading
    exe: str | None = None  # the real interpreter, when the command was a launcher


# CPython's options that take a value as the next argument (or attached:
# `-Wignore`). `-c` and `-m` take one too, but end the options: what follows
# belongs to the command or module, and no script file is run.
VALUED = frozenset("WX")
LONG_VALUED = frozenset({"--check-hash-based-pycs"})


def script(argv: Sequence[str]) -> str | None:
    """The script a Python command line runs, as written: its first argument
    that isn't an option. None for `-c`, `-m`, `-` (standard input) or no
    script at all (the interactive prompt)."""
    args = list(argv[1:])
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if arg == "-":
            return None
        if not arg.startswith("-"):
            return arg
        if arg.startswith("--"):
            i += 2 if arg in LONG_VALUED else 1
            continue
        for j, letter in enumerate(arg[1:]):
            if letter in "cm":
                return None
            if letter in VALUED:
                if j == len(arg) - 2:  # the value is the next argument
                    i += 1
                break
        i += 1
    return None


def runs(argv: Sequence[str]) -> str | None:
    """The file to grant for reading so a Python command line can run its
    script: the script's real path, if it is an existing regular file that
    isn't a credential. Only that file -- never a folder, which would grant
    everything in it, and never anything else on the line."""
    named = script(argv)
    if not named:
        return None
    real = os.path.realpath(os.path.join(os.getcwd(), named))
    if not os.path.isfile(real) or credential(real):
        return None
    return real


def shebang(path: str) -> tuple[str, list[str]] | None:
    """A script's first line: the interpreter it names (an absolute path) and
    what follows it on the line, as one argument, the way Linux passes it.
    None when `path` isn't a script that names one."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    text = head[2:].split(b"\n", 1)[0].rstrip(b"\r").decode(errors="surrogateescape").strip(" \t")
    parts = text.split(None, 1)
    if not parts or not os.path.isabs(parts[0]):
        return None
    rest = parts[1].strip() if len(parts) > 1 else ""
    return parts[0], [rest] if rest else []


def env_command(args: Sequence[str]) -> list[str] | None:
    """What a `#!/usr/bin/env ARGS` line runs: the program's name and the
    words after it. The program is the first word that is neither `-S` nor a
    NAME=value setting. None when `env` is given any other option (they
    change where or how it finds the program, so it isn't followed) or names
    no program."""
    words = [word for arg in args for word in arg.split()]
    for i, word in enumerate(words):
        if word in ("-S", "--split-string"):
            continue
        if word.startswith("-"):
            return None
        if "=" in word:
            continue
        return words[i:]
    return None


def env_program(args: Sequence[str]) -> str | None:
    """The program a `#!/usr/bin/env ARGS` line starts (`env_command`)."""
    found = env_command(args)
    return found[0] if found else None


def python(cmd0: str, where: str) -> bool:
    """Whether the command looks like a Python interpreter."""
    return bool(NAME.match(os.path.basename(cmd0)) or NAME.match(os.path.basename(where)))


def sane(path: object) -> str | None:
    """`path`, resolved, if it is safe to grant for reading; otherwise None."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    real = os.path.realpath(path)
    # Compared resolved on both sides: on macOS /etc is /private/etc.
    if not os.path.exists(real) or real in WIDE or real.count(os.sep) < 2:
        return None
    home = os.path.realpath(os.path.expanduser("~"))
    here = os.path.realpath(os.getcwd())
    if under(home, real) or under(here, real):
        return None  # the home folder, the working folder, or above either
    if credential(real):
        return None
    return real


def ask(cmd0: str, where: str) -> Answer:
    """Asks the interpreter `cmd0` (whose real path is `where`) about itself, confined.

    Run by the path it is found at, not its real path, for the same reason
    `jail._spawn` does: a virtualenv's python is a link, and only through
    the link does the interpreter know it is in the venv.

    Returns an empty answer for anything that is not a Python, is hlyn's own
    interpreter (already covered), or does not answer properly in time.
    """
    if not python(cmd0, where):
        return Answer()
    found = shutil.which(cmd0)
    if not found:
        return Answer()
    found = os.path.abspath(found)
    # Compared unresolved: a venv's python and its base interpreter are the
    # same file, but different interpreters with different packages.
    if found == os.path.abspath(sys.executable):
        return Answer()

    from . import jail

    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # the interpreter, confined
        try:
            os.close(r)
            null = os.open(os.devnull, os.O_RDWR)
            os.dup2(null, 0)
            os.dup2(w, 1)
            os.dup2(null, 2)
            probe = Policy(read=True, exec=True, net=False, env=False, tmp=False, log=False)
            jail._seal(probe)
            os.execv(found, [found, "-I", "-S", "-c", QUESTION])  # noqa: S606
        finally:
            os._exit(127)

    os.close(w)
    body = b""
    end = time.monotonic() + WAIT
    try:
        while len(body) < MOST:
            left = end - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select([r], [], [], left)
            if not ready:
                break
            chunk = os.read(r, MOST)
            if not chunk:
                break
            body += chunk
    finally:
        os.close(r)
        with contextlib.suppress(OSError):
            os.kill(pid, 9)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(pid, 0)
    return read(body, where)


def read(body: bytes, where: str) -> Answer:
    """The interpreter's answer, checked. Anything malformed means no answer."""
    try:
        data = json.loads(body.decode("utf-8").strip().splitlines()[0])
    except (UnicodeDecodeError, ValueError, IndexError):
        return Answer()
    if not isinstance(data, dict) or not isinstance(data.get("paths"), list):
        return Answer()
    reads = []
    for item in data["paths"][:16]:
        found = sane(item)
        if found and found not in reads:
            reads.append(found)
    exe = data.get("exe")
    if not (isinstance(exe, str) and os.path.isabs(exe)):
        return Answer(tuple(reads))
    exe = os.path.abspath(exe)
    real = os.path.realpath(exe)
    # A different program from the one started: `where` was a launcher. Only
    # followed to an executable file named like an interpreter, so a launcher
    # cannot redirect the run to an arbitrary program. Kept unresolved -- it
    # may be a venv's link, which only works as a link -- and granted by its
    # real path in `grants`.
    if (
        real != where
        and NAME.match(os.path.basename(exe))
        and NAME.match(os.path.basename(real))
        and os.path.isfile(real)
        and os.access(real, os.X_OK)
    ):
        return Answer(tuple(reads), exe)
    return Answer(tuple(reads))


def grants(answer: Answer, plan: Policy, where: str) -> tuple[Policy, str]:
    """`plan` widened by `answer`, and the program to actually run."""
    run = answer.exe or where
    real = os.path.realpath(run)
    if answer.reads and plan.read is not True:
        plan = plan.with_(read=[*(plan.read or ()), *answer.reads])
    if plan.exec is not True:
        grant = list(plan.exec) if isinstance(plan.exec, tuple) else []
        for item in (where, real, companion(real)):
            if item and item not in grant:
                grant.append(item)
        plan = plan.with_(exec=grant)
    return plan, run
