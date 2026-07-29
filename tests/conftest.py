"""Shared machinery for tests that actually apply confinement.

Confinement is one-way, so nothing may be applied in the test process itself:
a single `load()` would confine the whole run, and a KILL action would take
pytest down with it. Every such test therefore runs in a fresh interpreter and
is judged by how that interpreter died.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

SYS = 31  # SIGSYS, raised when seccomp kills a process for a refused syscall


def jail(
    body: str,
    policy: str = "Policy()",
    before: str = "",
    seal: str = "seccomp.load",
) -> subprocess.CompletedProcess:
    """Run `body` in a new interpreter, confined by `policy`.

    `before` runs while still unconfined, which is where a test resolves
    syscall numbers or stages files it will later try to reach.
    """
    src = "\n".join(
        [
            "import sys",
            f"sys.path.insert(0, {SRC!r})",
            "from hlyn.policy import Policy",
            "from hlyn.core import landlock, seccomp",
            "from hlyn.core import landlock" if sys.platform == "linux" else "",
            "from hlyn.core import mac" if sys.platform == "darwin" else "",
            textwrap.dedent(before),
            f"{seal}({policy})",
            textwrap.dedent(body),
        ]
    )
    done = subprocess.run(
        [sys.executable, "-c", src],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    # A test whose body never compiled proves nothing, but it exits non-zero
    # and so reads exactly like a successfully blocked escape. Fail loudly
    # instead of letting a broken test masquerade as a passing one.
    for fault in ("SyntaxError", "IndentationError", "ModuleNotFoundError"):
        if fault in done.stderr:
            raise AssertionError(f"the test body is broken, not the sandbox:\n{done.stderr}")
    return done


def boot(code: str) -> subprocess.CompletedProcess:
    """Run `code` in a new interpreter that can import the package.

    Nothing is confined up front, so the code under test decides when and how
    to seal itself. Used for the public entry points, which do their own
    policy resolution.
    """
    src = "\n".join(["import sys", f"sys.path.insert(0, {SRC!r})", textwrap.dedent(code)])
    done = subprocess.run(
        [sys.executable, "-c", src],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    for fault in ("SyntaxError", "IndentationError", "ModuleNotFoundError"):
        if fault in done.stderr:
            raise AssertionError(f"the test body is broken, not the sandbox:\n{done.stderr}")
    return done


def killed(done: subprocess.CompletedProcess) -> bool:
    """True if the kernel killed the process for attempting a refused syscall."""
    return done.returncode == -SYS
