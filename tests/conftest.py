"""Shared machinery for tests that actually apply confinement.

Confinement is one-way, so nothing may be applied in the test process itself:
a single `load()` would confine the whole run, and a KILL action would take
pytest down with it. Every such test therefore runs in a fresh interpreter and
is judged by how that interpreter died.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

SYS = 31  # SIGSYS, raised when seccomp kills a process for a refused syscall

# `landlock.load` raises exactly these two messages when the running kernel's
# own ABI is below what it asked for -- never for a genuine escape, since an
# escape means the seal *succeeded* and something got past it. Matched on the
# message body alone, not a traceback prefix: a bare `python -c` body raises it
# as `hlyn.error.Failed: <message>`, while `hlyn run`/`hlyn.on()` through the
# CLI catch it and print a plain `hlyn: <message>` sentence instead. Both need
# to be recognised, from every test file that spawns either shape of process.
#
# Found on real hardware below hlyn's floor (ABI 4): every confinement test
# failed with a message like "the home directory was readable", which was a
# lie -- the read was never attempted, because sealing itself was refused
# first. A test that cannot tell "this kernel cannot be tested" from "the
# boundary broke" is not trustworthy on exactly the machines most likely to
# hit the first case.
TOO_OLD = re.compile(
    r"(?:the kernel enforced only part of this policy|"
    r"this kernel applied no Landlock restrictions at all)[^\n]*"
)


def skip_if_too_old(done: subprocess.CompletedProcess) -> None:
    """Skip, rather than fail, when `done` shows this kernel refused to seal
    at all -- see `TOO_OLD`. Every helper that runs hlyn in a subprocess
    calls this before handing `done` to the test's own assertions."""
    found = TOO_OLD.search(done.stderr)
    if found:
        pytest.skip(f"this kernel cannot fully seal (see `hlyn probe`): {found.group()}")


def enforces() -> bool:
    """True if this exact machine can apply a full seal right now.

    The same fact `hlyn probe` reports, read straight from the real backend
    rather than reimplemented, so it can never quietly drift out of step with
    the thing it is meant to describe. A real backend being *present* is not
    the same question: on Linux, ABI 1-5 has genuine Landlock and still
    refuses every seal, since `landlock.load` always asks for ABI 6's signal
    and abstract-socket scoping. Tests that assert hlyn *succeeds* -- as
    opposed to tests of the refusal path itself -- gate on this, not merely on
    the platform, because every environment this suite had ever run on before
    happened to clear the floor, which hid the difference until real hardware
    below it did not.
    """
    if sys.platform not in ("linux", "darwin"):
        return False
    from hlyn.jail import back

    return bool(back().probe().get("enforce"))


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
    for fault in ("SyntaxError", "IndentationError", "ModuleNotFoundError", "NameError"):
        if fault in done.stderr:
            raise AssertionError(f"the test body is broken, not the sandbox:\n{done.stderr}")
    skip_if_too_old(done)
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
    for fault in ("SyntaxError", "IndentationError", "ModuleNotFoundError", "NameError"):
        if fault in done.stderr:
            raise AssertionError(f"the test body is broken, not the sandbox:\n{done.stderr}")
    skip_if_too_old(done)
    return done


def killed(done: subprocess.CompletedProcess) -> bool:
    """True if the kernel killed the process for attempting a refused syscall."""
    return done.returncode == -SYS
