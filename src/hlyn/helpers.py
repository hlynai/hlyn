"""Starting hlyn's helper processes (DESIGN-host-allowlisting.md 5.1).

A policy that names hosts runs two small helpers beside the agent: the proxy
(`proxy.py`) and the gate (`gate.py`). Each is a fresh interpreter, never a
bare fork of the caller, so nothing the caller's other threads were holding
at the moment of `fork` can deadlock it.

Which interpreter follows `multiprocessing`'s spawn start method, the
standard answer to the same question: `multiprocessing.spawn.get_executable()`,
so `multiprocessing.set_executable()` changes it too. It runs isolated
(`-I -S`: no environment variables, no user site, no `.pth` files), with
hlyn's own directory put on `sys.path` explicitly, so an install found only
through `PYTHONPATH` still loads the same hlyn.

A frozen app (PyInstaller and the like, `sys.frozen`) has no separate
interpreter. As with `multiprocessing.freeze_support()`, its `main` calls
`hlyn.helper()` first thing, and hlyn re-runs the app's own executable with a
marker argument that makes that call become the helper.

This module stays small and imports little: the gate starts through it on
every `hlyn.run(fn)` call that names hosts.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

__all__ = ["MARKER", "command", "helper", "interpreter", "main"]

# The argument a frozen app is re-run with to become a helper.
MARKER = "--hlyn-helper"

# The helpers, by name, and the module whose `main(argv)` each one runs.
NAMES = {"proxy": "hlyn.proxy", "gate": "hlyn.gate"}


def interpreter() -> str:
    """The Python a helper runs on: the one `multiprocessing` would start."""
    import multiprocessing.spawn

    return os.fsdecode(multiprocessing.spawn.get_executable())


def command(name: str, *args: str) -> list[str]:
    """The argument vector that starts helper `name` with `args`."""
    if name not in NAMES:
        raise ValueError(f"no helper called {name!r}")
    if getattr(sys, "frozen", False):
        return [sys.executable, MARKER, name, *args]
    # This very package, by path, as a bare module: helpers need only their
    # own submodules, and skipping the package's __init__ (the whole public
    # API) halves a helper's start, which a gate pays per run (5.8).
    here = os.path.dirname(os.path.abspath(__file__))
    boot = ("import sys, types; package = types.ModuleType('hlyn'); "
            f"package.__path__ = [{here!r}]; sys.modules['hlyn'] = package; "
            "from hlyn.helpers import main; main()")
    return [interpreter(), "-I", "-S", "-c", boot, name, *args]


def main(argv: Sequence[str] | None = None) -> None:
    """Run the helper named first in `argv` (default: `sys.argv[1:]`), then exit."""
    import importlib

    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in NAMES:
        print(f"hlyn: helper: expected one of {', '.join(NAMES)}, got {args[:1]}", file=sys.stderr)
        sys.exit(2)
    module = importlib.import_module(NAMES[args[0]])
    sys.exit(module.main(args[1:]))


def helper() -> None:
    """Become a helper if this process was started as one. For frozen apps.

        if __name__ == "__main__":
            hlyn.helper()        # first thing, like multiprocessing.freeze_support()
            main()

    Does nothing, and returns, in a process started any other way.
    """
    if len(sys.argv) > 1 and sys.argv[1] == MARKER:
        main(sys.argv[2:])
