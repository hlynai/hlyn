# SPDX-License-Identifier: Apache-2.0
"""What `import hlyn` costs, pinned.

Start-up is paid on every `hlyn run` and every `hlyn.on()`, so modules only
some paths need are imported where they are used, not at the top (Python 3.15's
`lazy import` isn't available to a package that supports 3.10). A module that
creeps back to the top would pass every behaviour test and quietly add its
import time to every run; these tests are what notices.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from conftest import SRC, enforces

# Each was measured 2026-10-02 (macOS, Python 3.14): pickle ~5 ms, socket ~2 ms,
# ctypes.util ~4 ms (it pulls in subprocess), argparse and asyncio more.
HEAVY = ("pickle", "socket", "ctypes", "ctypes.util", "subprocess", "argparse", "asyncio", "ssl")


def python(code: str) -> str:
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "PYTHONPATH": SRC}, check=False)
    print(done.stdout, done.stderr)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_importing_hlyn_loads_none_of_the_heavy_modules():
    loaded = python(f"import sys, hlyn; print([m for m in {HEAVY!r} if m in sys.modules])")
    print("loaded by `import hlyn`:", loaded)
    assert loaded == "[]"


def test_the_control_proves_the_check_can_fail():
    # If the list were never loaded by anything, the test above would pass for
    # the wrong reason: importing them by hand must show up.
    loaded = python("import sys, hlyn, pickle, socket; "
                    "print(sorted(m for m in ('pickle', 'socket') if m in sys.modules))")
    assert loaded == "['pickle', 'socket']"


def test_a_loose_ipv4_still_gets_its_hint_with_socket_imported_only_then():
    out = python(
        "import sys, hlyn\n"
        "from hlyn import hosts\n"
        "hosts.parse('example.com')\n"
        "before = 'socket' in sys.modules\n"
        "try:\n"
        "    hosts.parse('127.1')\n"
        "except hlyn.Invalid as exc:\n"
        "    said = str(exc)\n"
        "print(before, 'socket' in sys.modules, \"Did you mean '127.0.0.1'\" in said)"
    )
    assert out == "False True True"


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt")
def test_seatbelt_is_loaded_without_ctypes_util():
    out = python("import sys; from hlyn.core import mac; lib = mac.lib(); "
                 "print(hasattr(lib, 'sandbox_init'), 'ctypes.util' in sys.modules, "
                 "'subprocess' in sys.modules)")
    assert out == "True False False"


@pytest.mark.skipif(not enforces(), reason="this machine can't enforce")
def test_run_imports_pickle_before_it_forks_and_still_returns_results_and_errors(monkeypatch):
    # The child is sealed, and a threaded caller may hold the import lock: so
    # `pickle` must already be loaded when `run` forks.
    import hlyn

    real, seen = os.fork, []

    def fork():
        seen.append("pickle" in sys.modules)
        return real()

    monkeypatch.delitem(sys.modules, "pickle", raising=False)
    monkeypatch.setattr(os, "fork", fork)
    assert hlyn.run(lambda: 6 * 7) == 42

    def boom():
        raise ValueError("from the confined child")

    with pytest.raises(ValueError, match="from the confined child"):
        hlyn.run(boom)
    print("pickle loaded at each fork:", seen)
    assert seen and all(seen)
