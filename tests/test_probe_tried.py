# SPDX-License-Identifier: Apache-2.0
"""`hlyn probe` confines a test program instead of only reading versions.

A machine can look able (new kernel, libseccomp present) and still fail the
seal: a container profile that refuses a call the seal needs. Reading versions
says yes there; trying says no. Each test prints what probe said.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import SRC, boot, enforces
from test_openat2_refused import REFUSE


def probe(*args: str):
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "probe", *args], capture_output=True,
                          text=True, check=False, env={**os.environ, "PYTHONPATH": SRC})
    print(done.stdout, done.stderr, "exit", done.returncode)
    return done


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_probe_tries_a_confined_program_and_says_so():
    done = probe("--json")
    out = json.loads(done.stdout)
    assert out["tried"] == {"ok": True, "why": None} and out["enforce"] is True and done.returncode == 0
    text = probe().stdout
    assert "tried: a confined test program was refused the rest" in text
    row = next(line for line in text.splitlines() if "tried:" in line)
    assert len(row) <= 60, f"the new row must fit a narrow window: {len(row)} columns"


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_quick_reads_versions_only_and_tries_nothing():
    out = json.loads(probe("--json", "--quick").stdout)
    assert "tried" not in out and out["enforce"] is True
    assert "tried:" not in probe("--quick").stdout


@pytest.mark.skipif(sys.platform != "linux" or not enforces(), reason="openat2 filter is Linux")
def test_a_machine_that_looks_able_but_cannot_seal_is_found_by_trying():
    # The same refusal an old container profile gives (tests/test_openat2_refused.py).
    done = boot(REFUSE + """
import hlyn
quick = hlyn.probe()
tried = hlyn.probe(tried=True)
print("QUICK", quick["enforce"], "| TRIED", tried["enforce"], tried["tried"]["ok"])
print("WHY", tried.get("why"))
""")
    print(done.stdout, done.stderr)
    assert "QUICK True | TRIED False False" in done.stdout and "openat2" in done.stdout


@pytest.mark.skipif(sys.platform != "linux" or not enforces(), reason="openat2 filter is Linux")
def test_the_command_exits_nonzero_and_says_no_when_trying_fails():
    done = boot(REFUSE + """
import sys
from hlyn import cli
sys.exit(cli.main(["probe"]))
""")
    print(done.stdout, done.stderr)
    assert done.returncode == 1 and done.stdout.startswith("NO ") and "openat2" in done.stdout


def test_nothing_is_tried_when_the_machine_is_known_not_to_enforce(monkeypatch):
    from hlyn import jail

    class Unable:
        @staticmethod
        def probe() -> dict[str, object]:
            return {"enforce": False}

    monkeypatch.setattr(jail, "back", Unable)
    out = jail.probe(tried=True)
    print(out)
    assert out["tried"]["ok"] is None and out["enforce"] is False
