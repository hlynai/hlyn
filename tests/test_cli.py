"""The command line.

`hlyn run -- python agent.py` is the onboarding path for anyone who would
rather not edit their agent, so it is worth testing that it confines rather
than merely launches.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import SRC

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")


def hlyn(*args: str) -> subprocess.CompletedProcess:
    # A deliberately bare environment, so these tests prove the CLI works from
    # a clean shell rather than inheriting something from the test runner.
    # HLYN_SHIM is the one exception: it names where the Landlock shim lives,
    # and without forwarding it the CLI silently finds no shim, reports that it
    # cannot enforce, and exits non-zero anywhere the build tree is not laid
    # out exactly as expected.
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin"}
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        env["HLYN_SHIM"] = shim
    return subprocess.run(
        [sys.executable, "-m", "hlyn.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )


def test_probe_prints_json():
    done = hlyn("probe")
    out = json.loads(done.stdout)
    assert "enforce" in out and "platform" in out


@here
def test_probe_exits_zero_when_the_machine_can_enforce():
    # Usable as a preflight gate in a pipeline, not just something to read.
    assert hlyn("probe").returncode == 0


def test_presets_lists_the_built_ins():
    names = hlyn("presets").stdout.split()
    assert {"strict", "coder", "web", "data", "debug"} <= set(names)


def test_show_prints_the_resolved_policy():
    out = json.loads(hlyn("show", "--read", "/srv", "--net", "443").stdout)
    assert out["net"] == [443]
    assert any(item == "/srv" for item in out["read"])


def test_show_applies_a_preset():
    assert json.loads(hlyn("show", "--preset", "web").stdout)["net"] is True


def test_show_never_leaks_secrets_in_the_env_summary():
    out = json.loads(hlyn("show").stdout)
    assert all("KEY" not in name and "SECRET" not in name for name in out["env"])


def test_run_without_a_command_explains_itself():
    done = hlyn("run")
    assert done.returncode == 2
    assert "hlyn run --" in done.stderr


@here
def test_run_confines_the_command_it_launches():
    done = hlyn(
        "run", "--", sys.executable, "-c",
        "print('AGENT UP')\n"
        "try:\n"
        "    open('/etc/hosts').read(); print('ESCAPED')\n"
        "except OSError: print('CONFINED')",
    )
    assert "AGENT UP" in done.stdout, f"the command did not run: {done.stderr}"
    assert "CONFINED" in done.stdout, f"the command was not confined: {done.stdout}"


@here
def test_run_records_the_boundary_it_applied():
    done = hlyn("run", "--", sys.executable, "-c", "print('UP')")
    seals = [
        json.loads(line)
        for line in done.stderr.splitlines()
        if line.startswith("{") and '"seal"' in line
    ]
    assert seals, f"no seal record was written:\n{done.stderr}"
    assert seals[0]["kind"] == "seal"


@here
def test_run_can_be_told_to_record_nothing():
    done = hlyn("run", "--no-log", "--", sys.executable, "-c", "print('UP')")
    assert '"seal"' not in done.stderr
    assert "UP" in done.stdout
