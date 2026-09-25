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


def test_version_is_one_flag_away():
    done = hlyn("--version")
    assert done.returncode == 0
    assert done.stdout.startswith("hlyn ")


def test_probe_prints_json_when_asked():
    out = json.loads(hlyn("probe", "--json").stdout)
    assert "enforce" in out and "platform" in out


def test_probe_speaks_to_a_person_by_default():
    out = hlyn("probe").stdout
    assert "hlyn can" in out and "isolation between agents" in out
    with pytest.raises(ValueError):
        json.loads(out)


@here
def test_probe_exits_zero_when_the_machine_can_enforce():
    # Usable as a preflight gate in a pipeline, not just something to read.
    assert hlyn("probe").returncode == 0


def test_presets_lists_the_built_ins():
    names = {line.split()[0] for line in hlyn("presets").stdout.splitlines()}
    assert {"strict", "coder", "web", "data", "debug"} <= names


def test_presets_say_what_each_one_grants():
    lines = {line.split()[0]: line for line in hlyn("presets").stdout.splitlines()}
    assert "any network" in lines["web"]
    assert "run any program" in lines["coder"]


def test_show_prints_the_resolved_policy():
    out = json.loads(hlyn("show", "--read", "/srv", "--net", "443", "--json").stdout)
    assert out["net"] == [443]
    assert any(item == "/srv" for item in out["read"])


def test_show_prints_toml_by_default_like_watch():
    out = hlyn("show", "--net", "443", "--intent").stdout
    assert "net = [" in out and "443" in out


def test_show_applies_a_preset():
    assert json.loads(hlyn("show", "--preset", "web", "--json").stdout)["net"] is True


def test_show_never_leaks_secrets_in_the_env_summary():
    out = json.loads(hlyn("show", "--json").stdout)
    assert all("KEY" not in name and "SECRET" not in name for name in out["env"])


def test_flags_add_to_a_policy_file_never_replace_it(tmp_path):
    # `--net 8080` on top of a file granting 443 used to drop 443 -- read and
    # write were merged but exec, net and env were overwritten.
    policy = tmp_path / "policy.toml"
    policy.write_text('net = [443]\nexec = ["/usr/bin/true"]\nenv = ["A"]\n')
    out = json.loads(hlyn(
        "show", "-f", str(policy), "--net", "8080", "--exec", "/bin/ls", "--env", "B",
        "--intent", "--json",
    ).stdout)
    assert out["net"] == [443, 8080]
    assert set(out["exec"]) == {"/usr/bin/true", "/bin/ls"}
    assert set(out["env"]) == {"A", "B"}


def test_a_flag_never_narrows_a_field_that_grants_everything(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text("read = true\nnet = true\n")
    out = json.loads(hlyn(
        "show", "-f", str(policy), "--read", "/srv", "--net", "443", "--intent", "--json",
    ).stdout)
    assert out["read"] is True
    assert out["net"] is True


def test_a_host_name_gets_the_reason_not_a_type_error():
    done = hlyn("show", "--net", "api.openai.com")
    assert done.returncode == 2
    assert "host names are not enforceable" in done.stderr
    assert "--net 443" in done.stderr
    assert "invalid int" not in done.stderr


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


# ---------------------------------------------------------------------------
# the command line as a gate
# ---------------------------------------------------------------------------


@here
def test_a_separator_inside_the_command_is_left_alone():
    # `--` is a separator to argparse and an argument to git, cargo, npm and
    # pytest. Stripping every one of them rewrote the command being launched
    # into a different command, silently -- which for a tool whose claim is
    # that the boundary matches the document is the wrong bug to have.
    done = hlyn(
        "run", "--exec-any", "--", sys.executable, "-c",
        "import sys; print('ARGV', sys.argv[1:])",
        "--", "kept",
    )
    assert "ARGV ['--', 'kept']" in done.stdout, f"the separator was eaten: {done.stdout}{done.stderr}"


@here
def test_run_passes_on_the_exit_code_and_says_what_to_try():
    done = hlyn("run", "--no-log", "--", sys.executable, "-c", "import sys; sys.exit(3)")
    assert done.returncode == 3
    assert "Allow it with --read" in done.stderr
    assert "hlyn watch --" in done.stderr, "a Python command should be pointed at watch"


@here
def test_run_is_silent_when_the_command_succeeds():
    done = hlyn("run", "--no-log", "--", sys.executable, "-c", "print('UP')")
    assert done.returncode == 0
    assert done.stderr == ""


def test_a_command_that_cannot_start_gets_one_message_not_a_hint():
    done = hlyn("run", "--no-log", "--", "no-such-program-hlyn")
    assert done.returncode == 1
    assert "was not found" in done.stderr
    assert "Allow it with" not in done.stderr
