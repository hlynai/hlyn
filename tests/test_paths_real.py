# SPDX-License-Identifier: Apache-2.0
"""What is shown is what is sealed: links in grants and the audit log's place.

A grant naming a link is shown and recorded by what the kernel grants, its
target; and a log inside a writable folder is refused, because the agent could
delete and replace it while hlyn kept writing to the unlinked original.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import SRC, boot

from hlyn import jail
from hlyn.error import Invalid
from hlyn.policy import Policy, linked

REAL = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")


@pytest.fixture
def tree(tmp_path):
    project, secrets = tmp_path / "project", tmp_path / "secrets"
    project.mkdir()
    secrets.mkdir()
    (secrets / "key").write_text("TOPSECRET")
    os.symlink(secrets, project / "src")
    return project, secrets


def test_a_grant_naming_a_link_is_stored_as_what_it_grants(tree):
    project, secrets = tree
    plan = Policy(read=[project / "src"], write=[project / "src"])
    print(plan.read, plan.write)
    assert plan.read == (os.path.realpath(secrets),)
    assert plan.write == (os.path.realpath(secrets),)


def test_the_seal_record_and_hlyn_show_name_the_target(tree, tmp_path):
    project, secrets = tree
    env = {**os.environ, "PYTHONPATH": SRC}
    shown = subprocess.run([sys.executable, "-m", "hlyn.cli", "show", "--read", "./src"],
                           cwd=project, env=env, capture_output=True, text=True, check=False)
    print(shown.stdout[-400:], shown.stderr)
    assert os.path.realpath(secrets) in shown.stdout
    assert f"--read ./src is a link; granting what it names: {os.path.realpath(secrets)}" in shown.stderr
    log = tmp_path / "record.jsonl"
    subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--read", "./src", "--log", str(log), "--",
                    sys.executable, "-c", "pass"], cwd=project, env=env, capture_output=True, check=False)
    seal = next(json.loads(line) for line in log.read_text().splitlines() if '"seal"' in line)
    print("record read:", seal["read"])
    # `hlyn run` may add its own files to the typed list (the report library, on
    # Linux), so the grant is looked for, and the link's own name must be absent.
    assert os.path.realpath(secrets) in seal["read"]
    assert str(project / "src") not in seal["read"]


def test_the_systems_own_aliases_are_not_reported_as_links(tmp_path):
    if not os.path.islink("/tmp"):
        pytest.skip("/tmp is not a link here")
    assert linked(["/tmp/x"]) == []
    assert linked([tmp_path]) == []


def test_a_grant_swapped_for_a_link_after_the_check_is_not_sealed(tree, tmp_path):
    # The policy is checked (and shown) first; then something swaps the
    # folder for a link to the secrets before the seal. The last check refuses.
    project, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    plan = Policy(read=[target])
    os.rmdir(target)
    os.symlink(secrets, target)
    with pytest.raises(Invalid, match="now leads somewhere else") as error:
        jail._unchanged(plan)
    print(error.value)
    jail._unchanged(Policy(read=[project]))  # the control: unchanged grants pass


@REAL
def test_a_swap_between_check_and_seal_is_refused_by_the_real_seal(tree, tmp_path):
    _, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    done = boot(
        f"""
        import os, hlyn
        plan = hlyn.Policy(read=[{str(target)!r}], log=False)
        os.rmdir({str(target)!r}); os.symlink({str(secrets)!r}, {str(target)!r})
        try:
            hlyn.on(plan); print("SEALED", open({str(target / "key")!r}).read())
        except hlyn.Invalid as error:
            print("REFUSED", error)
        """
    )
    print(done.stdout, done.stderr[-300:])
    assert done.stdout.startswith("REFUSED"), done.stdout + done.stderr


@pytest.mark.parametrize("where", ["inside a write grant", "write=True", "inside tmp"])
def test_a_log_the_agent_could_replace_is_refused(tmp_path, where):
    out = tmp_path / "out"
    out.mkdir()
    log = str(out / "audit.jsonl")
    kwargs = {"inside a write grant": {"write": [out]}, "write=True": {"write": True},
              "inside tmp": {"tmp": str(out)}}[where]
    with pytest.raises(Invalid, match="could delete the record") as error:
        Policy(log=log, **kwargs)
    print(error.value)
    Policy(log=str(tmp_path / "audit.jsonl"), write=[out])  # the control: outside, accepted


@REAL
def test_with_the_log_outside_the_agent_cannot_unlink_or_replace_it(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    log = tmp_path / "audit.jsonl"
    env = {**os.environ, "PYTHONPATH": SRC}
    code = (f"import os\ntry:\n    os.unlink({str(log)!r}); print('UNLINKED')\n"
            "except OSError as e:\n    print('REFUSED', e.errno)")
    argv = [sys.executable, "-m", "hlyn.cli", "run", "--write", str(out), "--log", str(log),
            "--", sys.executable, "-c", code]
    done = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    print(done.stdout, done.stderr[-300:])
    assert "REFUSED" in done.stdout
    assert '"kind": "seal"' in log.read_text()
