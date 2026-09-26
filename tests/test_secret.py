"""Secrets a policy would let out.

A folder grant cannot exclude the `.env` inside it, so the danger is the pair:
secrets readable and the network open. These pin down when that is said, and
-- just as important, since a warning that always fires gets ignored -- when
it is not.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import warnings

import pytest
from conftest import SRC, skip_if_too_old

from hlyn.policy import Policy
from hlyn.secret import DEPTH, Exposed, credential, exposed


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hi')")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-live")
    (tmp_path / ".env.example").write_text("OPENAI_API_KEY=")
    return tmp_path


def names(found):
    return {os.path.basename(path) for path in found}


def test_a_folder_holding_a_secret_with_the_network_open_is_exposed(project):
    assert names(exposed(Policy(read=[project], net=[443]))) == {".env"}


def test_with_the_network_closed_nothing_is_exposed(project):
    # Readable, but with nowhere to go.
    assert exposed(Policy(read=[project])) == []


def test_granting_a_secret_file_on_its_own_is_a_decision_not_a_leak(project):
    assert exposed(Policy(read=[project / "src", project / ".env"], net=[443])) == []


def test_a_narrower_grant_is_the_fix(project):
    assert exposed(Policy(read=[project / "src"], net=[443])) == []


def test_templates_and_public_keys_are_not_secrets(tmp_path):
    for name in (".env.example", ".env.sample", ".env.template", "id_ed25519.pub"):
        (tmp_path / name).write_text("x")
    assert exposed(Policy(read=[tmp_path], net=True)) == []


@pytest.mark.parametrize(
    "name",
    [".env", ".env.production", "id_rsa", "server.key", "credentials.json", "service-account-prod.json"],
)
def test_real_secret_names_are_found(tmp_path, name):
    (tmp_path / name).write_text("-----BEGIN PRIVATE KEY-----\n")
    assert names(exposed(Policy(read=[tmp_path], net=True))) == {name}


def test_a_write_grant_exposes_too_since_writing_implies_reading(project):
    assert names(exposed(Policy(write=[project], net=[443]))) == {".env"}


def test_dependency_folders_are_not_searched(tmp_path):
    deep = tmp_path / "node_modules" / "some-lib" / "test"
    deep.mkdir(parents=True)
    (deep / "fixture.key").write_text("x")
    assert exposed(Policy(read=[tmp_path], net=True)) == []


def test_the_search_is_bounded_in_depth(tmp_path):
    deep = tmp_path
    for i in range(DEPTH + 2):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / ".env").write_text("x")
    assert exposed(Policy(read=[tmp_path], net=True)) == []


def test_granting_a_credential_folder_itself_is_exposed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "config").write_text("x")
    found = exposed(Policy(read=[tmp_path / ".aws"], net=[443]))
    assert found == [os.path.realpath(tmp_path / ".aws")]


def test_reading_everything_names_the_home_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".ssh").mkdir()
    assert names(exposed(Policy(read=True, net=[443]))) == {".ssh"}


def test_public_keys_are_not_credentials_but_private_ones_are():
    assert credential("/srv/id_ed25519")
    assert not credential("/srv/id_ed25519.pub")


def test_on_warns_before_sealing(project):
    # Checked through the public entry point, in a child: on() seals.
    code = f"""
import sys, warnings
sys.path.insert(0, {SRC!r})
import hlyn
warnings.simplefilter("error", hlyn.Exposed)
try:
    hlyn.on(read=[{str(project)!r}], net=[443], log=False)
except hlyn.Exposed as w:
    print("WARNED", ".env" in str(w))
"""
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert "WARNED True" in done.stdout, done.stderr


def test_the_warning_class_is_a_normal_python_warning(project):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from hlyn.jail import _warn

        _warn(Policy(read=[project], net=[443], log=False))
    assert [w.category for w in caught] == [Exposed]


def test_the_cli_warns_and_says_what_to_do(project):
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~")}
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "show", "--read", str(project), "--net", "443"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert "warning: the agent can read 1 secret file and reach the network" in done.stderr
    assert "--read ./src" in done.stderr
    assert "--env NAME" in done.stderr
    silenced = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "show", "--read", str(project), "--net", "443"],
        capture_output=True, text=True, env={**env, "PYTHONWARNINGS": "ignore::hlyn.Exposed"}, check=False,
    )
    assert "warning" not in silenced.stderr, silenced.stderr
    quiet = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "show", "--read", str(project / "src"), "--net", "443"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert "warning" not in quiet.stderr


@pytest.mark.parametrize(
    "name", [".envrc", ".npmrc", ".netrc", "secrets.toml", "secrets.yaml", "terraform.tfstate", "prod.tfvars"]
)
def test_project_level_secrets_are_found(tmp_path, name):
    (tmp_path / name).write_text("x")
    assert names(exposed(Policy(read=[tmp_path], net=True))) == {name}


def test_a_link_to_a_secret_outside_every_grant_is_not_exposed(tmp_path):
    # The kernel checks where a link leads, so this one cannot be read.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.env").write_text("x")
    granted = tmp_path / "granted"
    granted.mkdir()
    (granted / ".env").symlink_to(outside / "real.env")
    assert exposed(Policy(read=[granted], net=True)) == []


def test_a_link_to_a_secret_inside_a_grant_is_exposed(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "prod.key").write_text("-----BEGIN PRIVATE KEY-----\n")
    (tmp_path / ".env").symlink_to(tmp_path / "config" / "prod.key")
    assert names(exposed(Policy(read=[tmp_path], net=True))) == {".env", "prod.key"}


def test_a_credential_folder_is_named_once_not_file_by_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    for name in ("id_rsa", "id_ed25519", "config"):
        (ssh / name).write_text("x")
    assert exposed(Policy(read=[tmp_path], net=True)) == [str(ssh)]


def test_the_search_stops_when_its_time_is_up(tmp_path, monkeypatch):
    import hlyn.secret as secret

    (tmp_path / "a").mkdir()
    (tmp_path / "a" / ".env").write_text("x")
    monkeypatch.setattr(secret, "TIME", -1.0)
    assert exposed(Policy(read=[tmp_path], net=True)) == []


def _seal_and_capture(project, log, tmp_path):
    code = f"""
import sys, warnings
sys.path.insert(0, {SRC!r})
import hlyn
warnings.simplefilter("ignore")
hlyn.on(read=[{str(project)!r}], net=[443], log={log!r})
"""
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="seals")
def test_the_log_record_goes_where_the_policy_says(project, tmp_path):
    quiet = _seal_and_capture(project, False, tmp_path)
    skip_if_too_old(quiet)
    assert '"exposed"' not in quiet.stderr, quiet.stderr
    record = tmp_path / "log.jsonl"
    to_file = _seal_and_capture(project, str(record), tmp_path)
    skip_if_too_old(to_file)
    assert '"exposed"' not in to_file.stderr
    rows = [json.loads(line) for line in record.read_text().splitlines()]
    assert [row["kind"] for row in rows][:2] == ["exposed", "seal"]


def test_the_cli_refuses_when_warnings_are_errors(project):
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"),
           "PYTHONWARNINGS": "error::hlyn.Exposed"}
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--read", str(project), "--net", "443", "--",
         sys.executable, "-c", "print('RAN')"],
        capture_output=True, text=True, env=env, check=False,
    )
    assert done.returncode == 2
    assert "RAN" not in done.stdout
    assert "hlyn: refused:" in done.stderr
    assert "Traceback" not in done.stderr


def test_a_keynote_file_or_a_public_certificate_is_not_a_secret(tmp_path):
    (tmp_path / "Slides.key").write_bytes(b"PK\x03\x04 zip of a presentation")
    (tmp_path / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\nMIIB\n")
    (tmp_path / "tls.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
    assert names(exposed(Policy(read=[tmp_path], net=True))) == {"tls.pem"}
