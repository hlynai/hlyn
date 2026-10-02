# SPDX-License-Identifier: Apache-2.0
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


# hlyn installed from a wheel isn't importable when Python reads -W and
# PYTHONWARNINGS (before site-packages is on the path), so Python drops an
# entry naming hlyn's warnings. Putting hlyn on sys.path only after startup
# reproduces exactly that; PYTHONPATH, as the tests above use, hides it.
INSTALLED = (f"import runpy, sys; sys.path.insert(0, {SRC!r}); "
             "runpy.run_module('hlyn.cli', run_name='__main__')")


@pytest.mark.parametrize("action", ["error", "ignore", "default"])
def test_pythonwarnings_naming_hlyns_warning_works_for_an_installed_hlyn(project, action):
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"),
           "PYTHONWARNINGS": f"{action}::hlyn.Exposed"}
    done = subprocess.run(
        [sys.executable, "-c", INSTALLED, "run", "--no-log", "--read", str(project), "--net", "443", "--",
         sys.executable, "-c", "print('RAN')"],
        capture_output=True, text=True, env=env, check=False, cwd=str(project),
    )
    print(f"PYTHONWARNINGS={action}::hlyn.Exposed: exit {done.returncode}\nstdout:\n{done.stdout}"
          f"stderr:\n{done.stderr}")
    assert "Traceback" not in done.stderr
    if action == "error":
        assert done.returncode == 2 and "RAN" not in done.stdout and "hlyn: refused:" in done.stderr
    elif action == "ignore":
        assert done.returncode == 0 and "RAN" in done.stdout and "secret file" not in done.stderr
    else:
        assert done.returncode == 0 and "RAN" in done.stdout and "hlyn: warning:" in done.stderr


def test_pythonwarnings_naming_reach_works_for_an_installed_hlyn(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"), "PYTHONWARNINGS": "error::hlyn.Reach"}
    done = subprocess.run(
        [sys.executable, "-c", INSTALLED, "run", "--no-log", "--net", "localhost:2375", "--",
         sys.executable, "-c", "print('RAN')"],
        capture_output=True, text=True, env=env, check=False, cwd=str(tmp_path),
    )
    print(f"exit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    assert done.returncode == 2 and "RAN" not in done.stdout and "hlyn: refused:" in done.stderr


def test_a_program_filter_still_beats_pythonwarnings(project):
    """An entry applied late must not override what the program itself set
    for the warning: code runs after startup, so its filter wins, as it would
    have if Python could have applied the entry itself."""
    code = (f"import sys, warnings; sys.path.insert(0, {SRC!r}); import hlyn\n"
            "warnings.simplefilter('ignore', hlyn.Exposed)\n"
            f"hlyn.run(lambda: None, read=[{str(project)!r}], net=[443], log=False)\n"
            "print('RAN')\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"), "PYTHONWARNINGS": "error::hlyn.Exposed"}
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False)
    print(f"exit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    assert done.returncode == 0 and "RAN" in done.stdout


def test_a_keynote_file_or_a_public_certificate_is_not_a_secret(tmp_path):
    (tmp_path / "Slides.key").write_bytes(b"PK\x03\x04 zip of a presentation")
    (tmp_path / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\nMIIB\n")
    (tmp_path / "tls.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
    assert names(exposed(Policy(read=[tmp_path], net=True))) == {"tls.pem"}


def test_an_env_template_is_not_a_secret_whichever_end_the_word_is_on(tmp_path):
    # Found by `hlyn claude`: a Claude Code plugin marketplace ships
    # `.env.production.example` and friends, and the warning named all four.
    # A template is a template wherever the word sits; a real `.env` is not.
    for name in (".env.example", ".env.sample", ".env.production.example",
                 ".env.preview.example", ".env.local.template", ".env.defaults"):
        (tmp_path / name).write_text("KEY=replace-me\n")
    for name in (".env", ".env.local", ".env.production", ".env.prod.secret"):
        (tmp_path / name).write_text("KEY=real\n")
    found = names(exposed(Policy(read=[tmp_path], net=True)))
    print(sorted(found))
    assert found == {".env", ".env.local", ".env.production", ".env.prod.secret"}


# -- more secret files (REMAINING #5) ----------------------------------------

# Every credential path added to HOMES, as (path under HOME, "file" or "folder").
NEW_HOME_SECRETS = [
    (".cargo/credentials.toml", "file"), (".cargo/credentials", "file"), (".gem/credentials", "file"),
    (".config/pnpm/auth.ini", "file"), (".composer/auth.json", "file"),
    (".config/composer/auth.json", "file"), (".m2/settings.xml", "file"),
    (".gradle/gradle.properties", "file"), (".terraform.d/credentials.tfrc.json", "file"),
    (".config/pulumi/credentials.json", "file"), (".oci", "folder"), (".ibmcloud", "folder"),
    (".databrickscfg", "file"), (".boto", "file"), (".s3cfg", "file"), (".dockercfg", "file"),
    (".vault-token", "file"), (".config/doctl", "folder"), (".config/hub", "file"),
    (".config/glab-cli", "folder"), (".config/rclone", "folder"), (".config/stripe", "folder"),
    (".config/ngrok", "folder"), (".ngrok2", "folder"), (".config/configstore/firebase-tools.json", "file"),
    (".config/.wrangler", "folder"), (".supabase/access-token", "file"), (".sentryclirc", "file"),
    (".config/containers/auth.json", "file"), (".config/git/credentials", "file"),
    (".huggingface/token", "file"), (".kaggle/kaggle.json", "file"),
    (".config/kaggle/kaggle.json", "file"), (".config/github-copilot", "folder"), (".my.cnf", "file"),
    (".mylogin.cnf", "file"), (".msmtprc", "file"), (".subversion/auth", "folder"),
    (".config/sops/age", "folder"), (".local/share/keyrings", "folder"),
    (".local/share/kwalletd", "folder"), (".mozilla/firefox", "folder"), (".config/google-chrome", "folder"),
    (".config/chromium", "folder"), ("Library/Application Support/Google/Chrome", "folder"),
    ("Library/Application Support/Firefox/Profiles", "folder"),
]


@pytest.mark.parametrize(("path", "kind"), NEW_HOME_SECRETS, ids=[item[0] for item in NEW_HOME_SECRETS])
def test_a_home_that_holds_a_newly_listed_secret_is_warned_about_it(tmp_path, monkeypatch, path, kind):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = tmp_path / path
    if kind == "folder":
        target.mkdir(parents=True)
        (target / "inside").write_text("x")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("token=abc")
    found = exposed(Policy(read=[tmp_path], net=True))
    print(f"{path}: warned about {[os.path.relpath(item, tmp_path) for item in found]}")
    assert found == [str(target)]


@pytest.mark.parametrize(
    "name",
    [".vault-token", ".boto", ".s3cfg", ".dockercfg", ".my.cnf", ".mylogin.cnf", ".msmtprc", "_netrc",
     "auth.json", "token.json", "client_secret_123.apps.googleusercontent.com.json", "wp-config.php",
     ".dev.vars", ".secrets", ".sentryclirc", ".databrickscfg", "credentials.tfrc.json", "kaggle.json",
     "prod.tfstate", "AuthKey_ABC123.p8", "service.keytab", "store.jceks"],
)
def test_newly_listed_secret_names_are_found_in_a_project(tmp_path, name):
    (tmp_path / name).write_text("x")
    found = exposed(Policy(read=[tmp_path], net=True))
    print(f"{name}: warned about {[os.path.basename(item) for item in found]}")
    assert names(found) == {name}


@pytest.mark.parametrize(
    "path",
    ["/etc/shadow-", "/etc/security/opasswd", "/etc/sudoers.d/90-ci", "/etc/wireguard/wg0.conf",
     "/etc/NetworkManager/system-connections/home.nmconnection", "/etc/ppp/chap-secrets",
     "/etc/krb5.keytab", "/etc/kubernetes/admin.conf", "/etc/kubernetes/pki/ca.key",
     "/etc/rancher/k3s/k3s.yaml", "/etc/docker/key.json", "/var/lib/samba/private/passdb.tdb",
     "/etc/master.passwd", "/private/etc/master.passwd", "/private/etc/ssh/ssh_host_rsa_key"],
)
def test_newly_listed_system_secrets_are_credentials(path):
    print(f"{path}: credential={credential(path)}")
    assert credential(path)


@pytest.mark.parametrize(
    "path",
    ["README.md", "package.json", "settings.xml", "pip.conf", "config.json", "token.txt", "auth.py",
     "wp-config-sample.php", "main.tfstate.md", "client.json", "notes.secrets.md"],
)
def test_ordinary_files_with_similar_names_are_not_warned_about(tmp_path, monkeypatch, path):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / path).write_text("x")
    (tmp_path / ".m2").mkdir()
    (tmp_path / ".m2" / "toolchains.xml").write_text("x")  # next to a listed file, not it
    found = exposed(Policy(read=[tmp_path], net=True))
    print(f"{path}: warned about {found}")
    assert found == []


# -- hardlinks (REMAINING #16h) ----------------------------------------------


def _home_with_key(tmp_path, monkeypatch):
    """A throwaway HOME holding ~/.ssh/id_rsa and ~/.aws/credentials, and a project beside it."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".aws").mkdir()
    (home / ".ssh" / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    (home / ".aws" / "credentials").write_text("[default]\naws_secret_access_key=abc\n")
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home, project


@pytest.mark.parametrize(("secret_path", "alias"), [
    (".ssh/id_rsa", "notes.txt"), (".aws/credentials", "conf/helper.cfg"),
])
def test_a_hardlink_to_a_known_secret_is_warned_about_under_any_name(
    tmp_path, monkeypatch, secret_path, alias,
):
    home, project = _home_with_key(tmp_path, monkeypatch)
    (project / alias).parent.mkdir(parents=True, exist_ok=True)
    os.link(home / secret_path, project / alias)
    assert os.stat(project / alias).st_nlink == 2
    found = exposed(Policy(read=[project], net=True))
    print(f"{alias} (a second name for ~/{secret_path}): warned about {found}")
    assert found == [str(project / alias)]


def test_an_unrelated_hardlink_is_not_warned_about(tmp_path, monkeypatch):
    home, project = _home_with_key(tmp_path, monkeypatch)
    (project / "data.txt").write_text("rows")
    os.link(project / "data.txt", project / "copy.txt")
    os.link(home / ".ssh" / "id_rsa", home / "elsewhere.txt")  # a secret IS linked, just not in the grant
    assert os.stat(project / "copy.txt").st_nlink == 2
    found = exposed(Policy(read=[project], net=True))
    print(f"two names for one ordinary file: warned about {found}")
    assert found == []


def test_a_hardlink_is_not_warned_about_when_the_network_is_closed(tmp_path, monkeypatch):
    home, project = _home_with_key(tmp_path, monkeypatch)
    os.link(home / ".ssh" / "id_rsa", project / "notes.txt")
    assert exposed(Policy(read=[project])) == []


def test_a_secret_with_one_name_leaves_nothing_to_compare(tmp_path, monkeypatch):
    from hlyn.secret import _linked_secrets

    home, project = _home_with_key(tmp_path, monkeypatch)
    print(f"known secrets with a second name: {_linked_secrets(str(home))}")
    assert _linked_secrets(str(home)) == set()
    os.link(home / ".ssh" / "id_rsa", project / "notes.txt")
    key = os.stat(home / ".ssh" / "id_rsa")
    assert _linked_secrets(str(home)) == {(key.st_dev, key.st_ino)}


def test_a_hugging_face_token_in_the_cache_is_a_credential_but_the_walk_skips_caches(tmp_path, monkeypatch):
    # `.cache` is in SKIP (walking it costs more than the rest of a home), so a
    # grant of the whole home does not find the token; a grant of the folder does.
    monkeypatch.setenv("HOME", str(tmp_path))
    token = tmp_path / ".cache" / "huggingface" / "token"
    token.parent.mkdir(parents=True)
    token.write_text("hf_abc")
    assert credential(str(token))
    assert exposed(Policy(read=[tmp_path], net=True)) == []
    assert exposed(Policy(read=[tmp_path / ".cache" / "huggingface"], net=True)) == [str(token)]
