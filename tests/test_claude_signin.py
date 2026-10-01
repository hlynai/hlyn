# SPDX-License-Identifier: Apache-2.0
"""`hlyn claude --login`: a sign-in kept in the keychain, outside the agent.

These never touch a real keychain: creating even a throwaway one adds it to
the user's keychain search list, which is user-wide state. `security` is
replaced by a stand-in that does what its man page says for the three
commands hlyn uses, and records every command line it was given, so a test
can show the token never appeared in one. The real round trip is recorded in
FINDINGS.md.
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from hlyn import claude
from hlyn.error import Error

FAKE = r'''#!{python}
"""A stand-in for /usr/bin/security: find/add/delete-generic-password, and -i."""
import json, os, shlex, sys
store_path, log_path = os.environ["FAKE_STORE"], os.environ["FAKE_LOG"]
with open(log_path, "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
store = json.load(open(store_path)) if os.path.exists(store_path) else {{}}

def opts(args):
    out, rest, i = {{}}, [], 0
    while i < len(args):
        if args[i] in ("-a", "-s", "-X"):
            out[args[i]] = args[i + 1]; i += 2
        elif args[i] in ("-w", "-U"):
            out[args[i]] = True; i += 1
        else:
            rest.append(args[i]); i += 1
    return out, (rest[0] if rest else "default")

def run(args):
    verb, o = args[0], None
    o, keychain = opts(args[1:])
    key = f"{{keychain}}|{{o.get('-a')}}|{{o.get('-s')}}"
    if verb == "find-generic-password":
        if key not in store:
            print("security: SecKeychainSearchCopyNext: The specified item could not be found.",
                  file=sys.stderr)
            return 44
        print(store[key]); return 0
    if verb == "add-generic-password":
        if key in store and "-U" not in o:
            return 45
        store[key] = bytes.fromhex(o["-X"]).decode(); return 0
    if verb == "delete-generic-password":
        if key not in store:
            return 44
        del store[key]; return 0
    return 1

if sys.argv[1:] == ["-i"]:
    code = 0
    for line in sys.stdin:
        if line.strip():
            if os.environ.get("FAKE_DROP"):
                continue  # answers 0 and keeps nothing, as `security -i` can
            code = run(shlex.split(line)) or code
    code = 0  # `security -i` exits 0 whatever its commands did
else:
    code = run(sys.argv[1:])
json.dump(store, open(store_path, "w"))
sys.exit(code)
'''

TOKEN = "sk-ant-oat01-not-a-real-token-0123456789"  # noqa: S105 - a fake


@pytest.fixture
def keychain(tmp_path, monkeypatch):
    """The stand-in `security`, as macOS, with HOME pointing at a fresh folder."""
    fake = tmp_path / "security"
    fake.write_text(FAKE.format(python=sys.executable))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(claude, "SECURITY", str(fake))
    monkeypatch.setattr(claude.sys, "platform", "darwin")
    monkeypatch.setenv("FAKE_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "log.jsonl"))
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return tmp_path


def calls(where):
    log = where / "log.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def stored(where):
    path = where / "store.json"
    return json.loads(path.read_text()) if path.exists() else {}


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------


def test_a_saved_token_reads_back(keychain):
    claude.save(TOKEN, {})
    print("store:", stored(keychain))
    assert claude.saved({}) == TOKEN


def test_the_token_never_appears_on_a_command_line(keychain):
    # As Claude Code writes its own item: the command goes to `security -i`
    # on stdin, hex-encoded, so `ps` never shows the secret.
    claude.save(TOKEN, {})
    claude.saved({})
    seen = calls(keychain)
    print("command lines:", seen)
    assert ["-i"] in seen
    assert not any(TOKEN in arg or TOKEN.encode().hex() in arg for line in seen for arg in line)


def test_saving_again_replaces_it(keychain):
    claude.save(TOKEN, {})
    claude.save(TOKEN + "-new", {})
    assert claude.saved({}) == TOKEN + "-new"
    assert len(stored(keychain)) == 1


def test_a_save_that_did_not_land_is_an_error(keychain, monkeypatch):
    # `security -i` exits 0 even when a command in it fails, so success is
    # checked by reading the item back.
    monkeypatch.setenv("FAKE_DROP", "1")
    with pytest.raises(Error, match="couldn't save the sign-in"):
        claude.save(TOKEN, {})


def test_forget_removes_it_once(keychain):
    claude.save(TOKEN, {})
    assert claude.forget({}) is True
    assert claude.saved({}) is None
    assert claude.forget({}) is False


def test_another_keychain_file_can_be_named(keychain, tmp_path):
    env = {"HLYN_KEYCHAIN": str(tmp_path / "test.keychain-db")}
    claude.save(TOKEN, env)
    print("store:", list(stored(keychain)))
    assert claude.saved(env) == TOKEN
    assert claude.saved({}) is None  # not in the default one
    assert all(str(tmp_path / "test.keychain-db") in key for key in stored(keychain))


def test_it_is_kept_under_hlyns_own_name_not_claude_codes(keychain):
    claude.save(TOKEN, {})
    (key,) = stored(keychain)
    print(key)
    assert key.endswith("|hlyn: Claude Code sign-in")


# ---------------------------------------------------------------------------
# using it: OpenAPPA's precedence
# ---------------------------------------------------------------------------


def test_a_kept_token_signs_claude_code_in(keychain):
    claude.save(TOKEN, {})
    env: dict[str, str] = {}
    note = claude.signin(env)
    print("note:", note, "| env:", env)
    assert note is None and env == {"CLAUDE_CODE_OAUTH_TOKEN": TOKEN}


@pytest.mark.parametrize("name", list(claude.SIGNINS))
def test_a_variable_the_person_set_wins_and_the_keychain_is_not_read(keychain, name):
    claude.save(TOKEN, {})
    before = len(calls(keychain))
    env = {name: "theirs"}
    assert claude.signin(env) is None
    assert env == {name: "theirs"}
    assert len(calls(keychain)) == before, "the keychain was read although a variable was set"


def test_with_nothing_kept_it_says_how_to_sign_in(keychain):
    env: dict[str, str] = {}
    note = claude.signin(env)
    print(note)
    assert note is not None and "hlyn claude --login" in note
    assert env == {}


def test_a_sign_in_file_in_the_state_folder_needs_no_keychain(keychain, tmp_path):
    state = tmp_path / "home" / ".claude"
    state.mkdir()
    (state / ".credentials.json").write_text("{}")
    claude.save(TOKEN, {})
    before = len(calls(keychain))
    env: dict[str, str] = {}
    assert claude.signin(env) is None and env == {}
    assert len(calls(keychain)) == before


def test_on_linux_nothing_is_read(keychain, monkeypatch):
    monkeypatch.setattr(claude.sys, "platform", "linux")
    before = len(calls(keychain))
    env: dict[str, str] = {}
    assert claude.signin(env) is None and env == {}
    assert len(calls(keychain)) == before


def test_the_token_reaches_claude_codes_environment_and_nothing_wider(keychain):
    # Only CLAUDE_* and ANTHROPIC_* are kept for Claude Code; another secret
    # in the same environment is still removed.
    claude.save(TOKEN, {})
    env = {"OPENAI_API_KEY": "not-for-claude"}
    claude.signin(env)
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    print(sorted(plan.env))
    assert "CLAUDE_CODE_OAUTH_TOKEN" in plan.env and "OPENAI_API_KEY" not in plan.env


# ---------------------------------------------------------------------------
# --login
# ---------------------------------------------------------------------------


@pytest.fixture
def setup_token(tmp_path):
    """A stand-in `claude` whose `setup-token` prints a token and exits."""
    fake = tmp_path / "claude"
    fake.write_text(f"#!{sys.executable}\nimport sys\nassert sys.argv[1:] == ['setup-token']\n"
                    f"print('Your token: {TOKEN}')\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return str(fake)


def test_login_runs_setup_token_and_keeps_what_is_pasted(keychain, setup_token, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda prompt: f"  {TOKEN}\n")
    said = claude.login(setup_token, {})
    print(said)
    assert claude.saved({}) == TOKEN
    assert "hlyn claude --logout" in said


@pytest.mark.parametrize("pasted", ["", "yes", "Your token: sk-ant-oat01-abcdefghijklmnop", "sk-ant-é" * 5])
def test_login_refuses_something_that_is_not_a_token_and_keeps_nothing(keychain, setup_token,
                                                                       monkeypatch, pasted):
    monkeypatch.setattr("getpass.getpass", lambda prompt: pasted)
    with pytest.raises(Error, match="doesn't look like a token"):
        claude.login(setup_token, {})
    assert stored(keychain) == {}


def test_login_on_linux_says_it_is_not_needed(keychain, setup_token, monkeypatch):
    monkeypatch.setattr(claude.sys, "platform", "linux")
    said = claude.login(setup_token, {})
    assert "nothing to do" in said and stored(keychain) == {}


def test_a_user_name_that_could_break_the_command_is_refused(keychain, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: 'a" -s "other')
    with pytest.raises(Error, match="user name"):
        claude.save(TOKEN, {})
    assert stored(keychain) == {}


def test_security_is_called_by_its_full_path():
    assert os.path.isabs(claude.SECURITY) and claude.SECURITY == "/usr/bin/security"
