# SPDX-License-Identifier: Apache-2.0
"""The policy `hlyn claude` builds, without running Claude Code.

tests/test_claude.py runs the real thing; these pin each grant's shape, so a
change to one is a decision rather than an accident.
"""

from __future__ import annotations

import argparse
import os

import pytest

from hlyn import claude, cli
from hlyn.error import Error


@pytest.fixture
def home(tmp_path, monkeypatch):
    home, work = tmp_path / "home", tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    return home


@pytest.mark.parametrize(("url", "entry"), [
    (None, "api.anthropic.com"),
    ("https://gateway.example.com", "gateway.example.com:443"),
    ("https://gateway.example.com:8443/v1", "gateway.example.com:8443"),
    ("http://127.0.0.1:4000", "localhost:4000"),
    ("http://localhost:4000/", "localhost:4000"),
    ("http://10.0.0.5:8080", "10.0.0.5:8080"),
])
def test_the_model_host_follows_anthropic_base_url(url, entry):
    env = {"ANTHROPIC_BASE_URL": url} if url else {}
    print(url, "->", claude._model(env))
    assert claude._model(env) == entry


@pytest.mark.parametrize("url", ["ftp://example.com", "example.com", "https://"])
def test_a_base_url_hlyn_cant_allow_says_so(url):
    with pytest.raises(Error, match="ANTHROPIC_BASE_URL"):
        claude._model({"ANTHROPIC_BASE_URL": url})


def test_the_grants(home):
    (home / ".claude.json").write_text("{}")
    env = {"ANTHROPIC_API_KEY": "k", "CLAUDE_CODE_X": "1", "OPENAI_API_KEY": "no", "SHELL": "/bin/zsh"}
    box = claude.prepare(env)
    plan = claude.policy("/opt/claude/bin/claude", env, box)
    print(plan)
    cwd = os.getcwd()
    # The terminal is writable so the shell Claude Code starts can use it for
    # job control; typing into it stays refused by both kernels (TIOCSTI).
    assert set(plan.write) == {cwd, str(home / ".claude"), "/dev/tty"}
    assert "/dev/tty" in plan.read
    # The installation by both names: the link, and what it points at.
    assert cwd in plan.read and "/opt/claude/bin" in plan.read
    assert str(home / ".claude.json") in plan.read and str(home / ".claude.json") not in plan.write
    assert plan.exec is True
    assert [str(rule) for rule in plan.net] == ["api.anthropic.com:443", "platform.claude.com:443"]
    assert set(plan.env) == {"ANTHROPIC_API_KEY", "CLAUDE_CODE_X", "SHELL", "CLAUDE_CODE_TMPDIR",
                             "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "TMPPREFIX",
                             "CLAUDE_CODE_NO_FLICKER",  # claude._asks_renderer
                             *(["xcrun_db"] if os.uname().sysname == "Darwin" else [])}
    assert plan.tmp == box == env["CLAUDE_CODE_TMPDIR"]
    assert oct((home / ".claude").stat().st_mode & 0o777) == "0o700"


def test_claude_config_dir_replaces_both_state_paths(home, tmp_path):
    (home / ".claude.json").write_text("{}")
    env = {"CLAUDE_CONFIG_DIR": str(tmp_path / "state")}
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    assert str(tmp_path / "state") in plan.write
    assert str(home / ".claude.json") not in plan.read and str(home / ".claude") not in plan.write


def test_traffic_that_isnt_the_model_is_off_unless_the_user_said(home):
    mine = {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "0"}
    claude.prepare(mine)
    fresh: dict[str, str] = {}
    claude.prepare(fresh)
    assert mine["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "0"
    assert fresh["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"


def _args(**flags):
    base = dict(read=[], write=[], exec=[], exec_any=False, net=[], net_any=False, env=[],
                env_any=False, no_tmp=False, no_log=False, log=None)
    return argparse.Namespace(**{**base, **flags})


def test_flags_add_to_what_claude_gets(home):
    env: dict[str, str] = {}
    start = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    more = cli._policy(_args(net=["pypi.org"], read=["/srv/docs"]), start)
    print([str(rule) for rule in more.net], set(more.read) - set(start.read))
    assert {str(rule) for rule in more.net} == {
        "api.anthropic.com:443", "platform.claude.com:443", "pypi.org:443"}
    assert set(more.read) - set(start.read) == {"/srv/docs"}
    assert cli._policy(_args(net_any=True), start).net is True


@pytest.mark.parametrize(("platform", "env", "creds", "noted"), [
    ("darwin", {}, False, True),
    ("darwin", {"ANTHROPIC_API_KEY": "k"}, False, False),
    ("darwin", {"CLAUDE_CODE_OAUTH_TOKEN": "t"}, False, False),
    ("darwin", {"CLAUDE_CODE_USE_BEDROCK": "1"}, False, False),
    ("darwin", {}, True, False),
    ("linux", {}, False, False),
])
def test_the_macos_sign_in_note(home, monkeypatch, platform, env, creds, noted, tmp_path):
    monkeypatch.setattr(claude.sys, "platform", platform)
    # Never the real keychain: with no `security` here, nothing is kept.
    # tests/test_claude_signin.py covers a kept token.
    monkeypatch.setattr(claude, "SECURITY", str(tmp_path / "no-security-here"))
    if creds:
        (home / ".claude").mkdir()
        (home / ".claude" / ".credentials.json").write_text("{}")
    note = claude.signin(env)
    print(platform, env, creds, "->", note)
    assert (note is not None) == noted
    if noted:
        assert "hlyn claude --login" in note


@pytest.mark.parametrize("where", ["home", "root", "keys"])
def test_a_claude_config_dir_that_names_home_root_or_keys_is_refused(home, where):
    # CLAUDE_CONFIG_DIR comes from the environment and is granted read and
    # write; pointed at ~ it would hand Claude Code the whole home folder.
    target = {"home": home, "root": "/", "keys": home / ".ssh"}[where]
    if where == "keys":
        target.mkdir()
    env = {"CLAUDE_CONFIG_DIR": str(target)}
    with pytest.raises(Error, match="CLAUDE_CONFIG_DIR") as error:
        claude.policy("/opt/claude/claude", env, claude.prepare(env))
    print(error.value)


def test_a_claude_config_dir_of_its_own_is_still_used(home, tmp_path):
    own = tmp_path / "claude-state"
    own.mkdir()
    env = {"CLAUDE_CONFIG_DIR": str(own)}
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    print(plan.write)
    assert str(own) in plan.write


def test_gits_credential_store_stays_closed_while_its_config_is_read(home):
    # git keeps passwords in ~/.config/git/credentials as well as
    # ~/.git-credentials, so the files git reads there are granted by name, not the
    # folder.
    from hlyn.policy import under

    config = home / ".config" / "git"
    config.mkdir(parents=True)
    (config / "config").write_text("[user]\n")
    (config / "credentials").write_text("https://u:token@example.com\n")
    env: dict[str, str] = {}
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    reads = plan.reads()
    covers = lambda path: [root for root in reads if under(str(path), root)]  # noqa: E731
    print("config:", covers(config / "config"), "credentials:", covers(config / "credentials"))
    assert covers(config / "config")  # the control: git still reads its config
    assert not covers(config / "credentials")


def test_a_claude_binary_kept_in_the_home_folder_grants_the_file_not_the_home(home):
    # The installation's folder is granted so Claude Code can list it; when
    # that folder is the home folder, only the binary is.
    binary = home / "claude"
    binary.write_text("#!/bin/sh\n")
    env: dict[str, str] = {}
    plan = claude.policy(str(binary), env, claude.prepare(env))
    print(plan.read)
    assert str(home) not in plan.read and str(binary) in plan.read
    usual = claude.policy("/opt/claude/bin/claude", env, claude.prepare(env))
    assert "/opt/claude/bin" in usual.read  # the control: an ordinary install keeps its folder


def test_the_record_moves_out_of_reach_when_claude_code_may_write_its_usual_folder(home):
    # Started in the home folder, Claude Code may write ~/Library/Logs (or
    # ~/.local/state), where it could replace the record; it goes elsewhere.
    from hlyn.policy import under

    usual = claude.record(())
    moved = claude.record((str(home),))
    print("usual:", usual, "| home writable:", moved)
    assert under(os.path.realpath(usual), os.path.realpath(home))
    assert not under(os.path.realpath(moved), os.path.realpath(home))
    claude.Policy(log=moved, write=[str(home)])  # accepted: out of reach
