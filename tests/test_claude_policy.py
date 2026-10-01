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
