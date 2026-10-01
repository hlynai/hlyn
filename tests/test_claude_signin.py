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


def test_login_keeps_what_is_pasted_when_the_screen_has_no_heading_it_knows(keychain, setup_token,
                                                                            monkeypatch, capsys):
    # This stand-in prints "Your token: ..." on one line, not the real screen,
    # so the token isn't read off it; what's pasted is kept.
    monkeypatch.setattr("getpass.getpass", lambda prompt: f"  {TOKEN}\n")
    with pytest.raises(Error, match="ended without making a token"):
        claude.login(setup_token, {})
    assert stored(keychain) == {}


@pytest.mark.parametrize("pasted", ["", "yes", "Your token: sk-ant-oat01-abcdefghijklmnop", "sk-ant-é" * 5])
def test_login_refuses_a_paste_that_is_not_a_token_and_keeps_nothing(keychain, setup_drawing,
                                                                     monkeypatch, pasted):
    # The screen has a token but can't be read (boxed), so it asks; what's
    # pasted is checked before anything is kept.
    monkeypatch.setenv("FAKE_MODE", "boxed")
    monkeypatch.setattr("getpass.getpass", lambda prompt: pasted)
    with pytest.raises(Error, match="doesn't look like a token"):
        claude.login(setup_drawing, {})
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


# ---------------------------------------------------------------------------
# reading the token off `claude setup-token`'s screen
# ---------------------------------------------------------------------------
#
# Modelled on what Claude Code 2.1.269 draws (seen in a screenshot of a real
# run, 2026-10-01): a heading, a blank line, the token wrapped to the width
# with one space of indent, a blank line, then "Store this token securely".

LONG = "sk-ant-oat01-" + "Ab3_x-Z9" * 12  # a fake, the length of a real one


def drawn(token=LONG, width=80, indent=" ", colour=True):
    """The token's part of the screen, as setup-token draws it."""
    on, off = ("\x1b[38;5;220m", "\x1b[39m") if colour else ("", "")
    body = width - len(indent)
    lines = [token[i:i + body] for i in range(0, len(token), body)]
    shown = "\r\n".join(f"{indent}{on}{line}{off}" for line in lines)
    return (f"\r\n{indent}\x1b[1mYour OAuth token (valid for 1 year):\x1b[22m\r\n\r\n{shown}\r\n\r\n"
            f"{indent}\x1b[2mStore this token securely. You won't be able to see it again.\x1b[22m\r\n")


@pytest.mark.parametrize("width", [200, 80, 41, 20, 9])
def test_the_token_is_read_whatever_the_width(width):
    # At 9 columns even "sk-ant-" is split across lines.
    screen = drawn(width=width).encode()
    assert claude.scrape(screen) == LONG


def test_the_last_frame_wins_when_the_screen_is_redrawn():
    # A full-screen program redraws by moving the cursor up and erasing; an
    # earlier frame may hold a half-drawn token.
    half = drawn(token=LONG[:50]).replace("Store this token", "")
    redraw = "\x1b[2K\x1b[1A" * 8
    assert claude.scrape((half + redraw + drawn()).encode()) == LONG


def test_cursor_movement_and_links_inside_the_token_are_ignored():
    split = LONG[:30] + "\x1b[1C" + "\x1b]8;;https://x.example\x07" + LONG[30:] + "\x1b]8;;\x07"
    screen = drawn(colour=False).replace(LONG, split)
    assert claude.scrape(screen.encode()) == LONG


@pytest.mark.parametrize(("why", "screen"), [
    ("nothing drawn", ""),
    ("cancelled before a token", "\x1b[1mSign in to Claude\x1b[22m\r\nPress Esc to cancel\r\n"),
    ("no line after the token", drawn().split("Store this token")[0]),
    ("a box drawn around it", drawn().replace("\r\n ", "\r\n│ ")),
    ("cut short with an ellipsis", drawn(token=LONG[:60] + "…")),
    ("too short to be a token", drawn(token="sk-ant-oat01-short")),  # noqa: S106 - a fake
    ("two tokens run together", drawn(token=LONG + LONG)),
])
def test_anything_that_is_not_exactly_one_token_reads_as_none(why, screen):
    print(why)
    assert claude.scrape(screen.encode()) is None


FAKE_CLAUDE = r'''#!{python}
"""A stand-in `claude setup-token` that draws like the real one, at the width
of its own terminal, and says what width it saw."""
import os, sys
assert sys.argv[1:] == ["setup-token"], sys.argv
mode = os.environ.get("FAKE_MODE", "token")
width = os.get_terminal_size(1).columns
print(f"drawn at {{width}} columns", flush=True)
if mode == "cancel":
    print("Press Esc to cancel"); sys.exit(1)
token = {token!r}
body = width - 1
for i in range(0, len(token), body) if mode == "token" else []:
    pass
lines = [token[i:i + body] for i in range(0, len(token), body)]
border = "│" if mode == "boxed" else " "
print("\x1b[1mYour OAuth token (valid for 1 year):\x1b[22m\n")
print("\n".join(f"{{border}}\x1b[33m{{line}}\x1b[39m" for line in lines))
print("\nStore this token securely. You won't be able to see it again.")
'''


@pytest.fixture
def setup_drawing(tmp_path, monkeypatch):
    fake = tmp_path / "claude-draws"
    fake.write_text(FAKE_CLAUDE.format(python=sys.executable, token=LONG))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    # The size hlyn gives the new terminal comes from this one; under pytest
    # that is COLUMNS.
    monkeypatch.setenv("COLUMNS", "57")
    monkeypatch.setenv("LINES", "20")
    return str(fake)


def test_login_reads_the_token_off_the_screen_without_asking(keychain, setup_drawing, monkeypatch, capfd):
    def ask(prompt):
        raise AssertionError("asked to paste although the token was on the screen")
    monkeypatch.setattr("getpass.getpass", ask)
    said = claude.login(setup_drawing, {})
    out = capfd.readouterr()
    print(out.out[-400:], out.err, said, sep="\n")
    assert "drawn at 57 columns" in out.out, "the new terminal didn't get this one's size"
    assert claude.saved({}) == LONG
    assert f"({LONG[:16]}...{LONG[-4:]})" in out.err


def test_login_asks_to_paste_when_the_screen_cannot_be_read(keychain, setup_drawing, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "boxed")
    asked = []
    monkeypatch.setattr("getpass.getpass", lambda prompt: asked.append(prompt) or LONG)
    claude.login(setup_drawing, {})
    print(asked)
    assert asked and "couldn't read the token from the screen" in asked[0]
    assert claude.saved({}) == LONG


def test_a_cancelled_setup_saves_nothing_and_asks_nothing(keychain, setup_drawing, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "cancel")
    monkeypatch.setattr("getpass.getpass", lambda prompt: pytest.fail("asked to paste after a cancel"))
    with pytest.raises(Error, match="ended without making a token"):
        claude.login(setup_drawing, {})
    assert stored(keychain) == {}
