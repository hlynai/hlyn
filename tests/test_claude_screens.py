# SPDX-License-Identifier: Apache-2.0
"""The two screens `hlyn claude` draws: what Claude Code gets, and what it was
refused. Pure layout, no confinement; tests/test_claude_ask.py drives the real
terminal."""

from __future__ import annotations

import io
import os
import re
import signal

import pytest

from hlyn import claude
from hlyn.policy import Policy
from hlyn.report import Denial, Report
from hlyn.term import Paint, fit, squeeze, width


class Tty(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


# --- term.py ---------------------------------------------------------------

@pytest.mark.parametrize(("text", "room", "want"), [
    ("short", 10, "short"),
    ("exactly10!", 10, "exactly10!"),
    ("~/projects/deep/file.txt", 20, "/Users/ka…p/file.txt"),
    ("abcdefghij", 5, "ab…ij"),
    ("abcdefghij", 3, "abc"),
])
def test_squeeze_cuts_the_middle_and_keeps_both_ends(text, room, want):
    got = squeeze(text, room)
    print(f"{text!r} in {room} -> {got!r}")
    assert got == want and len(got) <= room


@pytest.mark.parametrize("room", range(4, 40))
def test_squeeze_never_exceeds_the_room(room):
    assert len(squeeze("/a/very/long/path/to/some/file.txt", room)) <= room


def test_fit_lists_what_fits_then_counts_the_rest():
    items = ["api.anthropic.com", "platform.claude.com", "pypi.org"]
    for room, want in [(80, "api.anthropic.com, platform.claude.com, pypi.org"),
                       (47, "api.anthropic.com, platform.claude.com  +1 more"),
                       (30, "api.anthropic.com  +2 more")]:
        got = fit(items, room)
        print(room, "->", got)
        assert got == want and len(got) <= room


def test_fit_with_one_item_too_long_cuts_it_not_the_count():
    got = fit(["x" * 80, "b"], 30)
    print(got)
    assert got.endswith("  +1 more") and len(got) <= 30 and "…" in got


def test_paint_is_plain_off_a_terminal_and_with_no_color(monkeypatch):
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert Paint(Tty(False))("x", "red") == "x"
    assert Paint(Tty(True))("x", "red") == "\x1b[31mx\x1b[0m"
    monkeypatch.setenv("NO_COLOR", "1")
    assert Paint(Tty(True))("x", "red") == "x"


def test_width_is_kept_between_60_and_120_and_reads_columns_when_the_terminal_says_0(monkeypatch):
    # A pseudo-terminal nobody sized reports 0 columns; COLUMNS is the answer.
    monkeypatch.setenv("COLUMNS", "90")
    assert width(io.StringIO()) == 90
    monkeypatch.setenv("COLUMNS", "20")
    assert width(io.StringIO()) == 60
    monkeypatch.setenv("COLUMNS", "300")
    assert width(io.StringIO()) == 120
    master, slave = os.openpty()
    try:
        monkeypatch.setenv("COLUMNS", "77")
        with os.fdopen(os.dup(slave), "w") as unsized:
            assert os.get_terminal_size(unsized.fileno()).columns == 0
            assert width(unsized) == 77
    finally:
        os.close(master)
        os.close(slave)


# --- the end report ----------------------------------------------------------

def report(*denials: Denial) -> Report:
    book = Report(Policy(), env={}, which=lambda _name: None, cwd="/work")
    for denial in denials:
        book.add(denial)
    return book


def refused(kind, target, allow=""):
    """A refusal as the proxy hears one for a host, as the program does otherwise."""
    if kind == "net":
        return Denial(kind=kind, target=target, allow=allow, source="proxy", op="not-listed")
    return Denial(kind=kind, target=target, allow=allow, source="program")


def keychain() -> Denial:
    """Claude Code asking the keychain for a sign-in hlyn already gave it."""
    return Denial(kind="system", target="com.apple.SecurityServer", op="mach-lookup", by="claude",
                  pid=1, count=1, source="kernel")


def test_the_end_report_is_a_table_with_one_next_command():
    book = report(refused("net", "example.com:443", "--net example.com"),
                  refused("read", "/opt/data/file.csv", "--read /opt/data/file.csv"))
    text = book.brief(0, ["claude"], log="/home/x/claude.jsonl", stream=Tty(False))
    print(text)
    lines = text.splitlines()
    assert "Claude Code ended. hlyn refused it 2 things:" in text
    assert any(re.match(r"  ✗  network +example.com:443 +--net example.com$", ln) for ln in lines)
    assert any(re.match(r"  ✗  read +/opt/data/file.csv +--read /opt/data/file.csv$", ln) for ln in lines)
    assert "  next time:  hlyn claude --read /opt/data/file.csv --net example.com" in lines
    assert any("allow only hosts you recognise" in ln for ln in lines)
    assert all(len(ln) <= 100 for ln in lines)


def test_one_refusal_says_thing_not_things():
    text = report(refused("net", "example.com:443", "--net example.com")).brief(0, stream=Tty(False))
    assert "refused it 1 thing:" in text


@pytest.mark.parametrize("columns", [60, 80, 120])
def test_the_end_report_never_wraps(columns, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(columns))
    path = "/Users/someone/very/long/folder/name/that/goes/on/and/on/for/a/while/file.txt"
    text = report(refused("read", path, f"--read {path}"),
                  refused("net", "a-very-long-host-name.example.org:443",
                          "--net a-very-long-host-name.example.org")).brief(0, stream=Tty(False))
    print(text)
    longest = max(len(ln) for ln in text.splitlines())
    assert longest <= columns, longest
    assert "…" in text  # the paths were cut, not wrapped


def test_hidden_refusals_leave_the_report_but_not_the_data():
    book = report(keychain(), refused("net", "example.com:443", "--net example.com"))
    text = book.brief(0, hide=claude.expected, stream=Tty(False))
    print(text)
    assert "SecurityServer" not in text and "refused it 1 thing:" in text
    assert any("SecurityServer" in e.target for e in book.items()), "the record must keep it"
    assert "SecurityServer" in book.brief(0, stream=Tty(False)), "shown when not hidden"


def test_only_hidden_refusals_print_nothing():
    book = report(keychain())
    assert book.items(), "the keychain refusal is an entry; hiding is the report's doing"
    assert book.brief(0, hide=claude.expected, stream=Tty(False)) == ""


def test_a_crash_with_a_signal_is_said_plainly():
    book = report(refused("net", "example.com:443", "--net example.com"))
    text = book.brief(-signal.SIGTERM, stream=Tty(False))
    print(text)
    assert f"stopped (signal {int(signal.SIGTERM)})" in text


@pytest.mark.parametrize(("kind", "target", "hidden"), [
    ("system", "mach-lookup com.apple.SecurityServer", True),
    ("read", "/var/db/mds/messages/501/se_SecurityMessages", True),
    ("read", "~/.CFUserTextEncoding", True),
    ("read", "~/.ssh/id_rsa", False),
    ("read", "/var/db/mds/other", False),
    ("net", "example.com:443", False),
    ("write", "~/.CFUserTextEncoding", False),
])
def test_expected_hides_only_the_known_probes(kind, target, hidden):
    got = claude.expected(refused(kind, target))
    print(kind, target, "->", got)
    assert got is hidden


# --- the opening screen -------------------------------------------------------

def test_the_opening_screen_marks_what_it_can_and_cant_use(monkeypatch):
    monkeypatch.setenv("COLUMNS", "100")
    cwd = os.getcwd()
    base = Policy(read=(cwd,), write=(cwd, "/h/.claude"), net=("api.anthropic.com",), env=())
    plan = Policy(read=(cwd, "/h/docs"), write=(cwd, "/h/.claude"),
                  net=("api.anthropic.com", "pypi.org:443"), env=())
    text = claude.describe(plan, base, (True, "from the keychain"), [], [], "/h/claude.jsonl",
                           Tty(False))
    print(text)
    lines = text.splitlines()
    assert lines[0] == "hlyn claude: Claude Code, confined"
    assert any(re.match(r"  ✓  network +api.anthropic.com, pypi.org$", ln) for ln in lines)
    assert any(re.match(r"  ✓  also +/h/docs +read$", ln) for ln in lines)
    assert any(re.match(r"  ✓  sign-in +from the keychain$", ln) for ln in lines)
    assert any(ln.startswith("  ✗  everything else") for ln in lines)
    assert max(len(ln) for ln in lines) <= 100


def test_an_unsigned_start_is_marked_with_a_bang():
    cwd = os.getcwd()
    base = plan = Policy(read=(cwd,), write=(cwd,), net=("api.anthropic.com",), env=())
    text = claude.describe(plan, base, (False, "not signed in: hlyn claude --login"), [], [], None,
                           Tty(False))
    print(text)
    assert re.search(r"  !  sign-in +not signed in: hlyn claude --login", text)


@pytest.mark.parametrize("columns", [60, 72, 120])
def test_the_opening_screen_never_wraps(columns, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(columns))
    cwd = os.getcwd()
    hosts = tuple(f"host{n}.some-long-domain.example.org" for n in range(8))
    base = Policy(read=(cwd,), write=(cwd, "/h/.claude"), net=("api.anthropic.com",), env=())
    plan = Policy(read=(cwd, *[f"/h/{'deep/' * 9}f{n}" for n in range(4)]), write=(cwd, "/h/.claude"),
                  net=("api.anthropic.com", *hosts), env=())
    text = claude.describe(plan, base, (True, "from ANTHROPIC_API_KEY"), ["./a" * 30, "./.env"],
                           ["./.git/hooks"], "/h/claude.jsonl", Tty(False))
    print(text)
    assert max(len(ln) for ln in text.splitlines()) <= columns
    assert "more" in text


# --- housekeeping Claude Code keeps outside its state folder -------------------

def test_its_housekeeping_folders_are_granted_when_they_exist(tmp_path, monkeypatch):
    home, work = tmp_path / "home", tmp_path / "work"
    (home / ".local/state/claude").mkdir(parents=True)
    (home / ("Library/Caches" if os.uname().sysname == "Darwin" else ".cache")).mkdir(parents=True)
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    env: dict[str, str] = {}
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    keeping = [os.path.expanduser(p) for p in claude.KEEPING]
    print(keeping, plan.write)
    assert len(keeping) == 2
    for path in keeping:
        assert os.path.isdir(path) and path in plan.write
        assert oct(os.stat(path).st_mode & 0o777) == "0o700"


def test_housekeeping_is_not_made_where_the_parent_is_missing(tmp_path, monkeypatch):
    home, work = tmp_path / "home", tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    env: dict[str, str] = {}
    plan = claude.policy("/opt/claude/claude", env, claude.prepare(env))
    assert not (home / ".local").exists()
    assert not any(os.path.expanduser(p) in plan.write for p in claude.KEEPING)


@pytest.mark.parametrize("columns", [60, 80, 120])
def test_the_home_folder_warning_wraps_to_the_window_and_keeps_every_word(columns, monkeypatch, tmp_path):
    # Found on Linux, where the folder was `/w` and the warning ran 84 columns.
    monkeypatch.setenv("COLUMNS", str(columns))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    base = plan = Policy(read=(str(tmp_path),), write=(str(tmp_path),), net=("api.anthropic.com",), env=())
    text = claude.describe(plan, base, (True, "from ANTHROPIC_API_KEY"), [], [], None, Tty(False))
    print(text)
    lines = text.splitlines()
    assert max(len(ln) for ln in lines) <= columns
    blank = lines.index("", 2)
    warning = " ".join(ln.strip().removeprefix("!").strip() for ln in lines[2:blank])
    assert "home folder" in warning and "Claude Code could read and change" in warning
    assert warning.endswith("Start it inside a project folder instead."), warning
