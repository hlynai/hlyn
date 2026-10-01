# SPDX-License-Identifier: Apache-2.0
"""`hlyn claude` at a terminal: say what Claude Code gets, then ask.

Driven on a pseudo-terminal, the way a person types at it, with a stand-in
`claude` that only says it ran, and a throwaway home folder (the record goes
to its ~/Library/Logs or ~/.local/state, never the real one).
"""

from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import sys
import time

import pytest
from conftest import SRC

pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")


@pytest.fixture
def place(tmp_path):
    """A home, a project inside it, and a stand-in `claude` on PATH."""
    home = tmp_path / "home"
    work = home / "project"
    (work / "src").mkdir(parents=True)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    fake = bin_ / "claude"
    fake.write_text("#!/bin/sh\necho \"CLAUDE RAN $*\"\n")
    fake.chmod(0o755)
    env = {
        "HOME": str(home), "PATH": f"{bin_}:/usr/bin:/bin", "TERM": "xterm-256color",
        "PYTHONPATH": SRC, "ANTHROPIC_API_KEY": "sk-ant-not-a-real-key", "COLUMNS": "100",
    }
    if os.environ.get("HLYN_SHIM"):
        env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
    return home, work, env


def typed(where, env, *answers, flags=()):
    """Run `hlyn claude` on a terminal in `where` and type each answer after a
    pause. Returns (exit status, what the terminal showed)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(where)
        os.execve(sys.executable, [sys.executable, "-m", "hlyn.cli", "claude", *flags], env)  # noqa: S606
    seen = bytearray()

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                seen.extend(data)
        return True

    for answer in answers:
        # Wait for the prompt rather than a fixed time: the policy is
        # resolved first, and that takes longer on a busy machine.
        end = time.time() + 30
        asked = seen.count(b"  > ")
        while seen.count(b"  > ") == asked and time.time() < end and pump(0.2):
            pass
        try:
            os.write(fd, answer.encode() + b"\r")
        except OSError:
            break
    pump(5)
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    shown = seen.decode("utf-8", "replace").replace("\r", "")
    return os.waitstatus_to_exitcode(status), re.sub(r"\x1b\[[0-9;]*m", "", shown)  # colour is not the words


def test_it_says_what_claude_code_gets_and_no_stops_it(place):
    _home, work, env = place
    code, screen = typed(work, env, "n")
    print(screen)
    assert "hlyn claude: Claude Code, confined" in screen
    assert "this folder" in screen and "~/project" in screen
    assert "api.anthropic.com, platform.claude.com" in screen
    assert "from ANTHROPIC_API_KEY" in screen
    assert "hlyn: not started." in screen and "CLAUDE RAN" not in screen
    assert code == 0


def test_yes_starts_it(place):
    _home, work, env = place
    code, screen = typed(work, env, "y")
    print(screen)
    assert "CLAUDE RAN" in screen and code == 0


def test_enter_starts_it_in_a_project(place):
    _home, work, env = place
    _code, screen = typed(work, env, "")
    print(screen)
    assert "Enter: yes" in screen and "CLAUDE RAN" in screen


def test_access_added_at_the_question_is_shown_then_used(place):
    home, work, env = place
    (home / "docs").mkdir()
    _code, screen = typed(work, env, "--read ~/docs --net pypi.org", "y")
    print(screen)
    second = screen.split("Start Claude Code?")[1]
    assert "~/docs" in second and "read" in second and "pypi.org" in second
    assert "CLAUDE RAN" in screen


def test_a_mistyped_flag_says_so_and_asks_again(place):
    _home, work, env = place
    _code, screen = typed(work, env, "--reed ~/docs", "n")
    print(screen)
    assert "can't add --reed" in screen
    # The mistake is answered at the prompt: the table and the examples are not drawn again.
    assert screen.count("Start Claude Code?") == 1 and screen.count("hlyn claude: Claude Code, confined") == 1
    assert screen.count("\n  > ") == 2 and "CLAUDE RAN" not in screen


def test_the_examples_come_from_this_machine(place):
    home, work, env = place
    (home / "Documents").mkdir()
    _code, screen = typed(work, env, "n")
    print(screen)
    assert "--read ~/Documents" in screen and "let it read that folder" in screen
    assert "--net github.com" in screen and "--write ./dist" in screen
    assert "../other-project" not in screen
    (home / "Documents").rmdir()
    _code, none = typed(work, env, "n")
    assert "--read ../other-project" in none and "~/Documents" not in none


def test_flags_that_work_draw_the_table_again_with_them(place):
    home, work, env = place
    (home / "docs").mkdir()
    _code, screen = typed(work, env, "--read ~/docs", "n")
    print(screen)
    assert screen.count("hlyn claude: Claude Code, confined") == 2
    assert screen.count("Start Claude Code?") == 2


def test_something_that_is_neither_asks_again(place):
    _home, work, env = place
    _code, screen = typed(work, env, "maybe", "n")
    print(screen)
    assert "type y to start, n to stop" in screen and "CLAUDE RAN" not in screen


def test_in_the_home_folder_it_warns_and_enter_means_no(place):
    # The folder it starts in is granted whole. The real run that prompted
    # this was started in ~, and Claude Code got all of it.
    home, _work, env = place
    _code, screen = typed(home, env, "")
    print(screen)
    assert "your home folder" in screen
    assert "Enter: no" in screen and "hlyn: not started." in screen and "CLAUDE RAN" not in screen


def test_risks_are_listed_last_and_short(place):
    _home, work, env = place
    (work / ".env").write_text("KEY=1\n")
    (work / ".git" / "hooks").mkdir(parents=True)
    _code, screen = typed(work, env, "n")
    print(screen)
    assert re.search(r"│ ! │ secret +│ \./\.env +│ readable", screen)
    assert re.search(r"│ ! │ runs later +│ \./\.git/hooks +│ writable", screen)
    assert "runs later: what's written there runs outside hlyn" in screen
    # The long warnings are not printed as well.
    assert "Grant only the folders it needs" not in screen
    assert "Whatever it writes there runs unconfined" not in screen


def test_its_own_state_folders_secrets_are_not_listed(place):
    # A sign-in file or a plugin's .npmrc in ~/.claude is granted on purpose,
    # the way `later.found` leaves out the state folder.
    home, work, env = place
    (home / ".claude" / "plugins").mkdir(parents=True)
    (home / ".claude" / "plugins" / ".npmrc").write_text("//registry/:_authToken=x\n")
    _code, screen = typed(work, env, "n")
    print(screen)
    assert ".npmrc" not in screen


def test_the_record_goes_to_a_file_not_the_screen(place):
    home, work, env = place
    _code, screen = typed(work, env, "y")
    print(screen)
    assert '{"t":' not in screen, "the record was drawn on the terminal"
    record = (home / "Library/Logs/hlyn/claude.jsonl" if sys.platform == "darwin"
              else home / ".local/state/hlyn/claude.jsonl")
    assert record.exists() and '"kind": "seal"' in record.read_text()
    assert "record of what it's refused: ~/" in screen


def test_yes_flag_skips_the_question(place):
    _home, work, env = place
    _code, screen = typed(work, env, flags=("-y",))
    print(screen)
    assert "Start Claude Code?" not in screen and "CLAUDE RAN" in screen


def test_without_a_terminal_it_does_not_ask(place):
    # A script: no question to answer, so none is asked; the warnings are
    # printed as they always were.
    _home, work, env = place
    (work / ".env").write_text("KEY=1\n")
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "claude"], cwd=work, env=env,
                          capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, check=False)
    print(done.stdout, done.stderr)
    assert "Start Claude Code?" not in done.stderr
    assert "CLAUDE RAN" in done.stdout
    assert "Grant only the folders it needs" in done.stderr


def test_end_of_input_never_starts_it(place):
    # Ctrl-D at the question: not a yes.
    _home, work, env = place
    _code, screen = typed(work, env, "\x04")
    print(screen)
    assert "CLAUDE RAN" not in screen
