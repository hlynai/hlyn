# SPDX-License-Identifier: Apache-2.0
"""The agent can learn why it was refused, while it runs: `$HLYN_BLOCKED`.

hlyn's unconfined parent hears each refusal live and keeps a short list in
the agent's scratch folder (report.Blocked). These tests run the real command
line with a confined Python agent that makes a refused call, then reads the
file the variable names and prints it. What is checked is what the agent
printed, so a file that is empty, wrong or absent fails.

On macOS the refusal reaches hlyn through the system log, a moment later and
with a few percent lost (tests/test_report_run.py `heard`), so the agent waits
for its line, and a run that lost the one refusal it needs is run again.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import SRC
from test_report_run import agent, heard, here, hlyn

pytestmark = here

# The agent: one refused read, then wait for hlyn to list it, and print the
# list and how long that took. argv[1] is the file to read; argv[2] the word
# to wait for in the list.
WAIT = """
    import os, sys, time
    where = os.environ.get("HLYN_BLOCKED")
    print("HLYN_BLOCKED=" + str(where))
    started = time.time()
    try:
        open(sys.argv[1]).read()
        print("read worked")
    except OSError as exc:
        print("refused:", exc.errno)
    text = ""
    while where and time.time() - started < 15:
        text = open(where).read()
        if sys.argv[2] in text:
            break
        time.sleep(0.001)
    print("ms: %.1f" % ((time.time() - started) * 1000))
    print("LIST START")
    print(text, end="")
    print("LIST END")
"""


def listed(done: subprocess.CompletedProcess) -> list[str]:
    """The lines the agent printed between its markers."""
    out = done.stdout.split("LIST START\n", 1)[1].split("LIST END", 1)[0]
    return out.splitlines()


def blocked(tmp_path, target: str, word: str, *flags: str, body: str = WAIT) -> subprocess.CompletedProcess:
    script = agent(tmp_path, body)
    argv = ["run", "--no-log", "--read", script, *flags, "--", sys.executable, script, target, word]
    return heard(lambda: hlyn(*argv),
                 lambda done: "LIST START" in done.stdout and word in done.stdout.split("LIST START", 1)[1])


@pytest.fixture
def outside(tmp_path_factory):
    box = tmp_path_factory.mktemp("outside")
    (box / "data.txt").write_text("x")
    return box


def test_a_refused_read_is_listed_with_the_flag_that_allows_it(tmp_path, outside):
    target = str(outside / "data.txt")
    done = blocked(tmp_path, target, "data.txt")
    lines = listed(done)
    print("what the agent read:", lines)
    assert "refused:" in done.stdout and "read worked" not in done.stdout
    assert "HLYN_BLOCKED=" in done.stdout and "HLYN_BLOCKED=None" not in done.stdout
    # The two header lines, then exactly the one refusal made.
    rows = [line for line in lines if not line.startswith("#")]
    assert len(rows) == 1
    kind_and_path, _, right = rows[0].partition("  ->  ")
    path = kind_and_path.removeprefix("read  ")
    assert kind_and_path.startswith("read  ") and os.path.realpath(path) == os.path.realpath(target)
    assert right == f"allow with --read {path}"
    assert lines[0].startswith("# hlyn refused these")
    # And the person still gets their report.
    assert "allow with" in done.stderr or "--read" in done.stderr


def test_a_credential_is_kept_closed_with_no_flag(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    key = home / ".ssh" / "id_ed25519"
    key.write_text("PRIVATE-KEY-CANARY\n")
    script = agent(tmp_path, WAIT)
    argv = ["run", "--no-log", "--read", script, "--", sys.executable, script, str(key), "id_ed25519"]
    done = heard(lambda: hlyn(*argv, env={"HOME": str(home)}),
                 lambda d: "LIST START" in d.stdout and "id_ed25519" in d.stdout.split("LIST START", 1)[1])
    # Other refusals may be listed too (macOS: the home folder's encoding hint).
    lines = [line for line in listed(done) if "id_ed25519" in line]
    print("what the agent read:", listed(done))
    assert len(lines) == 1 and lines[0].endswith("id_ed25519  ->  kept closed: a credential")
    assert "--read" not in "\n".join(lines)
    assert "PRIVATE-KEY-CANARY" not in done.stdout


def test_no_report_means_no_file_and_no_variable(tmp_path, outside):
    script = agent(tmp_path, """
        import os, sys
        print("variable:", os.environ.get("HLYN_BLOCKED"))
        try:
            open(sys.argv[1]).read()
        except OSError as exc:
            print("refused:", exc.errno)
        print("scratch:", sorted(os.listdir(os.environ["TMPDIR"])))
    """)
    done = hlyn("run", "--no-log", "--no-report", "--read", script, "--", sys.executable, script,
                str(outside / "data.txt"))
    assert "variable: None" in done.stdout
    assert "refused:" in done.stdout
    assert "scratch: []" in done.stdout


def test_the_list_stops_at_its_cap_and_says_so(tmp_path, outside):
    for number in range(90):
        (outside / f"f{number:02}.txt").write_text("x")
    body = """
        import os, sys, time
        where = os.environ["HLYN_BLOCKED"]
        started = time.time()
        for number in range(90):
            try:
                open(os.path.join(sys.argv[1], "f%02d.txt" % number)).read()
            except OSError:
                pass
        text = ""
        while time.time() - started < 30 and "more were refused" not in text:
            text = open(where).read()
            time.sleep(0.05)
        print("LIST START")
        print(text, end="")
        print("LIST END")
    """
    script = agent(tmp_path, body)
    argv = ["run", "--no-log", "--read", script, "--", sys.executable, script, str(outside)]
    done = heard(lambda: hlyn(*argv), lambda d: "more were refused" in d.stdout)
    lines = listed(done)
    rows = [line for line in lines if line.startswith("read")]
    print(len(rows), "rows;", lines[-1])
    assert len(rows) == 50
    assert lines[-1] == "# 50 listed; more were refused. The person's report lists them all."


def test_an_agent_that_replaces_the_file_with_a_link_makes_hlyn_write_nothing_through_it(tmp_path, outside):
    """hlyn holds one descriptor, opened before the agent exists, and never
    opens the path again: the agent's link, to a file it could read but
    hlyn's parent can write, stays as it was."""
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched\n")
    body = """
        import os, sys, time
        where = os.environ["HLYN_BLOCKED"]
        os.unlink(where)
        os.symlink(sys.argv[2], where)
        try:
            open(sys.argv[1]).read()
        except OSError as exc:
            print("refused:", exc.errno)
        time.sleep(3)
        print("done")
    """
    script = agent(tmp_path, body)
    done = hlyn("run", "--no-log", "--read", script, "--", sys.executable, script,
                str(outside / "data.txt"), str(victim))
    assert "refused:" in done.stdout and "done" in done.stdout
    assert victim.read_text() == "untouched\n"


def test_an_old_file_in_a_kept_scratch_folder_is_unlinked_not_followed(tmp_path):
    """A scratch folder an earlier agent had: its link in the file's place
    must not be truncated or written through when the next run starts."""
    sys.path.insert(0, SRC)
    from hlyn.report import BLOCKED, Blocked

    victim = tmp_path / "victim.txt"
    victim.write_text("untouched\n")
    folder = tmp_path / "scratch"
    folder.mkdir()
    os.symlink(victim, folder / BLOCKED)
    made = Blocked.start(str(folder))
    assert made is not None
    made.close()
    print("victim:", repr(victim.read_text()), "| list:", repr((folder / BLOCKED).read_text()))
    assert victim.read_text() == "untouched\n"
    assert not os.path.islink(folder / BLOCKED)
    assert (folder / BLOCKED).read_text().startswith("# hlyn refused these")


def test_how_long_a_refusal_takes_to_reach_the_file(tmp_path, outside):
    """Measured, not asserted tightly: the agent's own clock from the refused
    call to the line being readable. Bounded loosely so a slow machine passes
    and a missing line (15 s wait in the agent) fails."""
    times = []
    for number in range(5):
        (outside / f"t{number}.txt").write_text("x")
        done = blocked(tmp_path, str(outside / f"t{number}.txt"), f"t{number}.txt")
        ms = float(next(line for line in done.stdout.splitlines() if line.startswith("ms:")).split()[1])
        times.append(ms)
    print("ms from the refused call to the line:", times)
    assert all(ms < 10_000 for ms in times)


def test_the_system_prompt_line_is_one_short_instruction():
    sys.path.insert(0, SRC)
    from hlyn import claude

    full = claude.hinted(["/bin/claude", "-p", "go"], "/tmp/x/hlyn-blocked.txt")
    assert full[:2] == ["/bin/claude", "--append-system-prompt"]
    assert full[3:] == ["-p", "go"]
    assert "/tmp/x/hlyn-blocked.txt" in full[2] and "flag" in full[2] and len(full[2]) < 400
    # The person's own appended prompt is left alone.
    own = ["/bin/claude", "--append-system-prompt", "mine"]
    assert claude.hinted(own, "/tmp/x/hlyn-blocked.txt") == own


# -- hlyn claude, with the real Claude Code and a scripted model -------------

import test_claude  # noqa: E402
from test_claude import CANARY, session  # noqa: E402

place = test_claude.place  # the throwaway home and project fixture


@pytest.mark.skipif(test_claude.CLAUDE is None, reason="Claude Code (claude) is not installed")
def test_claude_code_is_told_where_to_look_and_the_file_says_why_and_which_flag(place):
    """The model's request carries the one-line hint, and a Bash call that
    reads the file it names, after a refused Read, returns the path and the
    flag. The key is a credential: its line has no flag."""
    home, work = place
    other = home / "notes.txt"  # outside the project and Claude Code's folders
    other.write_text("notes\n")
    key = str(home / ".ssh" / "id_ed25519")
    steps = [
        # Through `cat`, not Claude Code's own Read tool: on Linux Claude Code is a static
        # binary whose own refusals nothing hears (README, "Reports are not complete"),
        # while the programs it starts are heard on both systems.
        ("Bash", {"command": f"cat {other}"}),
        ("Bash", {"command": f"cat {key}"}),
        # The refusal reaches the file a moment later on macOS.
        ("Bash", {"command": 'for i in $(seq 100); do grep -q id_ed25519 "$HLYN_BLOCKED" && break; '
                             'sleep 0.1; done; cat "$HLYN_BLOCKED"'}),
    ]
    done, model = session(steps, home, work)
    results = model.results()
    print("exit", done.returncode, "\nresults:", results, "\nstderr:", done.stderr[-1500:])
    assert done.returncode == 0 and len(results) == len(steps)
    first, second, listing = results
    assert first[0] and second[0], "the reads weren't refused"
    sent = json.dumps(model.requests()[0])
    assert "also $HLYN_BLOCKED" in sent and "hlyn-blocked.txt" in sent, "the system prompt has no hint"
    text = listing[1]
    # The report spells /private/var as /var: compare what the path means.
    row = next(line for line in text.splitlines() if line.endswith("notes.txt") or "notes.txt  ->" in line)
    left, _, right = row.partition("  ->  ")
    path = left.removeprefix("read  ")
    # (and `~` is the agent's home, as in the person's report)
    assert os.path.realpath(path.replace("~", str(home), 1)) == os.path.realpath(other), row
    assert right == f"allow with --read {path}", row
    key_line = next(line for line in text.splitlines() if "id_ed25519" in line)
    assert key_line.endswith("->  kept closed: a credential"), key_line
    assert CANARY not in text and CANARY not in sent


@pytest.mark.skipif(test_claude.CLAUDE is None, reason="Claude Code (claude) is not installed")
def test_no_report_gives_claude_code_no_hint(place):
    home, work = place
    steps = [("Bash", {"command": 'echo "var=[$HLYN_BLOCKED]"'})]
    done, model = session(steps, home, work, flags=["--no-report"])
    print("exit", done.returncode, model.results())
    assert done.returncode == 0
    assert "var=[]" in model.results()[0][1]
    assert "HLYN_BLOCKED" not in json.dumps(model.requests()[0])



def test_plumbing_quiet_and_hidden_refusals_are_not_listed_and_repeats_are_listed_once(tmp_path):
    sys.path.insert(0, SRC)
    from hlyn.report import BLOCKED, Blocked, Entry

    made = Blocked.start(str(tmp_path), hide=lambda e: e.target == "/hidden")
    for entry in (
        Entry("system", "the keychain service", None, "never"),
        Entry("read", "/quiet", None, "x", quiet=True),
        Entry("read", "/hidden", "--read /hidden"),
        Entry("read", "/shown", "--read /shown"),
        Entry("read", "/shown", "--read /shown"),
        Entry("net", "evil.example:443", None, "not in --net and not one hlyn can check"),
    ):
        made.add(entry)
    made.close()
    rows = [line for line in (tmp_path / BLOCKED).read_text().splitlines() if not line.startswith("#")]
    print(rows)
    assert rows == [
        "read  /shown  ->  allow with --read /shown",
        "net   evil.example:443  ->  not in --net and not one hlyn can check",
    ]


def test_a_refused_host_is_listed_with_the_net_flag_too(tmp_path):
    """The proxy's 403 already tells the program; the list carries the same
    flag next to its file refusals, from the helper's report."""
    script = agent(tmp_path, """
        import os, time, urllib.request
        try:
            urllib.request.urlopen("http://other.example.com/", timeout=5)
        except Exception as exc:
            print("failed:", exc)
        where, text = os.environ["HLYN_BLOCKED"], ""
        for _ in range(300):
            text = open(where).read()
            if "other.example.com" in text:
                break
            time.sleep(0.01)
        print("LIST START")
        print(text, end="")
        print("LIST END")
    """)
    done = hlyn("run", "--no-log", "--read", script, "--net", "example.com", "--", sys.executable, script)
    lines = listed(done)
    print(lines)
    assert "net   other.example.com:80  ->  allow with --net other.example.com:80" in lines
    assert "allow with --net other.example.com:80" in done.stdout.split("LIST START")[0]
