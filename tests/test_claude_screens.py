# SPDX-License-Identifier: Apache-2.0
"""The two screens `hlyn claude` draws: what Claude Code gets, and what it was
refused. Pure layout, no confinement; tests/test_claude_ask.py drives the real
terminal."""

from __future__ import annotations

import io
import os
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
    ("/Users/dev/projects/deep/file.txt", 20, "/Users/de…p/file.txt"),
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
    assert "Claude Code ended. hlyn blocked 2 things:" in text
    rows = rows_of(text)
    assert rows[0] == ["", "what", "blocked", "from · to allow"]
    assert ["✗", "network", "example.com", "--net example.com"] in rows
    assert ["✗", "read", "/opt/data/file.csv", "--read /opt/data/file.csv"] in rows
    assert "  to allow:  hlyn claude --read /opt/data/file.csv --net example.com" in lines
    assert any("allow only hosts you recognise" in ln for ln in lines)
    assert all(len(ln) <= 100 for ln in lines)


def test_one_refusal_says_thing_not_things():
    text = report(refused("net", "example.com:443", "--net example.com")).brief(0, stream=Tty(False))
    assert "blocked 1 thing:" in text


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
    assert "SecurityServer" not in text and "blocked 1 thing:" in text
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
    ("read", "/Users/dev/.CFUserTextEncoding", True),
    ("read", "/Users/dev/.ssh/id_rsa", False),
    ("read", "/var/db/mds/other", False),
    ("net", "example.com:443", False),
    ("write", "/Users/dev/.CFUserTextEncoding", False),
])
def test_expected_hides_only_the_known_probes(kind, target, hidden):
    got = claude.expected(refused(kind, target))
    print(kind, target, "->", got)
    assert got is hidden


# --- the opening screen -------------------------------------------------------

def rows_of(text: str) -> list[list[str]]:
    """The table's rows as [mark, what, where, access], from the box."""
    return [[c.strip() for c in ln.strip().strip("│").split("│")] for ln in text.splitlines()
            if ln.strip().startswith("│")]


def test_the_opening_screen_is_a_table_of_what_it_can_and_cant_use(monkeypatch):
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
    rows = rows_of(text)
    assert rows[0] == ["", "what", "where", "access"]
    assert ["✓", "network", "api.anthropic.com, pypi.org", "connect"] in rows
    assert ["✓", "also", "/h/docs", "read"] in rows
    assert ["✓", "sign-in", "from the keychain", "use"] in rows
    assert ["✗", "everything else", "other folders, hosts, your keys", "blocked"] in rows
    box = [ln for ln in lines if ln.strip() and ln.strip()[0] in "┌├└│"]
    assert len({len(ln) for ln in box}) == 1, "the box is ragged"
    assert box[0].strip().startswith("┌") and box[-1].strip().startswith("└")
    assert max(len(ln) for ln in lines) <= 100


def test_an_unsigned_start_is_marked_with_a_bang():
    cwd = os.getcwd()
    base = plan = Policy(read=(cwd,), write=(cwd,), net=("api.anthropic.com",), env=())
    text = claude.describe(plan, base, (False, "not signed in: hlyn claude --login"), [], [], None,
                           Tty(False))
    print(text)
    assert ["!", "sign-in", "not signed in: hlyn claude --login", ""] in rows_of(text)


def test_secrets_and_files_that_run_later_are_rows_with_a_note():
    cwd = os.getcwd()
    base = plan = Policy(read=(cwd,), write=(cwd,), net=("api.anthropic.com",), env=())
    text = claude.describe(plan, base, (True, "x"), [os.path.join(cwd, ".env")],
                           [os.path.join(cwd, ".git/hooks")], None, Tty(False))
    print(text)
    rows = rows_of(text)
    assert ["!", "secret", "./.env", "readable"] in rows
    assert ["!", "runs later", "./.git/hooks", "writable"] in rows
    assert "! runs later: what's written there runs outside hlyn" in text


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


# --- who started a refused connection ----------------------------------------

def test_a_refused_host_is_traced_to_the_mcp_server_or_plugin_that_reached_for_it(tmp_path, monkeypatch):
    import json

    home, work = tmp_path / "home", tmp_path / "work"
    plugin = home / ".claude/plugins/cache/market/github/abc123"
    plugin.mkdir(parents=True)
    work.mkdir()
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"runpod": {"url": "https://mcp.getrunpod.io/"}, "local": {"command": "node"}},
        "projects": {"/p": {"mcpServers": {"docs": {"url": "https://docs.example.org/mcp"}}}}}))
    (plugin / ".mcp.json").write_text(json.dumps({"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}))
    (work / ".mcp.json").write_text(json.dumps({"mcpServers": {"mine": {"url": "http://tools.internal:8080/x"}}}))
    junk = home / ".claude/plugins/cache/market/broken/1"
    junk.mkdir(parents=True)
    (junk / ".mcp.json").write_text("{not json")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.chdir(work)
    hosts = claude.mcp_hosts({})
    print(hosts)
    assert hosts == {
        "mcp.getrunpod.io": 'your MCP server "runpod"',
        "docs.example.org": 'your MCP server "docs"',
        "tools.internal": 'this project\'s MCP server "mine"',
        "api.githubcopilot.com": 'the "github" plugin',
    }
    text = report(refused("net", "mcp.getrunpod.io:443", "--net mcp.getrunpod.io"),
                  refused("net", "api.githubcopilot.com:443", "--net api.githubcopilot.com"),
                  refused("net", "unknown.example:443", "--net unknown.example"),
                  ).brief(0, stream=Tty(False), who=lambda e: claude.whose(e, hosts))
    print(text)
    lines = text.splitlines()
    rows = rows_of(text)
    assert ["✗", "network", "mcp.getrunpod.io", 'your MCP server "runpod"'] in rows
    assert ["✗", "network", "api.githubcopilot.com", 'the "github" plugin'] in rows
    assert ["✗", "network", "unknown.example", "--net unknown.example"] in rows, \
        "a host nobody configured shows its flag instead"
    again = "  to allow:  hlyn claude " + " ".join(
        f"--net {h}" for h in ("api.githubcopilot.com", "mcp.getrunpod.io", "unknown.example"))
    assert again in lines


def test_whose_names_only_network_refusals_and_only_known_hosts():
    hosts = {"mcp.example.org": "the thing"}
    assert claude.whose(refused("net", "mcp.example.org:443"), hosts) == "the thing"
    assert claude.whose(refused("net", "mcp.example.org"), hosts) == "the thing"
    assert claude.whose(refused("net", "other.example.org:443"), hosts) == ""
    assert claude.whose(refused("read", "mcp.example.org:443"), hosts) == ""


def test_the_end_report_box_is_not_ragged(monkeypatch):
    monkeypatch.setenv("COLUMNS", "100")
    text = report(refused("net", "a.example:443", "--net a.example"),
                  refused("net", "much-longer-host.example.org:443", "--net much-longer-host.example.org"),
                  refused("read", "/opt/x", "--read /opt/x")).brief(0, stream=Tty(False))
    print(text)
    box = [ln for ln in text.splitlines() if ln.strip() and ln.strip()[0] in "┌├└│"]
    assert len({len(ln) for ln in box}) == 1, "the box is ragged"
    assert {ln.index("│", 5) for ln in box if ln.strip().startswith("│")} == {box[1].index("│", 5)}


# --- every branch of the end report, each pinned by a planted bug -----------------

def test_the_heading_counts_refusals_past_the_listed_limit_and_says_so():
    from hlyn.report import LIMIT

    book = report(*(refused("read", f"/opt/many/f{n}", f"--read /opt/many/f{n}") for n in range(LIMIT + 3)))
    text = book.brief(0, stream=Tty(False))
    print(text.splitlines()[:3], text.splitlines()[-4:])
    assert book.more == 3, book.more
    assert f"hlyn blocked {LIMIT + 3} things:" in text
    assert f"and 3 more, past the first {LIMIT}" in text


def test_a_failed_run_says_its_exit_code():
    text = report(refused("net", "example.com:443", "--net example.com")).brief(7, stream=Tty(False))
    print(text)
    assert "Claude Code exited with code 7. hlyn blocked 1 thing:" in text


def test_a_credential_is_shown_as_kept_closed_with_no_flag_to_allow_it(tmp_path):
    key = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
    book = report(Denial(kind="read", target=key, source="program"))
    entry = book.items()[0]
    text = book.brief(1, stream=Tty(False))
    print(text)
    assert entry.credential and entry.allow is None
    assert ["✗", "read", "~/.ssh/id_rsa", "kept closed: a credential"] in rows_of(text)
    assert "  to allow:" not in text


def test_the_same_flag_is_offered_once():
    book = report(refused("write", "/opt/a/x"), refused("write", "/opt/a/y"))
    text = book.brief(0, stream=Tty(False))
    print(text)
    flags = [e.allow for e in book.items()]
    assert flags == ["--write /opt/a", "--write /opt/a"], "the case needs two equal flags"
    assert text.count("--write /opt/a") == 2 + 1, "two rows and one 'to allow' line"
    assert "  to allow:  hlyn claude --write /opt/a\n" in text


def test_the_host_warning_is_for_hosts_not_for_ports():
    ports = Report(Policy(net=(443,)), env={}, which=lambda _name: None, cwd="/work")
    ports.add(Denial(kind="net", target="5432 127.0.0.1", op="connect", source="program"))
    port_text = ports.brief(0, stream=Tty(False))
    host_text = report(refused("net", "example.com:443", "--net example.com")).brief(0, stream=Tty(False))
    print(port_text, host_text)
    assert "--net 5432" in port_text and "allow only hosts you recognise" not in port_text
    assert "allow only hosts you recognise" in host_text


def test_the_record_and_an_incomplete_list_are_named_only_when_they_apply():
    book = report(refused("net", "example.com:443", "--net example.com"))
    bare = book.brief(0, stream=Tty(False))
    assert "every refusal" not in bare and "incomplete" not in bare
    book.why = "the system log fell behind"
    full = book.brief(0, log="/home/x/claude.jsonl", stream=Tty(False))
    print(full)
    assert "  every refusal: /home/x/claude.jsonl" in full
    assert "  this list may be incomplete: the system log fell behind" in full


def test_quiet_refusals_are_shown_only_when_the_run_failed_and_never_offer_their_flag():
    from hlyn.report import Entry

    book = report(refused("net", "example.com:443", "--net example.com"))
    book.entries[("write", "/opt/noise/cache")] = Entry(
        "write", "/opt/noise/cache", "--write /opt/noise", "it carries on without it", quiet=True,
        source="program")
    ok = book.brief(0, stream=Tty(False))
    failed = book.brief(1, stream=Tty(False))
    print(ok, failed)
    assert "/opt/noise" not in ok, "a quiet refusal was shown on a run that succeeded"
    assert ["✗", "write", "/opt/noise/cache", "--write /opt/noise"] in rows_of(failed)
    assert "  to allow:  hlyn claude --net example.com\n" in failed, "a quiet refusal's flag was offered"
    only = report()
    only.entries[("write", "/opt/noise/cache")] = book.entries[("write", "/opt/noise/cache")]
    assert only.brief(0, stream=Tty(False)) == ""


# --- a metadata address is never offered as a flag -----------------------------

METADATA = ["169.254.169.254:80", "[fd00:ec2::254]:80", "168.63.129.16:80", "100.100.100.200:80",
            "[fe80::1]:443"]


@pytest.mark.parametrize("target", METADATA)
def test_a_cloud_metadata_address_is_refused_without_a_flag_and_with_the_real_fix(target):
    book = report(refused("net", target, f"--net {target}"))
    entry = book.items()[0]
    print(entry.allow, "|", entry.note)
    assert entry.allow is None, "a flag was offered for a credentials address"
    assert "--env AWS_ACCESS_KEY_ID" in entry.note and "--env AWS_SECRET_ACCESS_KEY" in entry.note
    assert book.json(1)["blocked"][0]["allow"] is None
    for text in (book.text(1), book.brief(1, stream=Tty(False))):
        print(text)
        assert f"--net {target}" not in text and "  to allow:" not in text
        assert "--env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY" in " ".join(text.split()), \
            "the fix wasn't said (words may wrap, so whitespace is joined)"


def test_other_hosts_beside_a_metadata_address_keep_their_flags_and_the_note_is_said_once():
    book = report(refused("net", "169.254.169.254:80", "--net 169.254.169.254:80"),
                  refused("net", "[fd00:ec2::254]:80", "--net [fd00:ec2::254]:80"),
                  refused("net", "example.com:443", "--net example.com"))
    text = book.brief(1, stream=Tty(False))
    print(text)
    rows = rows_of(text)
    assert ["✗", "network", "169.254.169.254:80", "see below"] in rows
    assert ["✗", "network", "example.com", "--net example.com"] in rows
    assert text.count("A cloud metadata address") == 1, "the same note was repeated"
    assert "  to allow:  hlyn claude --net example.com\n" in text
    assert max(len(ln) for ln in text.splitlines()) <= 100


@pytest.mark.parametrize("columns", [60, 100])
def test_a_note_too_long_for_its_cell_is_said_in_full_below_the_table(columns, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(columns))
    book = report(refused("net", "169.254.169.254:80", "--net 169.254.169.254:80"))
    text = book.brief(1, stream=Tty(False))
    print(text)
    lines = text.splitlines()
    below = lines[lines.index("  169.254.169.254:80") + 1:]
    said = " ".join(ln.strip() for ln in below if ln.startswith("    "))
    assert said.endswith("(and --env AWS_SESSION_TOKEN if they are temporary).")
    assert max(len(ln) for ln in text.splitlines()) <= columns


def test_many_metadata_addresses_still_fit_the_window(monkeypatch):
    monkeypatch.setenv("COLUMNS", "60")
    book = report(*(refused("net", f"169.254.169.{n}:80", f"--net 169.254.169.{n}:80") for n in range(1, 13)))
    text = book.brief(1, stream=Tty(False))
    print(text)
    assert max(len(ln) for ln in text.splitlines()) <= 60
    assert text.count("A cloud metadata address") == 1


def test_a_quiet_refusals_long_note_is_cut_in_its_cell_not_said_below():
    from hlyn.report import Entry

    book = report(refused("net", "169.254.169.254:80", "--net 169.254.169.254:80"))
    book.entries[("write", "/opt/noise/cache")] = Entry(
        "write", "/opt/noise/cache", None, "in your home folder: a grant would expose everything inside",
        quiet=True, source="program")
    text = book.brief(1, stream=Tty(False))
    print(text)
    rows = rows_of(text)
    assert ["✗", "network", "169.254.169.254:80", "see below"] in rows
    quiet = next(row for row in rows if row[2] == "/opt/noise/cache")
    assert quiet[3].endswith("…") and quiet[3] != "see below"
    assert "a grant would expose everything inside" not in text
    assert text.count("\n  /opt/noise/cache\n") == 0
