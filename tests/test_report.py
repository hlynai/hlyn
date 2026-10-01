# SPDX-License-Identifier: Apache-2.0
"""Turning refusals into advice: the platform-neutral half.

Nothing here confines anything. These pin down what a refusal becomes -- which
flag is suggested, which refusals are dropped as not hlyn's, which are named as
credentials -- and that the parsers for both platforms' raw records survive
whatever the confined program, or the system log, sends them.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import sys

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hlyn.core import oslog, preload
from hlyn.policy import Policy
from hlyn.report import LIMIT, REASONS, WHY, Denial, Report, credential, flag, removed, safe, secret

HOME = os.path.expanduser("~")


def book(tmp_path, **policy):
    """A report over `policy`, with commands resolved inside `tmp_path`."""
    def which(name):
        found = tmp_path / "bin" / name
        return str(found) if found.exists() else None

    return Report(Policy(**policy), env={}, which=which, cwd=str(tmp_path))


def one(report, **fields):
    fields.setdefault("source", "program")
    return report.add(Denial(**fields))


# ---------------------------------------------------------------------------
# what each refusal suggests
# ---------------------------------------------------------------------------


def test_a_refused_read_suggests_exactly_that_path(tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("x")
    entry = one(book(tmp_path), kind="read", target=str(target), op="open")
    assert entry.allow == f"--read {target}"
    assert not entry.credential


def test_a_public_certificate_is_suggested_and_a_private_key_is_not(tmp_path):
    """A `.pem` or `.key` file is a credential only if it holds a private key
    (README, "Secrets in granted folders"); a CA bundle such as Homebrew's
    cert.pem is public, and the report suggests the flag for it."""
    public = tmp_path / "cert.pem"
    public.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    private = tmp_path / "server.pem"
    private.write_text("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
    report = book(tmp_path)
    shown = [one(report, kind="read", target=str(path), op="open") for path in (public, private)]
    for entry in shown:
        print(entry.target, "|", entry.allow, "|", entry.note, "| credential" if entry.credential else "")
    assert shown[0].allow == f"--read {public}" and not shown[0].credential
    assert shown[1].allow is None and shown[1].credential


def test_creating_a_file_suggests_its_folder(tmp_path):
    # A path that does not exist cannot be granted at all, so the only grant
    # that helps is the folder it would be made in.
    entry = one(book(tmp_path), kind="write", target=str(tmp_path / "new.txt"), op="open")
    assert entry.allow == f"--write {tmp_path}"


def test_writing_an_existing_file_suggests_the_file(tmp_path):
    target = tmp_path / "log.txt"
    target.write_text("x")
    entry = one(book(tmp_path), kind="write", target=str(target), op="open")
    assert entry.allow == f"--write {target}"


@pytest.mark.parametrize("op", ["unlink", "rename", "mkdir", "file-write-unlink", "file-write-create"])
def test_changing_a_folder_entry_suggests_the_folder(tmp_path, op):
    # Removing, renaming or making an entry needs write on the folder holding
    # it; a grant on the file itself would change nothing.
    target = tmp_path / "old.txt"
    target.write_text("x")
    entry = one(book(tmp_path), kind="write", target=str(target), op=op)
    assert entry.allow == f"--write {tmp_path}"


def test_a_program_found_by_name_is_suggested_by_its_real_path(tmp_path):
    (tmp_path / "bin").mkdir()
    real = tmp_path / "bin" / "tool-1.2"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    (tmp_path / "bin" / "tool").symlink_to(real)
    entry = one(book(tmp_path), kind="exec", target="tool", op="execvp")
    assert entry.allow == f"--exec {real}"


def test_a_program_that_does_not_exist_is_not_reported(tmp_path):
    assert one(book(tmp_path), kind="exec", target="no-such-tool", op="execvp") is None


def test_a_refused_port_suggests_that_port(tmp_path):
    entry = one(book(tmp_path, net=[443]), kind="net", target="5432 127.0.0.1", op="connect")
    assert entry.allow == "--net 5432"
    assert entry.target == "TCP 5432 (127.0.0.1)"


def test_a_port_the_policy_allows_is_not_hlyns_refusal(tmp_path):
    # Linux: TCP connect to an allowed port was refused by something else --
    # a firewall -- or the record was invented. Either way, no advice.
    assert one(book(tmp_path, net=[5432]), kind="net", target="5432 127.0.0.1", op="connect") is None


def test_a_fast_open_send_suggests_the_whole_network(tmp_path):
    # Refused even on a named port: Fast Open gets past Landlock's port rules,
    # so naming the port would not allow it and must not be suggested.
    entry = one(book(tmp_path, net=[443]), kind="net", target="443 127.0.0.1", op="sendto")
    assert entry.allow == "--net-any"
    assert entry.target == "TCP Fast Open to port 443 (127.0.0.1)"


def test_on_macos_an_allowed_port_refused_means_udp(tmp_path):
    entry = one(book(tmp_path, net=[53]), kind="net", target="53", op="network-outbound", source="kernel")
    assert entry.allow == "--net-any"
    assert "UDP" in entry.target


def test_listening_needs_the_whole_network(tmp_path):
    entry = one(book(tmp_path, net=[443]), kind="bind", target="8080 0.0.0.0", op="bind")
    assert entry.allow == "--net-any"


def test_a_closed_network_suggests_opening_it(tmp_path):
    entry = one(book(tmp_path), kind="net", target="socket:2", op="socket")
    assert entry.allow == "--net-any"
    assert "--net PORT" in entry.note


def test_a_socket_refused_with_the_network_open_is_not_hlyns(tmp_path):
    # A raw socket without CAP_NET_RAW also fails with EPERM.
    assert one(book(tmp_path, net=[443]), kind="net", target="socket:2", op="socket") is None


def test_sockets_hlyn_never_allows_get_no_flag(tmp_path):
    entry = one(book(tmp_path), kind="net", target="socket:40", op="socket")
    assert entry.kind == "other"
    assert entry.allow is None


def test_an_abstract_socket_outside_the_agent_gets_no_flag(tmp_path, monkeypatch):
    # From Landlock ABI 9 the gate lets an abstract name run, so a refusal is
    # Landlock's scope: a socket of a process outside this agent.
    from hlyn.core import landlock

    monkeypatch.setattr(landlock, "abi", lambda: 9)
    entry = one(book(tmp_path), kind="net", target="unix:@other-agent", op="connect")
    print(entry)
    assert entry.allow is None
    assert "outside this agent" in entry.note


@pytest.mark.skipif(sys.platform != "linux", reason="the gate and abstract names are Linux's")
@pytest.mark.parametrize(("net", "abi", "kept"), [(False, None, False), ([443], None, False),
                                                   (True, None, True), (False, 9, True)])
def test_an_abstract_name_the_gate_refused_is_reported_once(tmp_path, monkeypatch, net, abi, kept):
    """Before ABI 9, with the network not open, the gate refuses every
    abstract name before it runs and reports it itself (`unix-abstract`); the
    program's copy of the same refusal would call it another agent's socket.
    With an open network, or from ABI 9, Landlock's scope refused it, and
    the program's report is the only one. `abi` None: this machine's."""
    from conftest import enforces

    from hlyn.core import landlock, linux

    if abi is not None:
        monkeypatch.setattr(landlock, "abi", lambda: abi)
    elif not (enforces() and landlock.abi() < 9 and linux.watched(Policy(net=False))):
        pytest.skip("needs a kernel before Landlock ABI 9 where a gate can run")
    report = book(tmp_path, net=net)
    gate = report.add(Denial("net", "@own-agent", op="unix-abstract", allow="--net-any", source="gate"))
    program = one(report, kind="net", target="unix:@own-agent", op="connect")
    print(f"net={net} abi={abi or landlock.abi()}: gate {gate}; program {program}")
    assert (program is not None) is kept
    if net is not True:
        assert gate is not None and gate.target == "local socket @own-agent" and "7.1" in gate.note


def test_a_socket_file_refusal_from_inside_the_program_is_not_believed(tmp_path, monkeypatch):
    # Before Landlock ABI 9 nothing in hlyn refuses a socket file outside host
    # mode, so the refusal is the file's own permissions.
    from hlyn.core import landlock

    monkeypatch.setattr(landlock, "abi", lambda: 7)
    assert one(book(tmp_path), kind="net", target="unix:/run/app.sock", op="connect") is None


@pytest.fixture
def abi9(monkeypatch):
    """Landlock ABI 9 (Linux 7.1+), where the shim limits socket files."""
    from hlyn.core import landlock

    monkeypatch.setattr(landlock, "abi", lambda: 9)


def test_on_7_1_a_refused_socket_file_suggests_its_folder(tmp_path, abi9):
    server = tmp_path / "srv" / "app.sock"
    server.parent.mkdir()
    server.touch()
    entry = one(book(tmp_path, net=False), kind="net", target=f"unix:{server}", op="connect", by="psql")
    print(entry.target, "|", entry.allow, "|", entry.note)
    assert entry.target == f"local socket {server}"
    assert entry.allow == f"--write {server.parent}"
    assert entry.note == "a local socket needs write access to its folder" and not entry.quiet
    ported = one(book(tmp_path, net=[443]), kind="net", target=f"unix:{server}", op="sendto")
    assert ported.allow == f"--write {server.parent}"


def test_on_7_1_socket_files_the_policy_does_not_refuse_are_dropped(tmp_path, abi9):
    granted = tmp_path / "granted"
    granted.mkdir()
    cases = {
        "net=True leaves socket files open": (book(tmp_path, net=True), "/run/app.sock"),
        "host mode: the gate reports its own": (book(tmp_path, net=["pypi.org"]), "/run/app.sock"),
        "under a write grant": (book(tmp_path, write=[str(granted)]), f"{granted}/app.sock"),
        "write=True grants every folder": (book(tmp_path, write=True), "/run/app.sock"),
        "relative: whose folder is unknown": (book(tmp_path), "app.sock"),
    }
    for name, (report, where) in cases.items():
        got = one(report, kind="net", target=f"unix:{where}", op="connect")
        print(f"{name:40} {where:40} -> {got}")
        assert got is None, name


def test_on_7_1_the_log_socket_is_quiet_and_a_runtime_socket_warns(tmp_path, abi9):
    report = book(tmp_path)
    log = one(report, kind="net", target="unix:/dev/log", op="connect", by="python3")
    docker = one(report, kind="net", target="unix:/var/run/docker.sock", op="connect")
    for entry in (log, docker):
        print(entry.target, "|", entry.allow, "|", entry.note, "| quiet" if entry.quiet else "")
    assert log.quiet and log.note == "the system log; programs carry on without it"
    assert not docker.quiet and "hands that over" in docker.note
    # Landlock checks where the socket really is: /var/run is usually /run
    # (and on a Mac with Docker Desktop, a link into the home folder, shown
    # as ~ the way every flag in the report is).
    assert docker.allow == flag("--write", os.path.dirname(os.path.realpath("/var/run/docker.sock")))
    shown = report.text(0, ["agent"])
    print(shown)
    assert "/dev/log" not in shown and "docker.sock" in shown


def test_os_plumbing_is_counted_not_listed(tmp_path):
    report = book(tmp_path)
    assert one(report, kind="system", target="vfs.disk-space", op="system-info", source="kernel") is None
    assert report.system == 1
    assert report.items() == []


# ---------------------------------------------------------------------------
# what is dropped: refusals the policy explains away
# ---------------------------------------------------------------------------


def test_a_path_the_policy_grants_is_never_reported(tmp_path):
    # The Linux records come from inside the confined program. One claiming a
    # granted path was refused is either someone else's refusal or invented,
    # and must not become advice.
    target = tmp_path / "ok.txt"
    target.write_text("x")
    report = book(tmp_path, read=[str(tmp_path)])
    assert one(report, kind="read", target=str(target), op="open") is None
    assert report.dropped == 1


def test_nothing_is_reported_against_a_field_granting_everything(tmp_path):
    target = tmp_path / "x"
    target.write_text("x")
    assert one(book(tmp_path, read=True), kind="read", target=str(target)) is None
    assert one(book(tmp_path, exec=True), kind="exec", target="/bin/sh") is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything, so permissions never refuse")
def test_a_file_nobody_may_read_is_not_blamed_on_hlyn(tmp_path):
    locked = tmp_path / "locked"
    locked.write_text("x")
    locked.chmod(0)
    try:
        assert one(book(tmp_path), kind="read", target=str(locked), op="open") is None
    finally:
        locked.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_known_startup_probes_are_ignored(tmp_path):
    assert one(book(tmp_path), kind="read", target="/dev/dtracehelper", source="kernel") is None


def test_proc_gets_no_flag_and_stays_quiet(tmp_path):
    entry = one(book(tmp_path), kind="read", target="/proc/self/stat", op="open")
    assert entry.allow is None
    assert entry.quiet
    assert "environment" in entry.note


def test_pythons_bytecode_cache_is_quiet_and_folded(tmp_path):
    report = book(tmp_path)
    for name in ("a", "b", "c"):
        one(report, kind="write", target=f"{tmp_path}/lib/__pycache__/{name}.cpython-313.pyc.123")
    assert all(e.quiet and e.allow is None for e in report.items())
    assert report.text(0) == ""
    text = report.text(1)
    assert "3 paths under" in text
    assert "bytecode cache" in text
    assert "--write" not in text


def test_a_static_program_is_recognised(tmp_path):
    assert not preload.static(sys.executable)
    assert not preload.static(__file__)
    assert not preload.static(str(tmp_path / "missing"))


def test_relative_paths_are_not_guessed_at(tmp_path):
    assert one(book(tmp_path), kind="read", target="fd:7/config.json") is None


# ---------------------------------------------------------------------------
# credentials: named, never suggested
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        f"{HOME}/.ssh/id_ed25519",
        f"{HOME}/.aws/credentials",
        f"{HOME}/.config/gcloud/application_default_credentials.json",
        "/etc/shadow",
        "/srv/app/.env",
        "/srv/app/.env.production",
        "/srv/app/server.key",
        "/srv/app/cert.pem",
    ],
)
def test_credentials_are_recognised(path):
    assert credential(path)


@pytest.mark.parametrize("path", ["/srv/app/main.py", f"{HOME}/project/README.md", "/etc/hosts"])
def test_ordinary_files_are_not_credentials(path):
    assert not credential(path)


def test_a_credential_gets_no_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("k")
    entry = one(book(tmp_path), kind="read", target=str(key), op="open")
    assert entry.credential
    assert entry.allow is None
    assert "credential" in entry.note


def test_creating_a_file_in_a_credential_folder_gets_no_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".ssh").mkdir()
    entry = one(book(tmp_path), kind="write", target=str(tmp_path / ".ssh" / "authorized_keys"), op="open")
    assert entry.allow is None
    assert entry.credential


def test_credentials_are_listed_first(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    plain = tmp_path / "a.txt"
    plain.write_text("x")
    key = tmp_path / ".aws" / "credentials"
    key.parent.mkdir()
    key.write_text("k")
    report = book(tmp_path)
    one(report, kind="read", target=str(plain))
    one(report, kind="read", target=str(key))
    assert report.items()[0].credential


# ---------------------------------------------------------------------------
# folders a program lists on its own while starting
# ---------------------------------------------------------------------------


def test_listing_the_start_folder_is_quiet_but_allowable(tmp_path):
    entry = one(book(tmp_path), kind="read", target=str(tmp_path), op="file-read-data", source="kernel")
    assert entry.quiet
    assert entry.allow == f"--read {tmp_path}"


def test_listing_a_folder_above_it_is_never_given_a_flag(tmp_path):
    # A read grant is a whole tree. Suggesting one to allow a listing of a
    # parent -- or of the home folder -- would expose everything inside.
    inner = tmp_path / "project"
    inner.mkdir()
    report = Report(Policy(), env={}, cwd=str(inner))
    entry = one(report, kind="read", target=str(tmp_path), op="opendir")
    assert entry.quiet
    assert entry.allow is None


def test_a_file_made_directly_in_the_home_folder_is_never_given_a_flag(tmp_path, monkeypatch):
    # Making a file needs its folder, so this used to suggest `--write ~`:
    # the whole home folder, to let Claude Code save ~/.claude.json through
    # a temporary file beside it. One level down is still a normal flag.
    home = tmp_path / "home"
    (home / "notes").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    report = book(tmp_path)
    top = one(report, kind="write", target=str(home / ".claude.json.tmp.1.ab"), op="open")
    below = one(report, kind="write", target=str(home / "notes" / "new.txt"), op="open")
    print(f"{top.target}: allow={top.allow!r} note={top.note!r}\n{below.target}: allow={below.allow!r}")
    assert top.allow is None and top.quiet and "home folder" in top.note
    assert below.allow == "--write ~/notes"


def test_quiet_entries_alone_do_not_make_a_success_noisy(tmp_path):
    report = book(tmp_path)
    one(report, kind="read", target=str(tmp_path), op="opendir")
    assert report.text(0) == ""
    assert str(tmp_path) in report.text(1)


# ---------------------------------------------------------------------------
# counting
# ---------------------------------------------------------------------------


def test_running_totals_from_one_process_are_not_added_up(tmp_path):
    target = tmp_path / "x"
    target.write_text("x")
    report = book(tmp_path)
    for count in (1, 2, 4, 8):
        entry = one(report, kind="read", target=str(target), pid=10, count=count)
    one(report, kind="read", target=str(target), pid=11, count=1)
    assert entry.count == 9


def test_kernel_reports_are_added_up(tmp_path):
    target = tmp_path / "x"
    target.write_text("x")
    report = book(tmp_path)
    for _ in range(3):
        entry = one(report, kind="read", target=str(target), pid=10, source="kernel")
    one(report, kind="read", target=str(target), pid=10, count=5, source="kernel")
    assert entry.count == 8


def test_a_flood_of_distinct_refusals_is_capped(tmp_path):
    report = book(tmp_path)
    for i in range(LIMIT + 50):
        one(report, kind="write", target=str(tmp_path / f"f{i}"), op="open")
    assert len(report.items()) == LIMIT
    assert report.more == 50
    text = report.text(1)
    assert "and 50 more refusals" in text
    # All of them want the same folder, so they are one line, not a thousand.
    assert f"{LIMIT} paths under {tmp_path}" in text
    assert len(text.splitlines()) < 10


def test_past_the_reports_cap_every_refusal_is_still_logged(tmp_path, monkeypatch):
    """The report lists the first LIMIT distinct refusals; the log records
    every one, up to its own, larger cap (`log.LIMIT`). Both used to stop at
    the report's cap: 1002 of 3000 distinct refusals reached the log in a
    real `hlyn run` (review, 2026-09-30)."""
    import io

    from hlyn import cli, log

    stream = io.StringIO()
    monkeypatch.setattr(log, "_seen", {})
    log.sink(stream)
    try:
        report = book(tmp_path)
        for i in range(LIMIT + 50):
            cli._file(report, Denial("write", str(tmp_path / f"f{i}"), op="open", source="program"))
    finally:
        log.sink(True)
    denies = [row for row in map(json.loads, stream.getvalue().splitlines()) if row["kind"] == "deny"]
    print(f"{LIMIT + 50} distinct refusals: the report keeps {len(report.items())} (more: {report.more}); "
          f"the log has {len(denies)} deny records")
    assert len(report.items()) == LIMIT and report.more == 50
    wanted = sorted(str(tmp_path / f"f{i}") for i in range(LIMIT + 50))
    assert sorted(row["target"] for row in denies) == wanted


def test_the_gates_reporter_logs_past_its_cap_and_the_report_says_what_the_log_lost(tmp_path):
    """The gate's Reporter: past its LIMIT distinct refusals it stops sending
    them to the report but still logs each one; its last line says how many
    were past the cap, how many report lines found no room, and how many log
    lines found none, and the report prints the last."""
    from hlyn import cli
    from hlyn.core.guard import Reporter

    many = Reporter.LIMIT + 200
    with open(tmp_path / "log", "w+b") as logged, open(tmp_path / "events", "w+b") as events:
        reporter = Reporter(log=logged.fileno(), events=events.fileno())
        for i in range(many):
            reporter({"kind": "net", "target": f"10.0.{i // 256}.{i % 256}:443", "allow": None,
                      "why": "direct", "source": "gate", "pid": os.getpid()})
        reporter.flush(final=True)
        logged.seek(0)
        denies = [json.loads(line) for line in logged.read().splitlines()]
        events.seek(0)
        sent = [json.loads(line) for line in events.read().splitlines()]
    last = sent[-1]
    print(f"{many} distinct refusals: {len(denies)} logged, {len(sent) - 1} sent to the report, "
          f"last line {last}")
    assert len({row["target"] for row in denies}) == many
    assert len(sent) - 1 == Reporter.LIMIT
    assert last == {"kind": "more", "count": 200, "dropped": 0, "unlogged": 0}

    report = book(tmp_path, net=["example.com"])
    r, w = os.pipe()
    os.write(w, json.dumps({"kind": "more", "count": 3, "dropped": 2, "unlogged": 7}).encode() + b"\n")
    os.write(w, json.dumps({"target": "10.9.9.9:443", "why": "direct", "source": "gate",
                            "allow": "--net 10.9.9.9:443"}).encode() + b"\n")
    os.close(w)
    os.set_blocking(r, False)
    cli._proxied(r, b"", report)
    os.close(r)
    text = report.text(0)
    print(text)
    assert report.more == 5 and report.unlogged == 7
    assert "7 of these couldn't be written to hlyn's log" in text


@pytest.mark.parametrize("letter", ["a", "é", "日"])
@pytest.mark.parametrize("length", [300, 5000])
def test_the_gates_report_lines_are_whole_json_in_one_pipe_write(tmp_path, letter, length):
    """Each report line is one atomic pipe write (PIPE_BUF: 4096 on Linux,
    where the gate runs; 512 on macOS). Cutting the encoded line cut through
    a character's six-byte escape and the report dropped the line (review,
    2026-09-30: a 300-character non-ASCII socket path). Now a line is UTF-8,
    a path that fits arrives whole, and one that doesn't is shortened as
    text, marked with "…", and reported without a flag (a shortened path
    names another folder)."""
    import select

    from hlyn.core.guard import Reporter

    target = "/tmp/" + letter * length + "/x.sock"
    with open(tmp_path / "events", "w+b") as events:
        reporter = Reporter(events=events.fileno())
        reporter({"kind": "net", "target": target, "allow": "--write /tmp/" + letter * length,
                  "why": "unix", "source": "gate", "detail": "d" * 100, "pid": os.getpid()})
        events.seek(0)
        lines = events.read().splitlines()
    sent = json.loads(lines[0])
    whole = sent["target"] == target
    print(f"{letter!r} x {length}: {len(lines[0])} bytes (limit {select.PIPE_BUF}), target whole: {whole}, "
          f"allow: {str(sent['allow'])[:30]!r}")
    assert len(lines) == 1 and len(lines[0]) < select.PIPE_BUF
    if whole:
        assert sent["allow"] == "--write /tmp/" + letter * length
    else:
        assert sent["target"].endswith("…") and target.startswith(sent["target"][:-1])
        assert sent["allow"] is None and len(sent["target"]) >= 20
    if length == 300 and select.PIPE_BUF >= 4096:
        assert whole  # where the gate runs, a real socket path's length always fits
    if length == 5000:
        assert not whole
        entry = book(tmp_path, net=[443]).add(Denial("net", sent["target"], op="unix", source="gate",
                                                     allow="--write /tmp"))
        print(entry)
        assert entry is not None and entry.allow is None


def test_a_refusal_no_flag_can_allow_says_why_instead_of_same_as_above(tmp_path):
    """A name the proxy can't check (not a valid host name) has no flag to
    suggest. Its line said "same as above" with nothing above it (review,
    2026-09-30); it now says why, and "same as above" is kept for a real
    repeat of the line before."""
    report = book(tmp_path, net=["example.com"])
    report.add(Denial("net", "(invalid host name)", op="not-listed", source="proxy"))
    alone = report.text(1)
    print(alone)
    assert "same as above" not in alone
    assert "(invalid host name)  the name isn't one hlyn can check, so no --net entry can allow it" in alone
    report.add(Denial("net", "8.8.8.8:53", op="dns", source="proxy"))
    report.add(Denial("net", "(also invalid)", op="not-listed", source="proxy"))
    both = report.text(1)
    print(both)
    rows = [line for line in both.splitlines() if line.startswith("  net")]
    said = [row.split(None, 2)[2] for row in rows]  # in the report's order
    print(said)
    assert said[1].endswith("so no --net entry can allow it") and said[2].endswith("same as above")
    assert "(also invalid)" in rows[1] and "(invalid host name)" in rows[2]


# ---------------------------------------------------------------------------
# `why`: the machine key of a network refusal (design 4.6)
# ---------------------------------------------------------------------------

# One refusal per reason the proxy and the gate emit, as each really sends it
# (src/hlyn/proxy.py `_event`, src/hlyn/core/guard.py `_event`): source, target, flag.
PROXY_SAYS = {
    "not-listed": ("evil.example:443", "--net evil.example"),
    "private-address": ("internal.example:443", "--net 10.0.0.5"),
    "sni-mismatch": ("api.example.com:443", ""),
    "dns": ("8.8.8.8:53", ""),
    "resolve-failed": ("nope.example:443", ""),
    "direct": ("1.1.1.1:443", "--net 1.1.1.1:443"),
    "busy": ("", ""),
}
GATE_SAYS = {
    "udp": ("UDP", ""),
    "unix": ("/run/some.sock", "--write /run"),
    "unix-send": ("/run/some.sock", "--net-any"),
    "unix-bound": ("/run/some.sock", "--net-any"),
    "unix-abstract": ("@own-agent", "--net-any"),
    "gate-error": ("ValueError", ""),
    "direct": ("1.1.1.1:443", "--net 1.1.1.1:443"),
    "dns": ("8.8.8.8:53", ""),
    "proxy-gone": ("1.1.1.1:443", ""),
}


def _cases():
    out = [("proxy", why, *said) for why, said in PROXY_SAYS.items()]
    out += [("gate", why, *said) for why, said in GATE_SAYS.items()]
    return out


def test_every_reason_is_covered_by_a_case():
    """The list can't pass by being empty or by missing a key: the cases cover
    exactly the reasons, and every key of the report's WHY table is one."""
    print("REASONS:", REASONS)
    print("covered by the proxy:", sorted(PROXY_SAYS), "| by the gate:", sorted(GATE_SAYS))
    assert len(_cases()) == len(PROXY_SAYS) + len(GATE_SAYS) >= 16
    assert len(REASONS) == len(set(REASONS)) >= 13
    assert set(WHY) <= set(REASONS)
    assert set(PROXY_SAYS) | set(GATE_SAYS) == set(REASONS)


@pytest.mark.parametrize(("source", "why", "target", "allow"), _cases(),
                         ids=[f"{src}-{why}" for src, why, *_ in _cases()])
def test_a_network_refusal_carries_its_machine_key_in_json(tmp_path, source, why, target, allow):
    report = book(tmp_path, net=["api.example.com"])
    entry = report.add(Denial("net", target, op=why, allow=allow, source=source))
    assert entry is not None, f"{source} {why} was dropped"
    out = json.loads(json.dumps(report.json(1)))["blocked"]
    print(f"{source} {why!r} -> {out}")
    assert [item["why"] for item in out] == [why]  # exactly the key, never the prose
    assert out[0]["source"] == source and out[0]["kind"] == "net"


def test_an_unknown_reason_is_dropped_not_given_a_made_up_key(tmp_path):
    report = book(tmp_path, net=["api.example.com"])
    assert report.add(Denial("net", "evil.example:443", op="because", source="proxy")) is None
    assert report.json(1)["blocked"] == []


@pytest.mark.parametrize(
    ("platform", "op", "rest", "port", "why"),
    [
        ("darwin", "connect", "127.0.0.1", 9, "direct"),
        ("darwin", "connect", "*", 9, "direct"),
        ("linux", "sendto", "1.1.1.1", 443, "direct"),
        ("linux", "sendto", "8.8.8.8", 53, "dns"),
    ],
)
def test_a_direct_connection_heard_by_the_os_carries_its_key(
    tmp_path, monkeypatch, platform, op, rest, port, why
):
    monkeypatch.setattr("hlyn.report.sys.platform", platform)
    entry = one(book(tmp_path, net=["api.example.com"]), kind="net", target=f"{port} {rest}", op=op,
                source="kernel")
    assert entry is not None
    print(platform, op, rest, port, "->", entry.json())
    assert entry.json()["why"] == why and entry.json()["source"] == "kernel"


def test_a_port_refusal_with_no_hosts_has_no_reason_to_give(tmp_path):
    """Ports mode (no host list) has no proxy or gate reason: `why` is null,
    not a guess."""
    report = book(tmp_path, net=False)
    entry = one(report, kind="net", target="8080", source="kernel")
    assert entry is not None
    print(entry.json())
    assert entry.json()["why"] is None


def test_a_long_list_is_cut_short_and_points_at_json(tmp_path):
    report = book(tmp_path)
    for i in range(40):
        (tmp_path / f"f{i}").write_text("x")
        one(report, kind="read", target=str(tmp_path / f"f{i}"))
    text = report.text(1)
    assert "and 20 more lines. Add --json to see all of them." in text
    assert len(report.json(1)["blocked"]) == 40


def test_a_fork_heavy_loop_keeps_its_count_bounded(tmp_path):
    target = tmp_path / "x"
    target.write_text("x")
    report = book(tmp_path)
    for pid in range(2000):
        entry = one(report, kind="read", target=str(target), pid=pid)
    assert entry.count == 2000
    assert len(entry.counts) <= 256


# ---------------------------------------------------------------------------
# saying it
# ---------------------------------------------------------------------------


def test_a_failure_lists_what_was_blocked_and_how_to_allow_it(tmp_path):
    report = book(tmp_path, net=[443])
    (tmp_path / "a").write_text("x")
    one(report, kind="read", target=str(tmp_path / "a"))
    one(report, kind="net", target="5432 10.0.0.2")
    text = report.text(1, ["python", "agent.py"])
    assert text.startswith("hlyn: the command exited with code 1. hlyn blocked 2 things:")
    assert f"allow with --read {tmp_path / 'a'}" in text
    assert "allow with --net 5432" in text
    assert f"to allow all of these: --read {tmp_path / 'a'} --net 5432" in text


def test_a_success_that_was_refused_something_still_says_so(tmp_path):
    report = book(tmp_path)
    one(report, kind="write", target=str(tmp_path / "cache.db"))
    assert "finished, but hlyn blocked 1 thing" in report.text(0)


def test_a_clean_success_says_nothing(tmp_path):
    assert book(tmp_path).text(0) == ""


def test_a_failure_with_nothing_heard_gets_the_general_hint(tmp_path):
    text = book(tmp_path).text(3, [sys.executable, "agent.py"])
    assert "exited with code 3" in text
    assert "Allow it with --read" in text
    assert "hlyn watch --" in text


def test_a_failure_says_why_nothing_could_be_listed(tmp_path):
    report = book(tmp_path)
    report.why = "the system log fell behind"
    assert "could not be listed: the system log fell behind" in report.text(1)


def test_a_seccomp_kill_is_explained_as_such(tmp_path):
    assert "system call hlyn never allows" in book(tmp_path).text(-signal.SIGSYS)


def test_the_command_itself_is_not_named_on_every_line(tmp_path):
    report = book(tmp_path)
    (tmp_path / "a").write_text("x")
    one(report, kind="read", target=str(tmp_path / "a"), by="python3.13")
    one(report, kind="read", target=str(tmp_path / "a"), by="git", pid=2)
    text = report.text(1, ["python3", "agent.py"])
    assert "by git" in text
    assert "python3.13" not in text


def test_removed_secrets_are_named_on_failure_only(tmp_path):
    env = {"OPENAI_API_KEY": "sk", "EDITOR": "vi", "PATH": "/bin", "HLYN_SHIM": "/x"}
    report = Report(Policy(), env=env, cwd=str(tmp_path))
    assert report.env == ["OPENAI_API_KEY", "EDITOR"]
    assert "--env OPENAI_API_KEY" in report.text(1)
    assert report.text(0) == ""


def test_values_never_appear_anywhere(tmp_path):
    env = {"OPENAI_API_KEY": "sk-live-VALUE"}
    report = Report(Policy(), env=env, cwd=str(tmp_path))
    assert "VALUE" not in report.text(1)
    assert "VALUE" not in json.dumps(report.json(1))


def test_removed_lists_secrets_first_and_skips_its_own():
    env = {"B": "1", "A_TOKEN": "t", "HLYN_REPORT": "p", "PATH": "/bin", "_": "/usr/bin/env"}
    assert removed(Policy(), env) == ["A_TOKEN", "B"]
    assert removed(Policy(env=True), env) == []
    assert secret("GITHUB_TOKEN") and secret("db_password") and not secret("EDITOR")


def test_json_carries_everything(tmp_path):
    report = book(tmp_path)
    one(report, kind="write", target=str(tmp_path / "n"))
    out = json.loads(json.dumps(report.json(2)))
    assert out["exit"] == 2
    assert out["blocked"][0]["allow"] == f"--write {tmp_path}"
    assert set(out) == {"exit", "blocked", "more", "unlogged", "system", "removed_env", "why"}
    assert out["unlogged"] == 0
    print("entry:", out["blocked"][0])
    assert set(out["blocked"][0]) == {
        "kind", "target", "allow", "why", "note", "credential", "quiet", "count", "by", "source",
    }


# ---------------------------------------------------------------------------
# nothing from outside reaches the terminal as-is
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    ["\x1b[2J\x1b[31mFAKE", "a\nhlyn: all clear", "\u202etxt.exe", "tab\there", "bad\udcffbyte", "\x9bc"],
)
def test_names_are_made_harmless_before_printing(tmp_path, hostile):
    report = book(tmp_path)
    one(report, kind="write", target=str(tmp_path / hostile), by=hostile, pid=2)
    text = report.text(1, ["python"])
    body = text.replace("\n", "")
    assert body.isprintable(), repr(text)
    assert text.count("\n") == len(text.splitlines())


def test_safe_leaves_ordinary_text_alone():
    assert safe("/home/k/café notes.txt") == "/home/k/café notes.txt"


def test_flags_are_quoted_when_the_shell_needs_it(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/home/k")
    assert flag("--read", "/home/k/my notes") == "--read '~/my notes'"
    assert flag("--read", "/home/k/src") == "--read ~/src"
    assert flag("--read", "/home/k") == "--read ~"
    assert flag("--read", "/srv/data") == "--read /srv/data"


# ---------------------------------------------------------------------------
# the Linux record format
# ---------------------------------------------------------------------------

GOOD = b"hlyn1\tread\topen\t13\t/data/a%09b\t42\tpython3.13\t0\t8"


def test_a_record_parses():
    found = preload.parse(GOOD)
    assert found == Denial("read", "/data/a\tb", "open", "python3.13", 42, 8, "program")


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"hlyn2\tread\topen\t13\t42\tpy\t/a\t0\t1",  # unknown version
        b"hlyn1\tread\topen\t13\t42\tpy\t/a\t0",  # a field short
        b"hlyn1\tread\topen\t13\t42\tpy\t/a\t0\t1\textra",  # a field long
        b"hlyn1\tsteal\topen\t13\t42\tpy\t/a\t0\t1",  # unknown kind
        b"hlyn1\tread\tOPEN;rm\t13\t42\tpy\t/a\t0\t1",  # not an op name
        b"hlyn1\tread\topen\t2\t/a\t42\tpy\t0\t1",  # not a refusal errno
        b"hlyn1\tread\topen\t13\t/a\t-4\tpy\t0\t1",  # not a pid
        b"hlyn1\tread\topen\t13\t/a%ZZ\t42\tpy\t0\t1",  # broken escape
        b"hlyn1\tread\topen\t13\t/a%\t42\tpy\t0\t1",  # dangling escape
        b"hlyn1\tread\topen\t13\t\t42\tpy\t0\t1",  # no target
        b"hlyn1\tread\topen\t13\t/a\t42\t" + b"n" * 100 + b"\t0\t1",  # absurd name
        b"hlyn1\tread\topen\t13\t/a\t42\tpy\t0\t99999999999",  # absurd count
    ],
)
def test_anything_else_is_rejected(bad):
    assert preload.parse(bad) is None


@settings(max_examples=2000, deadline=None)
@given(st.binary(max_size=300))
def test_the_record_parser_never_raises(data):
    preload.parse(data)


@settings(max_examples=500, deadline=None)
@given(st.lists(st.binary(min_size=0, max_size=20), min_size=9, max_size=9))
def test_the_record_parser_survives_well_shaped_garbage(fields):
    preload.parse(b"\t".join([b"hlyn1", *fields[1:]]))


# ---------------------------------------------------------------------------
# the macOS log format
# ---------------------------------------------------------------------------

TAG = "hlyn-" + "ab" * 12


SANDBOX = "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"


def event(message, sender=SANDBOX, process="/kernel"):
    return json.dumps({"eventMessage": message, "senderImagePath": sender, "processImagePath": process})


def test_a_seatbelt_report_parses():
    found = oslog.parse(event(f"Sandbox: python3(4211) deny(1) file-read-data /Users/k/a b.txt\n{TAG}"), TAG)
    assert found == Denial("read", "/Users/k/a b.txt", "file-read-data", "python3", 4211, 1, "kernel")


def test_opening_an_app_or_url_is_named_and_never_suggested(tmp_path):
    """Seatbelt's `lsopen` (macOS `open`, LaunchServices): no field allows it,
    so the report says what it was and what to do instead of counting it as
    plumbing."""
    found = oslog.parse(event(f"Sandbox: open(12) deny(1) lsopen\n{TAG}"), TAG)
    entry = book(tmp_path).add(found)
    print(found, "\n", entry)
    assert (found.kind, found.op) == ("system", "lsopen")
    assert entry.target == "opening an app or URL (open, LaunchServices)" and entry.allow is None
    assert "Open it yourself, outside hlyn" in entry.note


def test_resolved_system_paths_are_shown_as_typed():
    found = oslog.parse(event(f"Sandbox: cat(1) deny(1) file-read-data /private/etc/hosts\n{TAG}"), TAG)
    assert found.target == "/etc/hosts"


@pytest.mark.parametrize(("head", "count"), [
    ("12 duplicate reports for ", 12), ("1 duplicate report for ", 1),
])
def test_batched_reports_carry_their_count(head, count):
    """Seatbelt reports the first of a run of identical refusals at once and
    the rest a moment later in one line, "N duplicate reports for ...", or
    "1 duplicate report for ..." for one. That line can be all that arrives
    when the log is busy, so both spellings are read."""
    found = oslog.parse(event(f"{head}Sandbox: Python(7) deny(1) file-write-create /tmp/x\n{TAG}"), TAG)
    print(repr(head), "->", found)
    assert found is not None and (found.kind, found.target, found.count) == ("write", "/tmp/x", count)


@pytest.mark.parametrize(
    ("message", "kind", "target"),
    [
        ("network-outbound remote:*:5432", "net", "5432"),
        ("network-outbound remote:10.0.0.2:443", "net", "443 10.0.0.2"),
        ("network-bind local:*:8123", "bind", "8123"),
        ("network-outbound /private/var/run/syslog", "net", "unix:/var/run/syslog"),
        ("process-exec* /bin/ls", "exec", "/bin/ls"),
        ("mach-lookup com.apple.foo", "system", "com.apple.foo"),
    ],
)
def test_each_operation_maps_to_a_field(message, kind, target):
    found = oslog.parse(event(f"Sandbox: x(1) deny(1) {message}\n{TAG}"), TAG)
    assert (found.kind, found.target) == (kind, target)


@pytest.mark.parametrize(
    "line",
    [
        event(f"Sandbox: x(1) deny(1) file-read-data /a\nhlyn-{'cd' * 12}"),  # another run's tag
        event(f"Sandbox: x(1) deny(1) file-read-data /a {TAG}"),  # tag not on its own line
        event(f"Sandbox: x(1) deny(1) file-read-data /a\n{TAG}", sender="/usr/bin/logger"),  # forged
        event(f"Sandbox: x(1) deny(1) file-read-data /a\n{TAG}", process="/usr/bin/python3"),  # forged
        event(f"Sandbox: x(1) allow file-read-data /a\n{TAG}"),  # not a refusal
        "not json",
        "[]",
        json.dumps({"eventMessage": 5}),
    ],
)
def test_only_this_runs_kernel_reports_are_believed(line):
    assert oslog.parse(line, TAG) is None


@settings(max_examples=1000, deadline=None)
@given(st.text(max_size=300))
def test_the_log_parser_never_raises(text):
    oslog.parse(text, TAG)
    oslog.parse(event(text), TAG)
    oslog.parse(event(f"Sandbox: {text}\n{TAG}"), TAG)


def test_the_tag_goes_into_the_profile_and_changes_nothing_else():
    from hlyn.core import mac

    plain = mac.profile(Policy())
    tagged = mac.profile(Policy(), TAG)
    assert "(deny default)" in plain
    assert f'(deny default (with message "{TAG}"))' in tagged
    assert tagged.replace(f' (with message "{TAG}")', "") == plain


def test_refusals_that_are_not_paths_are_never_folded_together():
    # Two local sockets share the flag --net-any, which names no folder:
    # folding them used to crash the report (IndexError) and would have
    # printed "2 paths under ..." for things that are not paths.
    report = Report(Policy(net=[443]))
    for path in ("/var/run/a.sock", "/var/run/b.sock"):
        report.add(Denial(kind="net", target=f"unix:{path}", op="network-outbound", by="x",
                          pid=1, source="kernel"))
    text = report.text(1, ["x"])
    print(text)
    assert "local socket /var/run/a.sock" in text
    assert "local socket /var/run/b.sock" in text
    assert "paths under" not in text


# ---------------------------------------------------------------------------
# the Linux gate's refusals (host mode, DESIGN-host-allowlisting.md 5.9)
# ---------------------------------------------------------------------------


def gated(tmp_path):
    return book(tmp_path, net=["pypi.org"])


def test_the_gates_refusals_become_lines_with_the_flag_that_allows_each(tmp_path):
    report = gated(tmp_path)
    got = {
        "direct": one(report, kind="net", target="140.82.112.5:443", op="direct", source="gate",
                      allow="--net 140.82.112.5", by="curl"),
        "dns": one(report, kind="net", target="1.1.1.1:53", op="dns", source="gate", allow=""),
        "unix": one(report, kind="net", target="/run/my app/db.sock", op="unix", source="gate",
                    allow="--write '/run/my app'"),
        "refused": one(report, kind="net", target="/run/docker.sock", op="unix", source="gate"),
        "unknown": one(report, kind="net", target="(unknown path)", op="unix", source="gate"),
        "gone": one(report, kind="net", target="127.0.0.1:41000", op="proxy-gone", source="gate"),
    }
    for name, entry in got.items():
        print(f"{name:8} {entry.target!r:40} allow={entry.allow!r} note={entry.note!r}")
    assert got["direct"].allow == "--net 140.82.112.5" and got["direct"].by == {"curl"}
    assert got["dns"].allow is None and got["dns"].note.startswith("DNS")
    assert got["unix"].allow == "--write '/run/my app'"
    assert got["unix"].target == "local socket /run/my app/db.sock"
    assert got["refused"].allow is None and "--net-any if you mean it" in got["refused"].note
    assert got["unknown"].allow is None and "hlyn probe" in got["unknown"].note
    assert got["gone"].allow is None and "network was closed" in got["gone"].note
    assert all(entry.source == "gate" for entry in got.values())


def test_the_keychain_and_the_pasteboard_are_explained_not_counted_as_plumbing(tmp_path):
    """macOS allows only measured services unless the network is open. Two
    refusals a user will meet are worth a line each: the keychain's service
    (it comes with a readable keychain file) and the pasteboard (shared with
    every program, so only an open network allows it)."""
    from hlyn.policy import Policy
    from hlyn.report import Denial, Report

    report = Report(Policy())
    keychain = report.add(Denial(kind="system", target="com.apple.SecurityServer", op="mach-lookup",
                                 by="git-credential-osxkeychain", pid=1, count=1, source="kernel"))
    pasteboard = report.add(Denial(kind="system", target="com.apple.pasteboard.1", op="mach-lookup",
                                   by="pbcopy", pid=1, count=1, source="kernel"))
    for entry in (keychain, pasteboard):
        print(entry.target, "| allow", entry.allow, "|", entry.note)
    assert keychain.target == "the keychain (com.apple.SecurityServer)"
    assert "--read ~/Library/Keychains/login.keychain-db" in keychain.note and keychain.allow is None
    assert pasteboard.target == "the pasteboard (com.apple.pasteboard.1)"
    assert "--net-any" in pasteboard.note and pasteboard.allow is None


def test_a_connection_to_port_0_suggests_no_flag(tmp_path):
    """Seen from pip on macOS: a refused connect to port 0. No entry can name
    port 0 (1-65535), so no flag is suggested."""
    from hlyn.policy import Policy
    from hlyn.report import Denial, Report

    for net in (["pypi.org"], [443], False):
        entry = Report(Policy(net=net)).add(Denial(kind="net", target="0 *", op="connect", by="python3",
                                                   pid=1, count=1, source="kernel"))
        print(net, "->", entry)
        assert entry is None or (entry.allow is None and ":0" not in (entry.note or ""))


def test_a_unix_send_to_a_path_and_a_bound_socket_are_explained(tmp_path):
    """The two unix refusals the pinned swap adds (guard._unix): each says
    what to change in the program, since no grant makes them race-free."""
    report = gated(tmp_path)
    send = one(report, kind="net", target="/run/app/log", op="unix-send", source="gate", allow="--net-any")
    bound = one(report, kind="net", target="/run/app/ctl", op="unix-bound", source="gate", allow="--net-any")
    for entry in (send, bound):
        print(f"{entry.target!r:34} allow={entry.allow!r} note={entry.note!r}")
    assert send.target == "local socket /run/app/log" and bound.target == "local socket /run/app/ctl"
    assert "connect the socket first" in send.note
    assert "bound before connecting" in bound.note
    assert send.allow is None and bound.allow is None


def test_a_flag_the_gate_passes_on_is_checked_not_trusted(tmp_path):
    """The address or path came from the agent's memory: a flag that doesn't
    parse as exactly that entry is dropped, and a unix flag is always built
    by the report from the path, never taken from the event."""
    report = gated(tmp_path)
    forged = one(report, kind="net", target="140.82.112.5:443", op="direct", source="gate",
                 allow="--net 140.82.112.5; rm -rf ~")
    unix = one(report, kind="net", target="/tmp/x.sock", op="unix", source="gate",
               allow="--write / --read ~/.ssh")
    print("forged direct flag ->", forged.allow, "| forged unix flag ->", unix.allow)
    assert forged.allow is None
    assert unix.allow == "--write /tmp"


def test_repeats_reported_by_the_gate_add_up_on_one_line(tmp_path):
    report = gated(tmp_path)
    for count in (1, 4, 2):  # the first at once, then batched repeats (guard.Reporter)
        one(report, kind="net", target="140.82.112.5:443", op="direct", source="gate",
            allow="--net 140.82.112.5", count=count)
    text = report.text(1, ["python3"])
    print(text)
    assert len(report.entries) == 1 and report.items()[0].count == 7
    assert "[7 times]" in text


def test_on_macos_a_direct_connect_with_no_address_says_what_would_allow_a_local_one(tmp_path, monkeypatch):
    """Seatbelt reports a refused connect as `remote:*:PORT`, without the
    address (measured on macOS 27), so the report can't tell a local service
    from anywhere else: no flag is suggested, and the note says which one to
    add if it was a service on this machine. With an address, the flag."""
    monkeypatch.setattr(sys, "platform", "darwin")
    report = book(tmp_path, net=["example.com"])
    unknown = one(report, kind="net", target="55432", op="network-outbound", source="kernel")
    local = one(report, kind="net", target="55433 127.0.0.1", op="network-outbound", source="kernel")
    for entry in (unknown, local):
        print(entry.target, "|", entry.allow, "|", entry.note)
    assert unknown.allow is None
    assert unknown.note.endswith("if it was a service on this machine, allow it with --net localhost:55432")
    assert local.allow == "--net localhost:55433"


@pytest.mark.skipif(sys.platform != "linux", reason="the gate reports direct connects on Linux only")
def test_on_linux_the_preload_copy_of_a_direct_connect_is_left_to_the_gate(tmp_path):
    """The preloaded reporter hears the same refused connect from inside the
    agent. With hosts, the gate's report (from outside) is the one kept, so
    the line isn't there twice. Fast Open sends are the preload's alone."""
    report = gated(tmp_path)
    inside = one(report, kind="net", target="443 140.82.112.5", op="connect")
    outside = one(report, kind="net", target="140.82.112.5:443", op="direct", source="gate",
                  allow="--net 140.82.112.5")
    print("preload's copy:", inside, "| gate's:", outside.target, outside.allow)
    assert inside is None and outside is not None
    assert [entry.target for entry in report.items()] == ["140.82.112.5:443"]


def test_a_refused_udp_socket_in_host_mode_explains_the_lookup(tmp_path):
    report = gated(tmp_path)
    entry = one(report, kind="net", target="UDP", op="udp", source="gate", by="python3")
    print(entry.target, "|", entry.note)
    assert entry.target == "a name lookup or QUIC (UDP)" and entry.allow is None
    assert "ignoring HTTPS_PROXY" in entry.note


def test_many_similar_refusals_read_well(tmp_path):
    """Addresses in numeric order, a reason said once for a run of lines
    that share it, and no forty-flag "allow all" line."""
    report = gated(tmp_path)
    for last in (10, 2, 1, 30, 3, 20, 4, 5, 6, 7):
        one(report, kind="net", target=f"10.0.0.{last}:443", op="direct", source="gate",
            allow=f"--net 10.0.0.{last}")
    text = report.text(1, ["agent"])
    print(text)
    rows = [line for line in text.splitlines() if line.startswith("  net")]
    assert [row.split()[1] for row in rows] == [f"10.0.0.{n}:443" for n in (1, 2, 3, 4, 5, 6, 7, 10, 20, 30)]
    assert rows[0].endswith("(connected directly instead of through HTTPS_PROXY)")
    assert not any("HTTPS_PROXY" in row for row in rows[1:])
    assert "to allow all of these" not in text
    assert "  10 different flags would allow these. Add --json to see each" in text
    few = gated(tmp_path)
    for last in (1, 2):
        one(few, kind="net", target=f"10.0.0.{last}:443", op="direct", source="gate",
            allow=f"--net 10.0.0.{last}")
    assert "  to allow all of these: --net 10.0.0.1 --net 10.0.0.2" in few.text(1, ["agent"])


def test_a_use_record_is_read_only_by_a_listener_that_asked_for_uses():
    # hlyn watch hears allowed calls (errno 0); hlyn run hears refusals. A
    # program can write either kind of line to the pipe, so each listener
    # takes only its own: a "use" never becomes a refusal in a run's report.
    use = GOOD.replace(b"\t13\t", b"\t0\t")
    print(preload.parse(use), preload.parse(use, uses=True), preload.parse(GOOD, uses=True), sep="\n")
    assert preload.parse(use) is None
    assert preload.parse(use, uses=True) is not None
    assert preload.parse(GOOD, uses=True) is None


# ---------------------------------------------------------------------------
# the real thing: `hlyn run --json`, one proxy denial
# ---------------------------------------------------------------------------

_CONNECT = """
import os, socket
host, port = os.environ["HTTPS_PROXY"].rsplit("//")[1].split(":")
s = socket.create_connection((host, int(port)))
s.sendall(b"CONNECT evil.example:443 HTTP/1.1\\r\\nHost: evil.example:443\\r\\n\\r\\n")
print(s.recv(300).decode().splitlines()[0])
"""


def test_hlyn_run_json_names_why_a_proxy_blocked_a_host(tmp_path):
    import subprocess

    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    env = {"PYTHONPATH": src, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--json", "--net", "api.example.com",
         "--", sys.executable, "-c", _CONNECT],
        capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp_path), check=False,
    )
    print(f"exit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    assert "403 hlyn: evil.example:443 is not in --net" in done.stdout
    line = next(row for row in reversed(done.stderr.splitlines()) if row.startswith('{"exit"'))
    net = [item for item in json.loads(line)["blocked"] if item["kind"] == "net"]
    print("the net entry:", json.dumps(net))
    assert len(net) == 1
    assert net[0]["target"] == "evil.example:443" and net[0]["allow"] == "--net evil.example"
    assert net[0]["why"] == "not-listed" and net[0]["source"] == "proxy"
