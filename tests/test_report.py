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
from hlyn.report import LIMIT, Denial, Report, credential, flag, removed, safe, secret

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


def test_an_abstract_socket_outside_the_agent_gets_no_flag(tmp_path):
    entry = one(book(tmp_path), kind="net", target="unix:@other-agent", op="connect")
    assert entry.allow is None
    assert "outside this agent" in entry.note


def test_a_socket_file_refusal_from_inside_the_program_is_not_believed(tmp_path):
    assert one(book(tmp_path), kind="net", target="unix:/run/app.sock", op="connect") is None


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
    assert set(out) == {"exit", "blocked", "more", "system", "removed_env", "why"}


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


def test_a_sandbox_report_parses():
    found = oslog.parse(event(f"Sandbox: python3(4211) deny(1) file-read-data /Users/k/a b.txt\n{TAG}"), TAG)
    assert found == Denial("read", "/Users/k/a b.txt", "file-read-data", "python3", 4211, 1, "kernel")


def test_resolved_system_paths_are_shown_as_typed():
    found = oslog.parse(event(f"Sandbox: cat(1) deny(1) file-read-data /private/etc/hosts\n{TAG}"), TAG)
    assert found.target == "/etc/hosts"


def test_batched_reports_carry_their_count():
    found = oslog.parse(
        event(f"12 duplicate reports for Sandbox: Python(7) deny(1) file-write-create /tmp/x\n{TAG}"), TAG
    )
    assert (found.kind, found.count) == ("write", 12)


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
