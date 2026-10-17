# SPDX-License-Identifier: Apache-2.0
"""What is shown is what is sealed: links in grants and the audit log's place.

A grant naming a link (read, write, exec or tmp) is shown and recorded by what
the kernel grants, its target, and checked again just before the seal. The log
is opened once, as a plain file with one name outside every write grant, and
every writer uses that descriptor: otherwise the agent could delete or replace
the record while hlyn kept writing to the original.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys

import pytest
from conftest import SRC, boot

from hlyn import jail, log
from hlyn.error import Invalid
from hlyn.policy import Policy, linked

REAL = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")


@pytest.fixture
def tree(tmp_path):
    project, secrets = tmp_path / "project", tmp_path / "secrets"
    project.mkdir()
    secrets.mkdir()
    (secrets / "key").write_text("TOPSECRET")
    os.symlink(secrets, project / "src")
    return project, secrets


def test_a_grant_naming_a_link_is_stored_as_what_it_grants(tree):
    project, secrets = tree
    plan = Policy(read=[project / "src"], write=[project / "src"])
    print(plan.read, plan.write)
    assert plan.read == (os.path.realpath(secrets),)
    assert plan.write == (os.path.realpath(secrets),)


def test_the_seal_record_and_hlyn_show_name_the_target(tree, tmp_path):
    project, secrets = tree
    env = {**os.environ, "PYTHONPATH": SRC}
    shown = subprocess.run([sys.executable, "-m", "hlyn.cli", "show", "--read", "./src"],
                           cwd=project, env=env, capture_output=True, text=True, check=False)
    print(shown.stdout[-400:], shown.stderr)
    assert os.path.realpath(secrets) in shown.stdout
    assert f"--read ./src is a link; granting what it names: {os.path.realpath(secrets)}" in shown.stderr
    log = tmp_path / "record.jsonl"
    subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--read", "./src", "--log", str(log), "--",
                    sys.executable, "-c", "pass"], cwd=project, env=env, capture_output=True, check=False)
    seal = next(json.loads(line) for line in log.read_text().splitlines() if '"seal"' in line)
    print("record read:", seal["read"])
    # `hlyn run` may add its own files to the typed list (the report library, on
    # Linux), so the grant is looked for, and the link's own name must be absent.
    assert os.path.realpath(secrets) in seal["read"]
    assert str(project / "src") not in seal["read"]


def test_the_systems_own_aliases_are_not_reported_as_links(tmp_path):
    if not os.path.islink("/tmp"):
        pytest.skip("/tmp is not a link here")
    assert linked(["/tmp/x"]) == []
    assert linked([tmp_path]) == []


def test_a_grant_swapped_for_a_link_after_the_check_is_not_sealed(tree, tmp_path):
    # The policy is checked (and shown) first; then something swaps the
    # folder for a link to the secrets before the seal. The last check refuses.
    project, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    plan = Policy(read=[target])
    os.rmdir(target)
    os.symlink(secrets, target)
    with pytest.raises(Invalid, match="now leads somewhere else") as error:
        jail._unchanged(plan)
    print(error.value)
    jail._unchanged(Policy(read=[project]))  # the control: unchanged grants pass


@REAL
def test_a_swap_between_check_and_seal_is_refused_by_the_real_seal(tree, tmp_path):
    _, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    done = boot(
        f"""
        import os, hlyn
        plan = hlyn.Policy(read=[{str(target)!r}], log=False)
        os.rmdir({str(target)!r}); os.symlink({str(secrets)!r}, {str(target)!r})
        try:
            hlyn.on(plan); print("SEALED", open({str(target / "key")!r}).read())
        except hlyn.Invalid as error:
            print("REFUSED", error)
        """
    )
    print(done.stdout, done.stderr[-300:])
    assert done.stdout.startswith("REFUSED"), done.stdout + done.stderr


@pytest.mark.parametrize("where", ["inside a write grant", "write=True", "inside tmp"])
def test_a_log_the_agent_could_replace_is_refused(tmp_path, where):
    out = tmp_path / "out"
    out.mkdir()
    log = str(out / "audit.jsonl")
    kwargs = {"inside a write grant": {"write": [out]}, "write=True": {"write": True},
              "inside tmp": {"tmp": str(out)}}[where]
    with pytest.raises(Invalid, match="could delete the record") as error:
        Policy(log=log, **kwargs)
    print(error.value)
    Policy(log=str(tmp_path / "audit.jsonl"), write=[out])  # the control: outside, accepted


@REAL
def test_with_the_log_outside_the_agent_cannot_unlink_or_replace_it(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    log = tmp_path / "audit.jsonl"
    env = {**os.environ, "PYTHONPATH": SRC}
    code = (f"import os\ntry:\n    os.unlink({str(log)!r}); print('UNLINKED')\n"
            "except OSError as e:\n    print('REFUSED', e.errno)")
    argv = [sys.executable, "-m", "hlyn.cli", "run", "--write", str(out), "--log", str(log),
            "--", sys.executable, "-c", code]
    done = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    print(done.stdout, done.stderr[-300:])
    assert "REFUSED" in done.stdout
    assert '"kind": "seal"' in log.read_text()



# -- tmp: a read and write grant like any other ------------------------------


def test_a_tmp_naming_a_link_is_refused(tree):
    # A scratch folder has no reason to be a link; one is how an existing folder
    # (here, the secrets) would be passed off as scratch space.
    project, _ = tree
    with pytest.raises(Invalid, match="is a link") as error:
        Policy(tmp=str(project / "src"))
    print(error.value)


def test_a_tmp_is_stored_and_granted_by_real_path(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    plan = Policy(tmp=str(scratch))
    print("tmp:", plan.tmp)
    assert plan.tmp == os.path.realpath(scratch)
    assert plan.tmp in plan.reads() and plan.tmp in plan.writes()


def test_a_tmp_swapped_for_a_link_after_the_check_is_not_sealed(tree, tmp_path):
    _, secrets = tree
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    plan = Policy(tmp=str(scratch))
    os.rmdir(scratch)
    os.symlink(secrets, scratch)
    with pytest.raises(Invalid, match="now leads somewhere else") as error:
        jail._unchanged(plan)
    print(error.value)


@pytest.mark.parametrize("kind", ["a key folder outside $HOME", "a folder holding a key", "home", "shared",
                                  "someone's /"])
def test_a_tmp_that_is_no_place_for_scratch_is_refused(tmp_path, monkeypatch, kind):
    # $HOME is left alone except for "home": a key folder must be refused
    # wherever it is, by its name or by what is in it (as an outside probe found).
    elsewhere = tmp_path / "fake-home"
    (elsewhere / ".ssh").mkdir(parents=True, mode=0o700)
    (elsewhere / ".ssh" / "id_ed25519").write_text("KEY")
    keyed = tmp_path / "work"
    (keyed / "deep" / "er").mkdir(parents=True, mode=0o700)
    keyed.chmod(0o700)
    (keyed / "deep" / "er" / ".env").write_text("OPENAI_API_KEY=sk-test\n")
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    if kind == "home":
        monkeypatch.setenv("HOME", str(elsewhere))
    target = {"a key folder outside $HOME": elsewhere / ".ssh", "a folder holding a key": keyed,
              "home": elsewhere, "shared": shared, "someone's /": "/"}[kind]
    plan = Policy(tmp=str(target), log=False)
    with pytest.raises(Invalid, match="can't be the agent's scratch folder") as error:
        jail._scratch(plan)
    print(error.value)
    fresh = tmp_path / "fresh"  # the control: a new folder is made, private, and accepted
    _, made = jail._scratch(Policy(tmp=str(fresh), log=False))
    assert made == os.path.realpath(fresh) and os.stat(fresh).st_mode & 0o777 == 0o700


@REAL
def test_a_confined_program_cannot_reach_keys_through_a_tmp_link(tmp_path):
    home = tmp_path / "fake-home"  # not $HOME, as in the outside probe
    (home / ".ssh").mkdir(parents=True, mode=0o700)
    (home / ".ssh" / "id_ed25519").write_text("TOPSECRET")
    link = tmp_path / "scratch"
    os.symlink(home / ".ssh", link)
    done = boot(
        f"""
        import hlyn
        try:
            print("READ", hlyn.run(lambda: open({str(link / "id_ed25519")!r}).read(),
                                   hlyn.Policy(tmp={str(link)!r}, log=False)))
        except hlyn.Invalid as error:
            print("REFUSED", error)
        """
    )
    print(done.stdout, done.stderr[-300:])
    assert done.stdout.startswith("REFUSED") and "TOPSECRET" not in done.stdout


# -- exec ---------------------------------------------------------------------


def test_an_exec_naming_a_link_is_stored_as_its_target_and_rechecked(tmp_path):
    tool = tmp_path / "tool"
    os.symlink("/bin/echo", tool)
    plan = Policy(exec=[tool])
    print("exec:", plan.exec)
    assert plan.exec == (os.path.realpath("/bin/echo"),)
    assert linked([tool]) == [(str(tool), os.path.realpath("/bin/echo"))]
    other = tmp_path / "other"
    other.write_text("#!/bin/sh\n")
    swapped = Policy(exec=[other])
    os.unlink(other)
    os.symlink("/bin/sh", other)
    with pytest.raises(Invalid, match="now leads somewhere else") as error:
        jail._unchanged(swapped)
    print(error.value)


@REAL
def test_a_program_named_by_a_link_still_runs(tmp_path):
    tool = tmp_path / "tool"
    os.symlink("/bin/echo", tool)
    env = {**os.environ, "PYTHONPATH": SRC}
    argv = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", "--exec", str(tool),
            "--", str(tool), "still runs"]
    done = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    print(done.stdout, done.stderr)
    assert done.returncode == 0 and done.stdout == "still runs\n"
    assert f"--exec {tool} is a link; granting what it names" in done.stderr


# -- the log: the file itself, opened once -----------------------------------


@pytest.fixture
def logs(tmp_path):
    safe, out = tmp_path / "safe", tmp_path / "out"
    safe.mkdir()
    out.mkdir()
    yield safe, out
    for key in [key for key in log._held if key.startswith(str(tmp_path))]:
        with contextlib.suppress(OSError):
            os.close(log._held.pop(key))


@pytest.mark.parametrize("kind", ["a link", "a hard link"])
def test_a_log_that_is_another_name_for_a_writable_file_is_refused(logs, kind):
    safe, out = logs
    inside, record = out / "audit.jsonl", safe / "audit.jsonl"
    inside.write_text("")
    (os.symlink if kind == "a link" else os.link)(inside, record)
    with pytest.raises(Invalid, match=r"is a link|has another name") as error:
        Policy(log=str(record), write=[out])
    print(error.value)


@pytest.mark.parametrize("swap", ["the file for a link", "the file for a hard link", "the folder for a link"])
def test_a_log_swapped_after_the_check_is_refused_by_every_writer(logs, swap):
    # The policy passes; then the path is changed before hlyn opens it. Both
    # the record's sink and the channel the proxy and gate write denials to
    # refuse, since both go through `log.record`.
    safe, out = logs
    record = safe / "audit.jsonl"
    plan = Policy(log=str(record), write=[out])
    if swap == "the file for a link":
        os.symlink(out / "audit.jsonl", record)
    elif swap == "the file for a hard link":
        (out / "audit.jsonl").write_text("")
        os.link(out / "audit.jsonl", record)
    else:
        os.rmdir(safe)
        os.symlink(out, safe)
    with pytest.raises(Invalid) as sink:
        log.sink(plan.log, plan.writes())
    with pytest.raises(Invalid) as denials, jail._denials(plan):
        pass
    print(sink.value, "|", denials.value, sep="\n")
    log.sink(True)


def test_every_writer_shares_the_one_descriptor_checked(logs):
    safe, _ = logs
    record = safe / "audit.jsonl"
    plan = Policy(log=str(record))
    log.sink(plan.log, plan.writes())
    try:
        with jail._denials(plan) as fd:
            mine, theirs = os.fstat(log.fileno()), os.fstat(fd)
            print("sink", (mine.st_dev, mine.st_ino), "denials", (theirs.st_dev, theirs.st_ino),
                  "held", log._held[str(record)])
            on_disk = os.stat(record)
            ids = {(info.st_dev, info.st_ino) for info in (mine, theirs, on_disk)}
            assert len(ids) == 1
    finally:
        log.sink(True)


def test_a_closed_record_descriptor_is_opened_and_checked_again(logs):
    # A sealed child closes descriptors it doesn't keep (`fds.shut`); the
    # record must then be opened again, through the same checks, not handed
    # back as a number that is closed or now names something else.
    safe, out = logs
    record = safe / "audit.jsonl"
    first = log.record(str(record))
    os.close(first)
    reused = os.open(out / "other", os.O_WRONLY | os.O_CREAT, 0o600)  # may take the same number
    again = log.record(str(record))
    print("first", first, "reused", reused, "again", again)
    assert os.fstat(again).st_ino == os.stat(record).st_ino != os.fstat(reused).st_ino
    os.close(reused)
    os.rename(record, safe / "moved")
    os.symlink(out / "x", record)  # and a swap made meanwhile is refused on that reopen
    os.close(again)
    with pytest.raises(Invalid, match="is a link") as error:
        log.record(str(record))
    print(error.value)


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock opens grants itself; Seatbelt resolves them")
@pytest.mark.parametrize("swap", [True, False], ids=["swapped after the check", "control"])
def test_a_link_swapped_in_after_the_last_check_is_refused_by_the_open_itself(tree, tmp_path, swap):
    # The window `_unchanged` can't close: a swap after it, before the grant
    # is opened for Landlock. Simulated by skipping `_unchanged`. Grants are
    # opened with openat2(RESOLVE_NO_SYMLINKS) (the probe in landlock._paths
    # and `pin` in the shim), so the seal is refused rather than land the rule
    # on the secrets. The control seals the same layout unswapped.
    _, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    (target / "key").write_text("fine")
    done = boot(f"""
        import os, hlyn
        from hlyn import jail
        plan = hlyn.Policy(read=[{str(target)!r}], log=False)
        jail._unchanged = lambda plan: None  # the swap lands after the last check
        if {swap}:
            os.rename({str(target)!r}, {str(target) + ".old"!r})
            os.symlink({str(secrets)!r}, {str(target)!r})
        try:
            hlyn.on(plan)
            print("SEALED", open({str(target / "key")!r}).read())
        except hlyn.Error as error:
            print("REFUSED", error)
        """)
    print(done.stdout, done.stderr[-300:])
    if swap:
        assert done.stdout.startswith("REFUSED")
        assert "a link appeared in it after it was checked" in done.stdout
        assert "TOPSECRET" not in done.stdout
    else:
        assert done.stdout.strip() == "SEALED fine"


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 RENAME_EXCHANGE and Landlock are Linux's")
@pytest.mark.parametrize("guard", ["both checks", "the native open alone"])
def test_a_grant_swapped_back_and_forth_during_sealing_never_reaches_the_other_target(tree, tmp_path, guard):
    # A second process swaps the granted folder and a link to the secrets
    # (atomically, RENAME_EXCHANGE) as fast as it can, while 300 confined
    # children are sealed with the folder granted and then read through its
    # path. Each must end one of three ways: sealed on the folder and reads
    # its own file; sealed on the folder and refused through the link; or
    # refused at the seal. Never the secrets. Both a seal and a refusal must
    # be seen, so the swap really did race the seal.
    _, secrets = tree
    target = tmp_path / "docs"
    target.mkdir()
    (target / "key").write_text("fine")
    spare = tmp_path / "spare"
    os.symlink(secrets, spare)
    done = boot(f"""
        import collections, ctypes, os, signal, hlyn
        libc = ctypes.CDLL(None, use_errno=True)
        plan = hlyn.Policy(read=[{str(target)!r}], log=False, tmp=False)
        if {guard == "the native open alone"}:
            from hlyn import jail
            jail._unchanged = lambda plan: None  # leave only openat2 (the probe and the shim)
        pid = os.fork()
        if pid == 0:
            while True:
                libc.renameat2(-100, {str(target).encode()!r}, -100, {str(spare).encode()!r}, 2)
        def read():
            return open({str(target / "key")!r}).read()
        seen = collections.Counter()
        for _ in range(300):
            try:
                seen["read " + hlyn.run(read, plan)] += 1
            except PermissionError:
                seen["sealed, refused through the link"] += 1
            except FileNotFoundError:
                seen["sealed, path missing mid-swap"] += 1
            except hlyn.Error as error:
                seen["refused at the seal: " + str(error).split(":")[0][:40]] += 1
        os.kill(pid, signal.SIGKILL)
        print(dict(seen))
        """)
    print(done.stdout, done.stderr[-500:])
    seen = eval(done.stdout.strip().splitlines()[-1])  # noqa: S307 - our own child's dict
    assert not any("TOPSECRET" in key for key in seen), seen
    assert seen.get("read fine", 0) > 0, "no seal landed on the folder: the swap may have stopped everything"
    assert sum(n for key, n in seen.items() if key.startswith("refused at the seal")) > 0, \
        "no seal was refused: the swap never raced the seal"


def test_a_record_opened_before_is_checked_against_the_grants_of_each_seal(logs):
    # Opened once with no grants (`hlyn.log.sink(path)` from a program), then
    # asked for by a seal whose write grants cover it: refused, not reused.
    safe, _ = logs
    record = safe / "audit.jsonl"
    log.record(str(record))
    with pytest.raises(Invalid, match="which the agent can write") as error:
        log.record(str(record), [str(safe)])
    print(error.value)


def test_a_record_refused_when_new_leaves_no_file_behind(logs):
    _, out = logs
    record = out / "audit.jsonl"
    with pytest.raises(Invalid, match="which the agent can write") as error:
        log.record(str(record), [str(out)])
    print(error.value, "| left behind:", record.exists())
    assert not record.exists()
    record.write_text("someone's\n")  # a file that was already there is the user's, and stays
    with pytest.raises(Invalid):
        log.record(str(record), [str(out)])
    assert record.read_text() == "someone's\n"
