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


def test_a_tmp_naming_a_link_is_stored_and_granted_as_its_target(tree):
    project, secrets = tree
    plan = Policy(tmp=str(project / "src"))
    reads, writes = plan.reads(), plan.writes()
    print("tmp:", plan.tmp)
    assert plan.tmp == os.path.realpath(secrets)
    assert os.path.realpath(secrets) in reads and os.path.realpath(secrets) in writes
    assert str(project / "src") not in reads and str(project / "src") not in writes


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


@pytest.mark.parametrize("kind", ["key folder", "home", "shared", "someone's /"])
def test_a_tmp_that_is_no_place_for_scratch_is_refused(tmp_path, monkeypatch, kind):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True, mode=0o700)
    (home / ".ssh" / "id_ed25519").write_text("KEY")
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    monkeypatch.setenv("HOME", str(home))
    target = {"key folder": home / ".ssh", "home": home, "shared": shared, "someone's /": "/"}[kind]
    link = tmp_path / "scratch"
    os.symlink(target, link)
    plan = Policy(tmp=str(link), log=False)
    with pytest.raises(Invalid, match="can't be the agent's scratch folder") as error:
        jail._scratch(plan)
    print(error.value)
    fresh = tmp_path / "fresh"  # the control: a new folder is made, private, and accepted
    _, made = jail._scratch(Policy(tmp=str(fresh), log=False))
    assert made == os.path.realpath(fresh) and os.stat(fresh).st_mode & 0o777 == 0o700


@REAL
def test_a_confined_program_cannot_reach_keys_through_a_tmp_link(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True, mode=0o700)
    (home / ".ssh" / "id_ed25519").write_text("TOPSECRET")
    link = tmp_path / "scratch"
    os.symlink(home / ".ssh", link)
    done = boot(
        f"""
        import os
        os.environ["HOME"] = {str(home)!r}
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
