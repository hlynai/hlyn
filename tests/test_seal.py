# SPDX-License-Identifier: Apache-2.0
"""A log that shows when it has been edited (`hlyn.seal`, `hlyn log verify`).

Each test builds a real log, changes it the way someone with write access to the
file could, and prints what `verify` said. The limit is tested too: a full
rewrite that rebuilds every seal passes without an anchor and fails with one.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest
from conftest import SRC, enforces

from hlyn import seal


def make(path, runs: int = 3, per_run: int = 4) -> str:
    """A log of `runs` sealed runs; returns the last seal's hash."""
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    last = ""
    try:
        for run in range(runs):
            for number in range(per_run):
                row = {"t": 1.0 + run, "kind": "deny", "what": "read", "target": f"/run{run}/file{number}"}
                os.write(fd, (json.dumps(row) + "\n").encode())
            last = seal.seal(fd)
    finally:
        os.close(fd)
    return last


def show(path, **more):
    out = seal.verify(str(path), **more)
    print(json.dumps(out, indent=1))
    return out


def test_an_untouched_log_is_intact_and_each_seal_chains_to_the_last(tmp_path):
    path = tmp_path / "log.jsonl"
    last = make(path)
    out = show(path)
    assert out["ok"] and out["state"] == "sealed" and out["seals"] == 3 and out["intact"] == 3
    assert out["last"] == last and out["after_last_seal"] == 0


def test_a_changed_byte_is_found_and_names_the_seal(tmp_path):
    path = tmp_path / "log.jsonl"
    make(path)
    data = bytearray(path.read_bytes())
    at = data.index(b"/run1/file2") + 4
    data[at] ^= 1
    path.write_bytes(bytes(data))
    out = show(path)
    assert out["state"] == "edited" and not out["ok"]
    assert any("seal 2" in p and "changed" in p for p in out["problems"])


@pytest.mark.parametrize("how", ["remove a record", "add a record", "swap two records"])
def test_removing_adding_or_reordering_records_is_found(tmp_path, how):
    path = tmp_path / "log.jsonl"
    make(path)
    lines = path.read_bytes().splitlines(keepends=True)
    if how == "remove a record":
        del lines[1]
    elif how == "add a record":
        lines.insert(1, b'{"t": 9, "kind": "allow", "what": "read", "target": "/planted"}\n')
    else:
        lines[0], lines[1] = lines[1], lines[0]
    path.write_bytes(b"".join(lines))
    out = show(path)
    assert out["state"] == "edited" and out["problems"]


def test_removing_a_seal_from_the_middle_is_found(tmp_path):
    path = tmp_path / "log.jsonl"
    make(path)
    lines = path.read_bytes().splitlines(keepends=True)
    seals = [i for i, line in enumerate(lines) if b'"log-seal"' in line]
    del lines[seals[1]]
    path.write_bytes(b"".join(lines))
    out = show(path)
    assert out["state"] == "edited"
    # Said in separate checks: where the next seal starts, which seal it follows, and
    # that the bytes it covers are no longer where it says.
    assert any("starts at byte" in p for p in out["problems"])
    assert any("does not follow the seal before it" in p for p in out["problems"])
    assert any("were changed" in p or ("does not follow" in p and "claims" in p) for p in out["problems"])
    assert out["after_last_seal"] >= 0


def test_a_forged_seal_with_a_correct_hash_in_the_middle_is_found(tmp_path):
    path = tmp_path / "log.jsonl"
    make(path)
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    cut = len(b"".join(lines[:2]))
    covered = data[:cut]
    forged = {"t": 1.0, "kind": "log-seal", "pid": 1, "from": 0, "bytes": cut, "records": 2, "prev": "",
              "sha256": hashlib.sha256(b"\n" + covered).hexdigest()}
    path.write_bytes(covered + (json.dumps(forged) + "\n").encode() + data[cut:])
    out = show(path)
    assert out["state"] == "edited"


def test_records_after_the_last_seal_are_unsealed_not_edited(tmp_path):
    path = tmp_path / "log.jsonl"
    make(path)
    with open(path, "ab") as handle:
        handle.write(b'{"t": 5, "kind": "deny", "what": "read", "target": "/late"}\n')
    out = show(path)
    assert out["state"] == "unsealed" and not out["ok"] and not out["problems"] and out["after_last_seal"] > 0


def test_a_log_with_no_seal_at_all_is_unsealed(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_text('{"kind": "deny"}\n')
    assert show(path)["state"] == "unsealed"


def test_cutting_off_the_last_seal_looks_unsealed_until_you_hold_an_anchor(tmp_path):
    path = tmp_path / "log.jsonl"
    last = make(path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    assert show(path)["state"] == "unsealed"
    out = show(path, anchor=last[:16])
    assert out["state"] == "edited" and any("not the one you kept" in p for p in out["problems"])


def test_a_whole_rewrite_that_rebuilds_every_seal_passes_alone_and_fails_with_an_anchor(tmp_path):
    # The limit, in a test so it stays stated: nothing in the file alone can
    # stop someone who rewrites all of it, seals included. The kept hash can.
    path = tmp_path / "log.jsonl"
    last = make(path)
    forged = tmp_path / "forged.jsonl"
    fd = os.open(forged, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    os.write(fd, b'{"t": 1, "kind": "allow", "what": "read", "target": "/anything"}\n')
    seal.seal(fd)
    os.close(fd)
    assert show(forged)["state"] == "sealed"
    out = show(forged, anchor=last[:16])
    assert out["state"] == "edited"


def test_text_that_looks_like_a_seal_inside_a_record_is_not_one(tmp_path):
    path = tmp_path / "log.jsonl"
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    target = '/x", "kind": "log-seal", "from": 0, "bytes": 0'
    trick = {"t": 1, "kind": "deny", "what": "read", "target": target}
    os.write(fd, (json.dumps(trick) + "\n").encode())
    os.write(fd, b'{"kind": "log-seal"} not json\n')
    os.write(fd, b"x" * 100_000 + b'"kind": "log-seal"\n')  # a very long line is never held
    seal.seal(fd)
    os.close(fd)
    out = show(path)
    assert out["state"] == "sealed" and out["seals"] == 1


def test_writers_and_sealers_running_together_never_make_a_log_look_edited(tmp_path):
    path = tmp_path / "log.jsonl"
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    stop = threading.Event()
    wrote = []

    def writer(name: str) -> None:
        number = 0
        while not stop.is_set():
            row = {"t": 1, "kind": "deny", "what": "read", "target": f"/{name}/{number}"}
            os.write(fd, (json.dumps(row) + "\n").encode())
            number += 1
        wrote.append(number)

    threads = [threading.Thread(target=writer, args=(f"w{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for _ in range(25):
        seal.seal(fd)
    stop.set()
    for thread in threads:
        thread.join()
    os.close(fd)
    out = show(path)
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    print("records written:", sum(wrote), "| lines in the file:", len(rows) - 25)
    assert out["state"] in ("sealed", "unsealed") and not out["problems"] and out["seals"] == 25
    assert len(rows) - 25 == sum(wrote)  # every record is there once; none lost to sealing


def test_two_processes_sealing_one_file_take_turns(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_bytes(b"")
    code = (
        "import os, sys, json\n"
        f"sys.path.insert(0, {SRC!r})\n"
        "from hlyn import seal\n"
        f"fd = os.open({str(path)!r}, os.O_RDWR | os.O_APPEND)\n"
        "for i in range(40):\n"
        "    os.write(fd, (json.dumps({'kind': 'deny', 'pid': os.getpid(), 'i': i}) + '\\n').encode())\n"
        "    seal.seal(fd)\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
    assert [p.wait(timeout=60) for p in procs] == [0] * 4
    out = show(path)
    assert out["state"] == "sealed" and out["seals"] == 160 and out["intact"] == 160


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_hlyn_run_seals_its_log_and_verify_finds_a_later_edit(tmp_path):
    log = tmp_path / "audit" / "run.jsonl"
    log.parent.mkdir()
    env = {**os.environ, "PYTHONPATH": SRC}
    for word in ("first", "second"):
        done = subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--log", str(log), "--no-report",
                               "--", "/bin/echo", word], capture_output=True, text=True, check=False, env=env)
        print(done.stdout, done.stderr)
        assert done.returncode == 0
    verify = [sys.executable, "-m", "hlyn.cli", "log", "verify", str(log)]
    good = subprocess.run(verify, capture_output=True, text=True, check=False, env=env)
    print(good.stdout, good.stderr, "exit", good.returncode)
    assert good.returncode == 0 and "intact  2 of 2" in good.stdout

    data = log.read_bytes()
    log.write_bytes(data.replace(b'"kind": "seal"', b'"kind": "sea1"', 1))
    bad = subprocess.run([*verify, "--json"], capture_output=True, text=True, check=False, env=env)
    print(bad.stdout, "exit", bad.returncode)
    assert bad.returncode == 1 and json.loads(bad.stdout)["state"] == "edited"


def test_verify_says_so_when_the_file_cannot_be_read(tmp_path):
    env = {**os.environ, "PYTHONPATH": SRC}
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "log", "verify", str(tmp_path / "none")],
                          capture_output=True, text=True, check=False, env=env)
    print(done.stderr)
    assert done.returncode == 2 and "can't read" in done.stderr
