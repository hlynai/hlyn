# SPDX-License-Identifier: Apache-2.0
"""Standard input, output and error: descriptors the agent is born with.

They are already open, so no `--read` or `--write` decides them: what is piped
in reaches the command, and what it prints goes where the parent sent it. That
is documented (SECURITY.md), pinned here as behaviour, and made visible:
`hlyn run` says so when standard input is a file the policy doesn't grant, and
`--no-stdin` gives the command /dev/null instead.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from conftest import SRC

REAL = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")


COPY = "import sys; sys.stdout.write(sys.stdin.read())"


def run(tmp_path, *flags, stdin, stdout=subprocess.PIPE, code=COPY):
    argv = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", *flags,
            "--", sys.executable, "-c", code]
    done = subprocess.run(argv, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, text=True,
                          check=False, env={**os.environ, "PYTHONPATH": SRC}, cwd=tmp_path)
    print(f"flags {flags}\nexit {done.returncode}\nstdout {done.stdout!r}\nstderr {done.stderr[-400:]}")
    return done


@pytest.fixture
def secrets(tmp_path):
    keys = tmp_path / "fake-home" / ".ssh"
    keys.mkdir(parents=True)
    (keys / "id_ed25519").write_text("SYNTHETIC-KEY")
    (tmp_path / "notes.txt").write_text("plain notes")
    return keys / "id_ed25519", tmp_path / "notes.txt"


@REAL
def test_what_is_piped_in_reaches_the_command_whatever_read_says(tmp_path):
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", "--",
         sys.executable, "-c", COPY],
        input="piped data", capture_output=True, text=True, check=False, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": SRC})
    print(done.stdout, done.stderr[-300:])
    assert done.stdout == "piped data" and "standard input is" not in done.stderr


@REAL
def test_a_file_as_standard_input_is_read_and_named_when_no_read_grants_it(tmp_path, secrets):
    key, notes = secrets
    with open(notes) as handle:
        done = run(tmp_path, stdin=handle)
    assert done.stdout == "plain notes"  # the property: it is read, though not granted
    assert f"standard input is {os.path.realpath(notes)}" in done.stderr
    assert "keys or tokens" not in done.stderr and "--no-stdin" in done.stderr
    with open(key) as handle:
        done = run(tmp_path, stdin=handle)
    assert done.stdout == "SYNTHETIC-KEY"
    assert f"standard input is {os.path.realpath(key)}; keys or tokens live there" in done.stderr


@REAL
@pytest.mark.parametrize("granted", ["the file", "its folder"])
def test_a_file_the_policy_grants_is_not_remarked_on(tmp_path, secrets, granted):
    _, notes = secrets
    with open(notes) as handle:
        done = run(tmp_path, "--read", str(notes if granted == "the file" else notes.parent), stdin=handle)
    assert done.stdout == "plain notes" and "standard input is" not in done.stderr


@REAL
def test_no_stdin_gives_the_command_an_empty_input(tmp_path, secrets):
    key, _ = secrets
    with open(key) as handle:
        done = run(tmp_path, "--no-stdin", stdin=handle)
    assert done.returncode == 0 and done.stdout == ""  # EOF at once: nothing of the key arrived
    assert "SYNTHETIC-KEY" not in done.stdout + done.stderr and "standard input is" not in done.stderr
    piped = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", "--no-stdin", "--",
         sys.executable, "-c", "import sys; sys.stdout.write(repr(sys.stdin.read()))"],
        input="piped data", capture_output=True, text=True, check=False, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": SRC})
    print(piped.stdout, piped.stderr[-200:])
    assert piped.stdout == "''"


@REAL
def test_output_goes_where_the_parent_sent_it_though_nothing_grants_a_write(tmp_path):
    # The other half of the channel: a command can write to the file its
    # standard output is, without any --write. Documented; the parent chose it.
    target = tmp_path / "out.txt"
    with open(target, "w") as handle:
        done = run(tmp_path, stdin=subprocess.DEVNULL, stdout=handle,
                   code="import sys; sys.stdout.write('written through stdout')")
    assert done.returncode == 0 and target.read_text() == "written through stdout"
    other = tmp_path / "other.txt"
    other.write_text("untouched")
    done = run(tmp_path, stdin=subprocess.DEVNULL,
               code=f"open({str(other)!r}, 'w').write('x')")  # a path is not a descriptor: still refused
    assert done.returncode != 0 and other.read_text() == "untouched"
