# SPDX-License-Identifier: Apache-2.0
"""A file in a granted folder that also has a name elsewhere is warned about.

Two paths, one file: the kernel checks the path used to open it, so a hard link
named `notes.txt` inside a granted folder reads whatever `.env` it was made from,
and no file name says so. `secret.exposed` now says when the network is open and
a file in the grants has a name the scan did not see. Each test prints what it
said.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from conftest import SRC, enforces

from hlyn import Policy, secret


def tree(tmp_path):
    outside = tmp_path / "outside"
    proj = tmp_path / "project"
    outside.mkdir()
    proj.mkdir()
    (proj / "plain.txt").write_text("hello")
    return outside, proj


def check(proj, **more):
    found = secret.exposed(Policy(read=[str(proj)], net=[443], **more))
    names = sorted(os.path.basename(p) for p in secret.renamed)
    print("found:", [os.path.basename(p) for p in found], "| renamed:", names)
    return found


def test_control_a_folder_of_ordinary_files_is_not_flagged(tmp_path):
    _, proj = tree(tmp_path)
    (proj / "second.txt").write_text("x")
    assert check(proj) == [] and not secret.renamed


def test_an_innocent_name_hard_linked_to_a_secret_outside_is_flagged_and_the_words_say_why(tmp_path):
    outside, proj = tree(tmp_path)
    (outside / "stash.cfg").write_text("API_KEY=SYNTHETIC")
    os.link(outside / "stash.cfg", proj / "notes.txt")
    found = check(proj)
    text = secret.warning(found, cli=True)
    print(text)
    assert [os.path.basename(p) for p in found] == ["notes.txt"] and secret.renamed == set(found)
    assert "hard link" in text and "also has a name elsewhere" in text
    assert "secret file" not in text.split("\n")[0]  # it is not called a secret: nobody knows


def test_a_file_whose_every_name_is_inside_the_grants_is_not_flagged(tmp_path):
    _, proj = tree(tmp_path)
    (proj / "a.txt").write_text("x")
    os.link(proj / "a.txt", proj / "b.txt")
    assert check(proj) == []


def test_both_folders_granted_means_both_names_are_seen(tmp_path):
    outside, proj = tree(tmp_path)
    (outside / "stash.cfg").write_text("x")
    os.link(outside / "stash.cfg", proj / "notes.txt")
    found = secret.exposed(Policy(read=[str(proj), str(outside)], net=[443]))
    print("found:", found)
    assert found == []


def test_nothing_is_said_without_a_network(tmp_path):
    outside, proj = tree(tmp_path)
    (outside / "stash.cfg").write_text("x")
    os.link(outside / "stash.cfg", proj / "notes.txt")
    assert secret.exposed(Policy(read=[str(proj)], net=False)) == []


def test_a_scan_that_stopped_early_does_not_claim_a_name_is_missing(tmp_path, monkeypatch):
    # Both names are inside the grant, but the scan runs out before it reaches the
    # second one. It must not call the first one "named elsewhere".
    _, proj = tree(tmp_path)
    (proj / "plain.txt").unlink()
    (proj / "sub").mkdir()
    (proj / "a.txt").write_text("x")
    os.link(proj / "a.txt", proj / "sub" / "b.txt")
    monkeypatch.setattr(secret, "LOOKS", 2)  # the two top-level entries, then out of budget
    found = secret.exposed(Policy(read=[str(proj)], net=[443]))
    print("found:", found, "| scan stopped early in:", [os.path.basename(c) for c in secret.cut])
    assert secret.cut and found == []
    monkeypatch.setattr(secret, "LOOKS", 20_000)  # control: given the budget, nothing is flagged either
    assert secret.exposed(Policy(read=[str(proj)], net=[443])) == [] and not secret.cut


def test_a_hard_link_to_a_known_secret_is_still_called_a_secret(tmp_path):
    outside, proj = tree(tmp_path)
    (outside / "key").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")
    os.link(outside / "key", proj / "id_ed25519")
    found = check(proj)
    assert [os.path.basename(p) for p in found] == ["id_ed25519"] and not secret.renamed
    assert "secret file" in secret.warning(found, cli=True)


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_hlyn_run_warns_before_the_command_reads_it(tmp_path):
    outside, proj = tree(tmp_path)
    (outside / "stash.cfg").write_text("API_KEY=SYNTHETIC")
    os.link(outside / "stash.cfg", proj / "notes.txt")
    env = {**os.environ, "PYTHONPATH": SRC}
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--read", str(proj),
                           "--net", "443", "--", "cat", str(proj / "notes.txt")],
                          capture_output=True, text=True, check=False, env=env)
    print("stdout:", done.stdout, "\nstderr:", done.stderr)
    assert "hard link" in done.stderr and "notes.txt" in done.stderr
    quiet = subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--read", str(proj),
                            "--net", "443", "--", "true"], capture_output=True, text=True, check=False,
                           env={**env, "PYTHONWARNINGS": "ignore::hlyn.Exposed"})
    assert "hard link" not in quiet.stderr
