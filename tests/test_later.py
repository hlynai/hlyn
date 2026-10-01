# SPDX-License-Identifier: Apache-2.0
"""Files a write grant lets the agent fill in, which something else runs later.

The hole these warn about: the agent writes `.git/hooks/pre-commit`, hlyn
refuses nothing (the folder was granted on purpose), and the command runs
unconfined the next time the person types `git commit`. Neither kernel can
grant a folder minus one file, so the answer is a sentence -- and an error for
a CI job that must not allow it (`-W error::hlyn.Runs`).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from conftest import SRC

from hlyn import later
from hlyn.policy import Policy


def place(root, *paths: str):
    """Make each path under `root`; a trailing slash means a folder."""
    for item in paths:
        full = root / item.rstrip("/")
        if item.endswith("/"):
            full.mkdir(parents=True, exist_ok=True)
        else:
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text("{}\n")
    return root


def names(hits, root):
    return sorted(os.path.relpath(hit, os.path.realpath(root)) for hit in hits)


# ---------------------------------------------------------------------------
# what counts
# ---------------------------------------------------------------------------


def test_a_writable_project_names_what_runs_later(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/", ".claude/settings.json", ".mcp.json", ".envrc",
                 "src/app.py", "README.md")
    hits = later.found(Policy(write=(str(work),)))
    print(names(hits, work))
    assert names(hits, work) == [".claude/settings.json", ".envrc", ".git/hooks", ".mcp.json"]


def test_a_checkout_deeper_in_the_tree_counts_too(tmp_path):
    work = place(tmp_path / "work", "vendor/lib/.git/hooks/", "a/b/c/.envrc")
    hits = later.found(Policy(write=(str(work),)))
    print(names(hits, work))
    assert names(hits, work) == ["a/b/c/.envrc", "vendor/lib/.git/hooks"]


def test_the_agents_own_work_is_not_warned_about(tmp_path):
    # Editing these is the job. Warning every run would teach people to
    # ignore the warning, which is what `secret.exposed` avoids the same way.
    work = place(tmp_path / "work", "CLAUDE.md", "AGENTS.md", "Makefile", "package.json",
                 "pyproject.toml", "setup.py", "Cargo.toml", "conftest.py", "Dockerfile",
                 "docker-compose.yml", ".github/workflows/ci.yml", ".vscode/tasks.json")
    assert later.found(Policy(write=(str(work),))) == []


def test_a_name_that_does_not_exist_yet_is_not_named(tmp_path):
    # Every writable folder has infinitely many names the agent *could*
    # create; the useful warning is "this file, which you run".
    work = place(tmp_path / "work", "src/app.py")
    assert later.found(Policy(write=(str(work),))) == []


def test_nothing_writable_means_nothing_to_say(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    assert later.found(Policy(read=(str(work),))) == []
    assert later.found(Policy(write=False)) == []
    assert later.found(Policy()) == []


def test_a_grant_beside_the_hooks_does_not_reach_them(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/", "out/")
    assert later.found(Policy(write=(str(work / "out"),))) == []


def test_a_file_granted_on_its_own_still_counts(tmp_path):
    work = place(tmp_path / "work", ".envrc")
    hits = later.found(Policy(write=(str(work / ".envrc"),)))
    assert names(hits, work) == [".envrc"]


def test_known_folders_are_left_out(tmp_path, monkeypatch):
    # `hlyn claude` passes Claude Code's own state folder: granted on purpose,
    # explained in the README, so not a surprise to report every run.
    home = place(tmp_path / "home", ".claude/hooks/", ".claude/settings.json")
    monkeypatch.setenv("HOME", str(home))
    work = place(tmp_path / "work", ".git/hooks/")
    plan = Policy(write=(str(home / ".claude"), str(work)))
    loud = later.found(plan)
    quiet = later.found(plan, known=(str(home / ".claude"),))
    print("without known:", len(loud), "| with known:", names(quiet, work))
    assert len(loud) == 3
    assert names(quiet, work) == [".git/hooks"]


def test_write_anywhere_names_the_home_files_that_run_at_login(tmp_path, monkeypatch):
    home = place(tmp_path / "home", ".zshrc", ".bashrc", ".ssh/config", ".gitconfig",
                 "Library/LaunchAgents/", ".config/autostart/", "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    hits = later.found(Policy(write=True))
    print(names(hits, home))
    assert ".zshrc" in names(hits, home) and ".ssh/config" in names(hits, home)
    assert "notes.txt" not in names(hits, home)


def test_the_home_folder_granted_whole_names_them_too(tmp_path, monkeypatch):
    home = place(tmp_path / "home", ".zshrc", ".claude/settings.json", "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    hits = later.found(Policy(write=(str(home),)))
    print(names(hits, home))
    assert set(names(hits, home)) == {".zshrc", ".claude/settings.json"}


def test_a_link_pointing_out_of_the_grant_is_not_counted(tmp_path):
    # The kernel checks the target, so a link to a file outside every grant
    # is not writable. Same rule as `secret.exposed`.
    outside = place(tmp_path / "outside", "real/hooks/")
    work = tmp_path / "work"
    (work / ".git").mkdir(parents=True)
    (work / ".git" / "hooks").symlink_to(outside / "real" / "hooks")
    assert later.found(Policy(write=(str(work),))) == []


def test_the_walk_skips_installed_dependencies(tmp_path):
    # A hook inside node_modules is a dependency's own fixture, and walking
    # it costs more than every other folder together.
    work = place(tmp_path / "work", "node_modules/pkg/.git/hooks/", ".venv/x/.envrc",
                 "target/debug/.envrc")
    assert later.found(Policy(write=(str(work),))) == []


def test_a_wide_tree_is_bounded_and_fast(tmp_path):
    import time

    work = tmp_path / "work"
    for i in range(400):
        (work / f"d{i}" / "deep").mkdir(parents=True)
    place(work, ".git/hooks/")
    start = time.monotonic()
    hits = later.found(Policy(write=(str(work),)))
    spent = time.monotonic() - start
    print(f"{spent:.2f}s over 801 folders")
    assert names(hits, work) == [".git/hooks"]
    assert spent < 10


def test_at_most_twelve_are_named(tmp_path):
    many = [f"p{i}/.envrc" for i in range(30)]
    work = place(tmp_path / "work", *many)
    assert len(later.found(Policy(write=(str(work),)))) == later.SHOWN == 12


# ---------------------------------------------------------------------------
# the words
# ---------------------------------------------------------------------------


def test_the_warning_counts_and_says_what_to_do(tmp_path, monkeypatch):
    work = place(tmp_path / "work", ".git/hooks/", ".mcp.json")
    monkeypatch.chdir(work)
    text = later.warning(later.found(Policy(write=(str(work),))), cli=True)
    print(text)
    assert "can write 2 files that run later" in text
    assert "./.git/hooks" in text and "./.mcp.json" in text
    assert "--write ./out" in text
    assert "PYTHONWARNINGS=ignore::hlyn.Runs" in text


def test_one_file_reads_as_one(tmp_path, monkeypatch):
    work = place(tmp_path / "work", ".envrc")
    monkeypatch.chdir(work)
    text = later.warning(later.found(Policy(write=(str(work),))), cli=True)
    print(text)
    assert "can write 1 file that runs later" in text


def test_the_library_wording_names_python_not_flags(tmp_path, monkeypatch):
    work = place(tmp_path / "work", ".envrc")
    monkeypatch.chdir(work)
    text = later.warning(later.found(Policy(write=(str(work),))), cli=False)
    print(text)
    assert 'write=["./out"]' in text and "--write" not in text
    assert "warnings.filterwarnings" in text


def test_a_file_outside_the_start_folder_is_shown_with_a_tilde(tmp_path, monkeypatch):
    # A path under the folder the command started in reads as ./x; anywhere
    # else in the home folder reads as ~/x.
    home = place(tmp_path / "home", ".zshrc")
    work = place(tmp_path / "work", "src/")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    text = later.warning(later.found(Policy(write=(str(home),))), cli=True)
    print(text)
    assert "~/.zshrc" in text


# ---------------------------------------------------------------------------
# through the command line and the library
# ---------------------------------------------------------------------------


def hlyn(*args: str, cwd=None, env=None):
    where = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin"}
    if os.environ.get("HLYN_SHIM"):
        where["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
    where.update(env or {})
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, timeout=120,
                          cwd=cwd, env=where, check=False)


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_the_command_line_warns_and_still_runs(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-m", "hlyn.cli", "run", "--write", ".", "--no-log", "--no-report",
                "--", "/bin/echo", "ok", cwd=work)
    print(done.stdout, done.stderr)
    assert done.returncode == 0 and "ok" in done.stdout
    assert "1 file that runs later" in done.stderr and "./.git/hooks" in done.stderr


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_warnings_as_errors_refuses_the_run(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-W", "error::hlyn.Runs", "-m", "hlyn.cli", "run", "--write", ".",
                "--no-log", "--no-report", "--", "/bin/echo", "ok", cwd=work)
    print(done.stdout, done.stderr)
    assert done.returncode == 2 and "ok" not in done.stdout
    assert "hlyn: refused:" in done.stderr
    assert "warnings are errors here" in done.stderr


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_the_warning_can_be_silenced(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-m", "hlyn.cli", "run", "--write", ".", "--no-log", "--no-report",
                "--", "/bin/echo", "ok", cwd=work,
                env={"PYTHONWARNINGS": "ignore::hlyn.Runs"})
    print(done.stdout, done.stderr)
    assert done.returncode == 0 and "runs later" not in done.stderr


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_show_warns_without_running_anything(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-m", "hlyn.cli", "show", "--write", ".", cwd=work)
    print(done.stdout, done.stderr)
    assert done.returncode == 0 and "runs later" in done.stderr


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_the_library_warns_before_it_seals(tmp_path):
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-c", f"""
import warnings, hlyn
with warnings.catch_warnings(record=True) as heard:
    warnings.simplefilter("always")
    hlyn.on(write=[{str(work)!r}], log=False)
    print([w.category.__name__ for w in heard])
    print([str(w.message).splitlines()[0] for w in heard if w.category is hlyn.Runs])
""", cwd=work)
    print(done.stdout, done.stderr)
    assert "Runs" in done.stdout and "1 file that runs later" in done.stdout


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
def test_the_library_refuses_before_it_seals_when_warnings_are_errors(tmp_path):
    # Raised before the seal, so the process is left untouched: a test suite
    # can use it to keep a policy that allows hook planting out.
    work = place(tmp_path / "work", ".git/hooks/")
    done = hlyn("-W", "error::hlyn.Runs", "-c", f"""
import hlyn
try:
    hlyn.on(write=[{str(work)!r}], log=False)
    print("SEALED ANYWAY")
except hlyn.Runs as exc:
    print("refused before sealing:", str(exc).splitlines()[0])
    open({str(tmp_path / "proof.txt")!r}, "w").write("still unconfined")
""", cwd=work)
    print(done.stdout, done.stderr)
    assert "refused before sealing:" in done.stdout and "SEALED ANYWAY" not in done.stdout
    assert (tmp_path / "proof.txt").read_text() == "still unconfined"
