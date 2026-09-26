"""Running a Python other than hlyn's own.

The command's interpreter is asked where its files are, confined, and its
answer is checked before anything is granted. These tests pin the checking,
then attack it with an "interpreter" that lies and tries to break out while it
is being asked, then run real interpreters end to end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest
from conftest import SRC

from hlyn import interpreter
from hlyn.interpreter import Answer, python, read, sane

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")


def hlyn(*args, cwd=None):
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": os.path.expanduser("~")}
    if os.environ.get("HLYN_SHIM"):
        env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
    return subprocess.run(
        [sys.executable, "-m", "hlyn.cli", *args], capture_output=True, text=True, env=env,
        cwd=cwd, timeout=120, check=False,
    )


# ---------------------------------------------------------------------------
# what an answer may grant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["python", "python3", "python3.12", "python3.13t", "pypy3.10"])
def test_interpreter_names_are_recognised(name):
    assert python(name, "/x/y")


@pytest.mark.parametrize("name", ["node", "pythonista", "ipython", "python-config", "sh"])
def test_other_programs_are_not_asked(name):
    assert not python(name, f"/x/{name}")


def test_a_real_interpreter_folder_is_accepted(tmp_path):
    lib = tmp_path / "lib" / "python3.12"
    lib.mkdir(parents=True)
    assert sane(str(lib)) == os.path.realpath(lib)


@pytest.mark.parametrize("bad", ["/", "/usr", "/usr/local", "/opt", "/etc", "/tmp", "relative/path", 7, None])
def test_broad_or_malformed_paths_are_refused(bad):
    assert sane(bad) is None


def test_home_and_the_folders_above_the_working_folder_are_refused(tmp_path, monkeypatch):
    work = tmp_path / "a" / "b"
    work.mkdir(parents=True)
    monkeypatch.chdir(work)
    assert sane(str(tmp_path / "a")) is None
    assert sane(str(work)) is None
    assert sane(os.path.expanduser("~")) is None


def test_credentials_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".aws").mkdir()
    assert sane(str(tmp_path / ".aws")) is None


def test_a_malformed_answer_grants_nothing():
    for body in (b"", b"not json", b"[]", b'{"paths": "no"}', b"\xff\xfe", b'{"paths": [1, 2]}'):
        assert read(body, "/usr/bin/python3") == Answer()


def test_a_launcher_is_followed_only_to_an_interpreter(tmp_path):
    real = tmp_path / "bin" / "python3.12"
    real.parent.mkdir()
    real.write_text("")
    real.chmod(0o755)
    other = tmp_path / "bin" / "evil"
    other.write_text("")
    other.chmod(0o755)
    body = json.dumps({"exe": str(real), "paths": []}).encode()
    assert read(body, "/shim/python").exe == str(real)
    body = json.dumps({"exe": str(other), "paths": []}).encode()
    assert read(body, "/shim/python").exe is None


def test_an_answer_is_bounded():
    body = json.dumps({"paths": ["/nonexistent"] * 10_000}).encode()
    assert read(body, "/x/python").reads == ()


# ---------------------------------------------------------------------------
# a hostile "interpreter", asked while confined
# ---------------------------------------------------------------------------


def fake(tmp_path, script: str) -> str:
    """A program called `python3` that runs `script` instead of Python."""
    folder = tmp_path / "fakebin"
    folder.mkdir(exist_ok=True)
    path = folder / "python3"
    path.write_text("#!/bin/sh\n" + textwrap.dedent(script))
    path.chmod(0o755)
    return str(path)


@here
def test_a_lying_interpreter_can_only_grant_interpreter_shaped_folders(tmp_path):
    good = tmp_path / "lib" / "python3.12"
    good.mkdir(parents=True)
    liar = fake(tmp_path, f"""
        echo '{{"exe": "/bin/sh", "paths": ["/", "{os.path.expanduser('~')}", "/etc", "{good}"]}}'
    """)
    answer = interpreter.ask(liar, os.path.realpath(liar))
    assert answer.reads == (os.path.realpath(good),)
    assert answer.exe is None


@here
def test_the_interpreter_cannot_write_or_reach_the_network_while_asked(tmp_path):
    trap = tmp_path / "escaped"
    liar = fake(tmp_path, f"""
        echo pwned > {trap} 2>/dev/null
        (exec 3<>/dev/tcp/127.0.0.1/80) 2>/dev/null && echo net > {trap}.net
        echo '{{"paths": []}}'
    """)
    interpreter.ask(liar, os.path.realpath(liar))
    assert not trap.exists()
    assert not os.path.exists(f"{trap}.net")


@here
def test_an_interpreter_that_hangs_is_given_up_on(tmp_path, monkeypatch):
    import time

    monkeypatch.setattr(interpreter, "WAIT", 0.5)
    slow = fake(tmp_path, "sleep 30\n")
    began = time.monotonic()
    assert interpreter.ask(slow, os.path.realpath(slow)) == Answer()
    assert time.monotonic() - began < 5


@here
def test_hlyns_own_interpreter_is_not_asked():
    assert interpreter.ask(sys.executable, os.path.realpath(sys.executable)) == Answer()


# ---------------------------------------------------------------------------
# real interpreters, end to end
# ---------------------------------------------------------------------------


@pytest.fixture
def venv(tmp_path):
    """A virtualenv with a package only it has."""
    where = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(where)], check=True)
    found = next((where / "lib").glob("python*/site-packages"))
    (found / "onlyhere.py").write_text("WHERE = 'venv'\n")
    return where


@here
def test_a_virtualenv_runs_with_its_own_packages(tmp_path, venv):
    agent = tmp_path / "agent.py"
    agent.write_text("import sys, onlyhere; print('UP', onlyhere.WHERE, sys.prefix)\n")
    done = hlyn("run", "--no-log", "--no-report", "--read", str(tmp_path), "--",
                str(venv / "bin" / "python"), str(agent), cwd=str(tmp_path))
    assert f"UP venv {venv}" in done.stdout or f"UP venv {os.path.realpath(venv)}" in done.stdout, done.stderr


@here
def test_a_launcher_script_runs_the_interpreter_it_names(tmp_path, venv):
    # pyenv and asdf put a small script called `python` first on PATH that
    # starts the real interpreter. It is followed rather than refused.
    shim = tmp_path / "shims" / "python"
    shim.parent.mkdir()
    shim.write_text(f'#!/bin/sh\nexec "{venv / "bin" / "python"}" "$@"\n')
    shim.chmod(0o755)
    agent = tmp_path / "agent.py"
    agent.write_text("import onlyhere; print('UP', onlyhere.WHERE)\n")
    done = hlyn("run", "--no-log", "--no-report", "--read", str(tmp_path), "--", str(shim), str(agent),
                cwd=str(tmp_path))
    assert "UP venv" in done.stdout, done.stderr
