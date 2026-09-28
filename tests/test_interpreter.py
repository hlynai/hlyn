# SPDX-License-Identifier: Apache-2.0
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
from conftest import SRC, enforces, skip_if_too_old

from hlyn import interpreter
from hlyn.interpreter import Answer, python, read, sane

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")

# `interpreter.ask` confines the interpreter it questions as its own safety
# mechanism (see interpreter.py); on a kernel below hlyn's floor that inner
# seal fails closed -- correctly, by returning an empty answer rather than
# trusting an unconfined probe -- and a test expecting a *filtered* answer
# instead sees an *absent* one. That is not the escape it looks like, so these
# two tests need a machine where sealing genuinely works, not merely one where
# a backend is present -- gated on `enforces()`, the same real fact `hlyn
# probe` reports, not a local guess at it.
functional = pytest.mark.skipif(not enforces(), reason="this kernel cannot fully seal (see hlyn probe)")


def hlyn(*args, cwd=None):
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": os.path.expanduser("~")}
    if os.environ.get("HLYN_SHIM"):
        env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", *args], capture_output=True, text=True, env=env,
        cwd=cwd, timeout=120, check=False,
    )
    skip_if_too_old(done)
    return done


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
@functional
def test_a_lying_interpreter_can_only_grant_interpreter_shaped_folders(tmp_path):
    good = tmp_path / "lib" / "python3.12"
    good.mkdir(parents=True)
    liar = fake(tmp_path, f"""
        echo '{{"exe": "/bin/sh", "paths": ["/", "{os.path.expanduser('~')}", "/etc", "{good}"]}}'
    """)
    answer = interpreter.ask(liar, os.path.realpath(liar))
    assert answer.reads == (os.path.realpath(good),)
    assert answer.exe is None


@functional
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
def test_the_interpreter_asked_cannot_reach_a_local_socket(tmp_path):
    """The interpreter asked may be anything (a venv's python is a file in
    the project), so it is asked with nothing to talk to: before Linux 7.1
    Landlock doesn't check socket files, and this probe has no gate, so it
    gets a filter that refuses every connect and send outright."""
    import socket as sock
    import tempfile

    # A short folder: macOS allows 104 bytes for a socket's path.
    path = os.path.join(tempfile.mkdtemp(prefix="hlyn-", dir="/tmp"), "s.sock")
    server = sock.socket(sock.AF_UNIX)
    server.bind(path)
    server.listen(4)
    server.setblocking(False)
    (tmp_path / "fakebin").mkdir(exist_ok=True)
    fake_path = tmp_path / "fakebin" / "python3"
    liar = str(fake_path)
    with open(liar, "w") as fh:
        fh.write(f"#!{sys.executable}\n"
                 "import socket\n"
                 f"for _ in range(3):\n"
                 f"    try:\n"
                 f"        socket.socket(socket.AF_UNIX).connect({path!r})\n"
                 f"    except OSError:\n"
                 f"        pass\n"
                 "print('{\"paths\": []}')\n")
    fake_path.chmod(0o755)
    answer = interpreter.ask(liar, os.path.realpath(liar))
    reached = 0
    while True:
        try:
            server.accept()[0].close()
            reached += 1
        except OSError:
            break
    server.close()
    print("answer:", answer, "| the socket was reached", reached, "times")
    assert reached == 0


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


# ---------------------------------------------------------------------------
# the script it is asked to run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("argv", "found"), [
    (["python", "agent.py"], "agent.py"),
    (["python", "agent.py", "--flag", "-c"], "agent.py"),
    (["python", "-u", "agent.py"], "agent.py"),
    (["python", "-uB", "agent.py"], "agent.py"),
    (["python", "-I", "-S", "agent.py"], "agent.py"),
    (["python", "-W", "ignore", "agent.py"], "agent.py"),
    (["python", "-Wignore", "agent.py"], "agent.py"),
    (["python", "-X", "dev", "agent.py"], "agent.py"),
    (["python", "-uX", "dev", "agent.py"], "agent.py"),
    (["python", "--check-hash-based-pycs", "never", "agent.py"], "agent.py"),
    (["python", "--", "agent.py"], "agent.py"),
    (["python", "--", "-odd-name.py"], "-odd-name.py"),
    (["python", "-c", "print(1)", "agent.py"], None),
    (["python", "-uc", "print(1)"], None),
    (["python", "-m", "pkg", "agent.py"], None),
    (["python", "-mpkg"], None),
    (["python", "-"], None),
    (["python", "-i"], None),
    (["python"], None),
])
def test_the_script_is_the_first_argument_that_is_not_an_option(argv, found):
    print(argv, "->", interpreter.script(argv))
    assert interpreter.script(argv) == found


def test_only_an_existing_file_that_is_not_a_credential_is_granted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agent.py").write_text("print('hi')\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "agent.py")
    cases = {
        "agent.py": os.path.realpath(tmp_path / "agent.py"),
        str(tmp_path / "agent.py"): os.path.realpath(tmp_path / "agent.py"),
        "link.py": os.path.realpath(tmp_path / "agent.py"),  # what the kernel checks
        "missing.py": None,
        "pkg": None,  # a folder: granting it would grant everything in it
        ".ssh/id_ed25519": None,
    }
    for name, want in cases.items():
        got = interpreter.runs(["python3", name])
        print(f"python3 {name!r:40} grants {got}")
        assert got == want, name


@here
@functional
def test_hlyn_run_python_agent_py_needs_no_flag_for_the_script(tmp_path):
    """`hlyn run -- python agent.py` runs: the file Python was asked to run
    is readable, as the program itself is runnable. Only that file."""
    (tmp_path / "agent.py").write_text(textwrap.dedent("""
        print("agent ran")
        try:
            open("beside.txt").read()
            print("beside.txt: READ")
        except OSError as exc:
            print("beside.txt:", exc.strerror)
    """))
    (tmp_path / "beside.txt").write_text("not granted")
    done = hlyn("run", "--no-log", "--json", "--", sys.executable, "agent.py", cwd=str(tmp_path))
    print(f"exit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    assert done.returncode == 0
    ran, beside = done.stdout.splitlines()
    assert ran == "agent ran"
    assert beside in ("beside.txt: Operation not permitted", "beside.txt: Permission denied")  # macOS, Linux
    done = hlyn("run", "--no-log", "--no-report", "--", sys.executable, "-c", "open('agent.py')",
                cwd=str(tmp_path))
    print(f"with -c: exit {done.returncode}\n{done.stderr}")
    assert done.returncode == 1 and "PermissionError" in done.stderr


@pytest.mark.parametrize(("line", "found"), [
    (b"#!/bin/sh\n", ("/bin/sh", [])),
    (b"#!/bin/sh -e\n", ("/bin/sh", ["-e"])),
    (b"#! /usr/bin/env python3\n", ("/usr/bin/env", ["python3"])),
    (b"#!/usr/bin/env -S python3 -u\n", ("/usr/bin/env", ["-S python3 -u"])),
    (b"#!/usr/bin/env\tnode\r\n", ("/usr/bin/env", ["node"])),
    (b"print('no line')\n", None),
    (b"#!\n", None),
    (b"#!relative/python\n", None),
])
def test_a_scripts_first_line_names_its_interpreter(tmp_path, line, found):
    tool = tmp_path / "tool"
    tool.write_bytes(line + b"echo body\n")
    print(line, "->", interpreter.shebang(str(tool)))
    assert interpreter.shebang(str(tool)) == found


@pytest.mark.parametrize(("args", "found"), [
    (["python3"], "python3"),
    (["-S python3 -u"], "python3"),
    (["-S", "python3"], "python3"),
    (["-i", "python3"], None),  # env -i: a program found with a cleared environment; not followed
    (["NAME=value", "python3"], "python3"),
    ([], None),
])
def test_env_in_a_first_line_names_the_program_it_starts(args, found):
    print(args, "->", interpreter.env_program(args))
    assert interpreter.env_program(args) == found


@here
@functional
@pytest.mark.parametrize("line", [
    "#!/bin/sh", "#!/usr/bin/env python3", "#!/usr/bin/env -S python3 -u", f"#!{sys.executable}",
])
def test_a_script_runs_by_name_like_any_program(tmp_path, line):
    """`hlyn run -- ./tool` for a script: the kernel runs its interpreter,
    which must read the script. Both come with asking to run it, the way a
    binary's own execute permission does; nothing else does."""
    body = "echo script ran" if line.endswith("sh") else "print('script ran')"
    tool = tmp_path / "tool"
    tool.write_text(f"{line}\n{body}\n")
    tool.chmod(0o755)
    (tmp_path / "beside.txt").write_text("not granted")
    done = hlyn("run", "--no-log", "--json", "--", "./tool", cwd=str(tmp_path))
    print(f"{line}: exit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    assert done.returncode == 0 and done.stdout == "script ran\n"


@here
@functional
def test_a_program_that_cannot_start_is_explained_not_a_traceback(tmp_path):
    tool = tmp_path / "tool"
    tool.write_text("#!/no/such/interpreter\necho unreachable\n")
    tool.chmod(0o755)
    done = hlyn("run", "--no-log", "--no-report", "--", "./tool", cwd=str(tmp_path))
    print(f"exit {done.returncode}\nstderr:\n{done.stderr}")
    assert done.returncode != 0 and "Traceback" not in done.stderr
    assert "hlyn: can't start ./tool" in done.stderr and "/no/such/interpreter" in done.stderr
