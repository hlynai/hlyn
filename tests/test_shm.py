# SPDX-License-Identifier: Apache-2.0
"""`--shm` / `shm=True`: Python `multiprocessing` under hlyn (FINDINGS.md,
"multiprocessing"; REMAINING #16o).

Lock, Queue, Pool and shared_memory each need a POSIX semaphore or shared
memory object. Refused by default (EACCES on Linux, where they are files in
/dev/shm; EPERM on macOS, where they are Seatbelt operations); opt-in with
`--shm`. Every test prints what the confined program saw, and has an
unconfined control, so a failure can't be the script being broken.
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import textwrap

import pytest
from conftest import SRC, enforces

here = pytest.mark.skipif(
    sys.platform not in ("linux", "darwin") or not enforces(), reason="this machine cannot enforce a policy"
)

DEFAULT = errno.EACCES if sys.platform == "linux" else errno.EPERM
ALL_OK = {"Lock": "ok", "Queue": "ok", "shared_memory": "ok", "Pool": "ok"}

# One line per feature: `Lock ok`, or `Lock FAIL <errno name>`.
AGENT = """
import errno, multiprocessing as m
from multiprocessing import shared_memory

def sq(x):
    return x * x

def put():
    q = m.Queue()
    q.put(1)
    return q.get()

def seg():
    s = shared_memory.SharedMemory(create=True, size=16)
    s.close()
    s.unlink()

def pool():
    with m.Pool(2) as p:
        return p.map(sq, [1, 2, 3])

if __name__ == "__main__":
    for name, fn in (("Lock", m.Lock), ("Queue", put), ("shared_memory", seg), ("Pool", pool)):
        try:
            fn()
            print(name, "ok")
        except OSError as exc:
            print(name, "FAIL", errno.errorcode[exc.errno])
"""


@pytest.fixture
def script(tmp_path):
    path = tmp_path / "mp.py"
    path.write_text(AGENT)
    return path


def hlyn(*args: str) -> subprocess.CompletedProcess:
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": os.environ.get("HOME", "/")}
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", *args],
        capture_output=True, text=True, timeout=120, check=False, env=env,
    )
    print(f"$ hlyn run {' '.join(args)}\n{done.stdout}{done.stderr}(exit {done.returncode})")
    return done


def seen(done: subprocess.CompletedProcess) -> dict[str, str]:
    out = {}
    for line in done.stdout.splitlines():
        word = line.split()
        if len(word) >= 2 and word[1] in ("ok", "FAIL"):
            out[word[0]] = " ".join(word[1:])
    return out


def test_unconfined_control(script):
    done = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=60, check=False
    )
    print(done.stdout, done.stderr)
    assert seen(done) == ALL_OK


@here
def test_all_four_work_with_shm(script):
    done = hlyn("--shm", "--read", str(script.parent), "--", sys.executable, str(script))
    assert seen(done) == ALL_OK


@here
def test_all_four_are_refused_by_default(script):
    done = hlyn("--read", str(script.parent), "--", sys.executable, str(script))
    name = errno.errorcode[DEFAULT]
    assert seen(done) == {key: f"FAIL {name}" for key in ALL_OK}


@here
def test_the_notice_says_what_it_opens(script):
    done = hlyn("--shm", "--read", str(script.parent), "--", sys.executable, "-c", "pass")
    assert done.returncode == 0
    lines = [line for line in done.stderr.splitlines() if "--shm" in line]
    assert len(lines) == 1, done.stderr
    assert ("/dev/shm" if sys.platform == "linux" else "POSIX shared memory") in lines[0]
    quiet = hlyn("--read", str(script.parent), "--", sys.executable, "-c", "pass")
    assert "--shm" not in quiet.stderr


@here
def test_the_python_option_matches_the_flag(script):
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {SRC!r})
        import hlyn
        hlyn.spawn([sys.executable, {str(script)!r}], read=[{str(script.parent)!r}], shm=True)
        """)
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=False
    )
    print(done.stdout, done.stderr)
    assert seen(done) == ALL_OK


def test_a_policy_says_it_in_a_file_or_in_code():
    from hlyn import spec
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    assert Policy().shm is False
    assert spec.loads('{"shm": true}', "json").shm is True
    assert spec.shape(Policy(shm=True))["shm"] is True
    assert spec.shape(Policy())["shm"] is False
    with pytest.raises(Invalid, match="shm"):
        Policy(shm="yes")


@pytest.mark.skipif(sys.platform != "darwin", reason="the name filter is Seatbelt's")
@here
def test_macos_allows_only_the_names_python_makes():
    body = textwrap.dedent("""
        import ctypes, errno, os
        libc = ctypes.CDLL(None, use_errno=True)
        libc.sem_open.restype = ctypes.c_void_p
        for name in (b"/mp-probe1", b"/other-probe1"):
            r = libc.sem_open(name, os.O_CREAT, 0o600, 1)
            bad = r in (None, ctypes.c_void_p(-1).value)
            print(name.decode(), errno.errorcode[ctypes.get_errno()] if bad else "ok")
            libc.sem_unlink(name)
        for name in (b"/psm_probe1", b"/other-probe2"):
            fd = libc.shm_open(name, os.O_CREAT | os.O_RDWR, 0o600)
            print(name.decode(), "ok" if fd >= 0 else errno.errorcode[ctypes.get_errno()])
            libc.shm_unlink(name)
        """)
    done = hlyn("--shm", "--", sys.executable, "-c", body)
    got = dict(line.split() for line in done.stdout.splitlines())
    assert got == {
        "/mp-probe1": "ok", "/other-probe1": "EPERM", "/psm_probe1": "ok", "/other-probe2": "EPERM",
    }


@pytest.mark.skipif(sys.platform != "linux", reason="SysV shared memory is gated by seccomp on Linux")
@here
def test_linux_sysv_stays_refused_with_shm():
    body = textwrap.dedent("""
        import ctypes, errno
        libc = ctypes.CDLL(None, use_errno=True)
        r = libc.shmget(0, 4096, 0o1600)
        print("shmget", r if r >= 0 else errno.errorcode[ctypes.get_errno()])
        """)
    done = hlyn("--shm", "--", sys.executable, "-c", body)
    assert done.stdout.split() == ["shmget", "EPERM"]


def test_hlyn_claudes_opening_table_shows_the_grant_only_when_on(monkeypatch):
    from hlyn import claude
    from hlyn.policy import Policy

    class Tty:
        def isatty(self):
            return False

        def write(self, text):
            return len(text)

    monkeypatch.setenv("COLUMNS", "100")
    cwd = os.getcwd()
    base = Policy(read=(cwd,), write=(cwd,), net=("api.anthropic.com",), env=())
    off = claude.describe(base, base, (True, "x"), [], [], None, Tty())
    on = claude.describe(base.with_(shm=True), base, (True, "x"), [], [], None, Tty())
    print(on)
    assert "shared memory" in on
    assert "shared memory" not in off
