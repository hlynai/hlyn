# SPDX-License-Identifier: Apache-2.0
"""`hlyn.run(fn)` keeps its confined child out of the caller's process group (Linux).

Before Linux 7.2 a confined program can aim a signal at its whole process group
past Landlock's signal scope. Sharing the caller's group would let it reach the
unconfined caller; in a group of its own there is nobody else in it. Since the
terminal's Ctrl-C then reaches only the caller, an interrupted caller ends the
child's group itself. Each test prints what it observed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from conftest import SRC, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="the kernel behaviour is Linux's"),
    pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)"),
]


def _state(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2]
    except OSError:
        return "gone"


def boot(code: str, **more: object) -> subprocess.Popen[str]:
    return subprocess.Popen([sys.executable, "-c", textwrap.dedent(code)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": SRC},
                            start_new_session=True, **more)


@pytest.mark.parametrize("policy", ["net=False", "net=True", "net=[443]"])
def test_the_child_is_in_a_group_of_its_own_and_the_caller_is_not_in_it(policy):
    proc = boot(f"""
        import os, hlyn
        child = hlyn.run(lambda: (os.getpid(), os.getpgrp()), log=False, {policy})
        print("caller", os.getpid(), "group", os.getpgrp(), "| child", child[0], "group", child[1])
        assert child[1] != os.getpgrp(), "the child shares the caller's group"
        assert child[1] == child[0], "the child should lead its own group"
    """)
    out, err = proc.communicate(timeout=60)
    print(out, err)
    assert proc.returncode == 0, err


@pytest.mark.parametrize("net", ["False", "True"], ids=["through a gate (before ABI 9)", "no gate"])
def test_an_interrupted_caller_ends_the_child_and_what_it_started(tmp_path, net):
    marks = tmp_path / "pids"
    proc = boot(f"""
        import os, time, hlyn

        def work():
            sleeper = os.fork()  # something the child started
            if sleeper == 0:
                time.sleep(300)
                os._exit(0)
            with open({str(marks)!r}, "w") as fh:
                fh.write(f"{{os.getpid()}} {{sleeper}}")
            time.sleep(300)

        try:
            hlyn.run(work, log=False, write=[{str(tmp_path)!r}], net={net})
        except KeyboardInterrupt:
            print("caller interrupted")
    """)
    end = time.monotonic() + 30
    while not marks.exists() and time.monotonic() < end:
        time.sleep(0.05)
    assert marks.exists(), "the child never started"
    time.sleep(0.2)
    pids = [int(item) for item in marks.read_text().split()]
    assert all(os.path.exists(f"/proc/{pid}") for pid in pids), "control: both were running"
    os.kill(proc.pid, signal.SIGINT)  # the terminal's Ctrl-C reaches the caller alone
    out, err = proc.communicate(timeout=30)
    time.sleep(0.5)
    gone = [not os.path.exists(f"/proc/{pid}") or _state(pid) == "Z" for pid in pids]
    print(out, err, "| child and its sleeper gone:", gone)
    assert "caller interrupted" in out and all(gone)
