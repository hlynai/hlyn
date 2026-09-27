# SPDX-License-Identifier: Apache-2.0
"""Signals: an agent controls what it started, and nothing else.

The boundary is the sandbox itself, as Landlock's signal scope draws it on
Linux (ABI 6) and Seatbelt's `(target same-sandbox)` on macOS: a confined
process may signal itself, its children and theirs, and they may signal it
back; it may not signal a process outside -- one it didn't start, hlyn
itself, or another agent, even one confined by the same policy.

Both halves matter. Without the first, `subprocess.run(timeout=...)`,
`Popen.terminate()` and every tool that stops what it started fail with
`Operation not permitted`; without the second, one agent can kill or
interrupt another. Each test prints what every signal did, and whether it
arrived.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from conftest import SRC, enforces

pytestmark = pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")

PY = sys.executable
ENV = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~")}

# A process that records each SIGUSR1 it gets in BOX/<its pid>, then waits.
TARGET = textwrap.dedent("""
    import os, signal, sys, time
    box = sys.argv[1]
    signal.signal(signal.SIGUSR1, lambda *_: open(os.path.join(box, str(os.getpid())), "w").close())
    print(os.getpid(), flush=True)
    time.sleep(60)
""")

AGENT = textwrap.dedent("""
    import json, os, signal, subprocess, sys, time
    box, target, outsiders = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    said = {}

    def send(name, pid, number=signal.SIGUSR1):
        try:
            os.kill(pid, number)
            said[name] = "sent"
        except OSError as exc:
            said[name] = f"refused: {exc.strerror}"

    # What it started: a child, and a grandchild through a second Python.
    # stderr not inherited: if the agent can't stop them, they mustn't hold
    # the test's pipe open while they wait out their time.
    quiet = {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL, "text": True}
    child = subprocess.Popen([sys.executable, "-c", target, box], **quiet)
    kid = int(child.stdout.readline())
    spawner = "import subprocess as s, sys; s.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]).wait()"
    middle = subprocess.Popen([sys.executable, "-c", spawner, target, box], **quiet)
    grand = int(middle.stdout.readline())
    send("its child", kid)
    send("its grandchild", grand)
    back = subprocess.run(
        [sys.executable, "-c", "import os, signal\\ntry:\\n os.kill(os.getppid(), 0); print('sent')\\n"
         "except OSError as exc: print('refused:', exc.strerror)"], capture_output=True, text=True)
    said["its child, to it"] = back.stdout.strip()
    try:
        subprocess.run(["/bin/sleep", "30"], timeout=0.5)
        said["subprocess.run(timeout=0.5)"] = "returned"
    except subprocess.TimeoutExpired:
        said["subprocess.run(timeout=0.5)"] = "TimeoutExpired, child killed"
    except OSError as exc:
        said["subprocess.run(timeout=0.5)"] = f"refused: {exc.strerror}"
    try:
        child.terminate()
        said["Popen.terminate()"] = f"exit {child.wait(timeout=5)}"
    except OSError as exc:
        said["Popen.terminate()"] = f"refused: {exc.strerror}"
    for name, pid in outsiders.items():
        send(name, pid)
    send("hlyn, its parent", os.getppid())
    for pid in (grand,):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    print(json.dumps(said), flush=True)
""")


def hlyn(*args: str, **kw) -> subprocess.Popen[str]:
    return subprocess.Popen([PY, "-m", "hlyn.cli", "run", "--no-log", "--no-report", *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV, **kw)


@pytest.mark.parametrize("net", [[], ["--net", "example.com"]], ids=["no network", "hosts"])
def test_an_agent_signals_what_it_started_and_nothing_else(tmp_path, net):
    box = tmp_path / "box"
    box.mkdir()
    target = tmp_path / "target.py"
    target.write_text(TARGET)
    agent = tmp_path / "agent.py"
    agent.write_text(AGENT)
    grants = ["--read", str(tmp_path), "--write", str(box), "--exec", PY, "--exec", "/bin/sleep", *net]

    # Outside the agent's sandbox: a process of the same user, and a second
    # agent confined by exactly the same policy in a run of its own.
    unrelated = subprocess.Popen([PY, "-c", TARGET, str(box)], stdout=subprocess.PIPE, text=True)
    peer = hlyn(*grants, "--", PY, str(target), str(box))
    try:
        outsiders = {"an unrelated process": int(unrelated.stdout.readline()),
                     "another agent, same policy": int(peer.stdout.readline())}
        done = subprocess.run([PY, "-m", "hlyn.cli", "run", "--no-log", "--no-report", *grants, "--",
                               PY, str(agent), str(box), TARGET, json.dumps(outsiders)],
                              capture_output=True, text=True, env=ENV, timeout=120, check=False)
        time.sleep(0.3)
    finally:
        for process in (unrelated, peer):
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
    arrived = sorted(int(name) for name in os.listdir(box))
    print(f"exit {done.returncode}\nstderr:\n{done.stderr}")
    said = json.loads(done.stdout.strip().splitlines()[-1])
    for name, what in said.items():
        print(f"{name:32} {what}")
    print("SIGUSR1 arrived at:", arrived, "| outsiders:", outsiders)

    assert said["its child"] == "sent" and said["its grandchild"] == "sent"
    assert said["its child, to it"] == "sent"
    assert said["subprocess.run(timeout=0.5)"] == "TimeoutExpired, child killed"
    assert said["Popen.terminate()"] == f"exit {-signal.SIGTERM}"
    for name in ("an unrelated process", "another agent, same policy", "hlyn, its parent"):
        assert said[name] == "refused: Operation not permitted", name
    assert not set(arrived) & set(outsiders.values())
    assert len(arrived) == 2  # the child and the grandchild, and no one else
