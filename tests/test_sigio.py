# SPDX-License-Identifier: Apache-2.0
"""The F_SETOWN + SIGIO trick against hlyn's helpers (REMAINING #16k).

Before Linux 7.2 (CVE-2026-72183) a sealed process could point a descriptor's
owner (`F_SETOWN`) at a process group, switch on `O_ASYNC`, and have the
kernel deliver SIGIO (or any `F_SETSIG` signal) past Landlock's signal scope.
A helper with default dispositions dies of SIGIO. The helpers therefore ignore
SIGIO and SIGURG (helpers.py); the confined command must not inherit that,
since ignored dispositions survive exec.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest
from conftest import SRC, enforces, skip_if_too_old

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not enforces(), reason="Landlock's signal scope and the gate are Linux-only"
)

SIGIO, SIGURG = 29, 23

# The sealed agent cannot read /proc, so it says when it has attacked and waits
# on its stdin while the test (outside) reads the helpers' state.
ATTACK = """
import fcntl, os, signal, sys, hlyn

got = hlyn.on(net=["api.example.com"])
gate, proxy = got["helpers"]
decoy = int(sys.argv[1])
print("pids", os.getpid(), gate, proxy, flush=True)
for number in (signal.SIGIO, signal.SIGURG):
    signal.signal(number, lambda *_: None)  # caught, not ignored: the agent is in the decoy's group too

def aim(owner, signo):
    r, w = os.pipe()
    fcntl.fcntl(r, fcntl.F_SETSIG, signo)
    fcntl.fcntl(r, fcntl.F_SETOWN, owner)
    fcntl.fcntl(r, fcntl.F_SETFL, fcntl.fcntl(r, fcntl.F_GETFL) | os.O_ASYNC)
    os.write(w, b"x")
    os.close(w); os.close(r)

try:
    os.kill(decoy, signal.SIGKILL)
    print("plain kill of the decoy: ALLOWED")
except OSError as e:
    print("plain kill of the decoy: errno", e.errno)
for owner in (gate, proxy, -os.getpgid(gate), -os.getpgid(proxy), decoy, -os.getpgrp()):
    for signo in (signal.SIGIO, signal.SIGURG):
        try:
            aim(owner, signo)
        except OSError as e:
            print(f"aim {owner} signal {int(signo)}: errno {e.errno}")
print("attacked", flush=True)
sys.stdin.readline()
# Still answering? The gate refuses a direct connect with EACCES; the proxy
# answers a name not in --net with a 403.
import socket, urllib.request
s = socket.socket(); s.settimeout(5)
try:
    s.connect(("1.1.1.1", 443)); print("gate answers: CONNECTED")
except OSError as e:
    print("gate answers: errno", e.errno)
try:
    urllib.request.urlopen("https://evil.example.net/", timeout=10)
except Exception as e:
    print("proxy answers:", e)
"""


def status(pid: int) -> dict[str, str]:
    """`/proc/<pid>/status` as fields; `{"State": "gone"}` if it has no entry."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            return dict(row.split(":\t", 1) for row in fh.read().splitlines() if ":\t" in row)
    except OSError:
        return {"State": "gone"}


def ignores(pid: int, number: int) -> bool:
    return bool(int(status(pid)["SigIgn"], 16) >> (number - 1) & 1)


def describe(name: str, pid: int) -> None:
    fields = status(pid)
    if "SigIgn" not in fields:
        print(f"{name} pid {pid}: State {fields['State']}")
        return
    print(f"{name} pid {pid}: State {fields['State']}; SigIgn {fields['SigIgn']}; "
          f"SIGIO ignored {ignores(pid, SIGIO)}; SIGURG ignored {ignores(pid, SIGURG)}")


def test_helpers_survive_sigio_sigurg_and_the_f_setown_attack():
    decoy = subprocess.Popen(["sleep", "60"], process_group=0)  # default signals, in the agent's group
    agent = subprocess.Popen(
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {SRC!r})\n" + ATTACK, str(decoy.pid)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        process_group=decoy.pid,
    )
    try:
        lines: list[str] = []
        for row in agent.stdout:
            lines.append(row.rstrip())
            if row.startswith("attacked"):
                break
        print("\n".join(lines))
        if not lines or not lines[-1].startswith("attacked"):
            agent.wait(timeout=60)
            err = agent.stderr.read()
            skip_if_too_old(subprocess.CompletedProcess([], 1, "", err))
            raise AssertionError(f"the agent did not get as far as the attack:\n{err}")
        pids = next(row for row in lines if row.startswith("pids"))
        agent_pid, gate, proxy = (int(word) for word in pids.split()[1:])
        time.sleep(1)
        print("-- after the agent's F_SETOWN attack (pid and group owners, SIGIO and SIGURG):")
        for name, pid in (("agent", agent_pid), ("gate", gate), ("proxy", proxy), ("decoy", decoy.pid)):
            describe(name, pid)
        # Whatever a given kernel lets F_SETOWN reach, a signal that does reach
        # a helper must not kill it: send both, as the kernel would.
        for pid in (gate, proxy):
            os.kill(pid, signal.SIGIO)
            os.kill(pid, signal.SIGURG)
        time.sleep(1)
        print("-- after SIGIO and SIGURG sent straight to each helper:")
        for name, pid in (("gate", gate), ("proxy", proxy)):
            describe(name, pid)
        states = {"gate": status(gate)["State"], "proxy": status(proxy)["State"]}
        ignored = {name: (ignores(pid, SIGIO), ignores(pid, SIGURG))
                   for name, pid in (("gate", gate), ("proxy", proxy)) if states[name] != "gone"}
        agent_ignores = (ignores(agent_pid, SIGIO), ignores(agent_pid, SIGURG))
        agent.stdin.write("go\n")
        agent.stdin.flush()
        rest, err = agent.communicate(timeout=60)
        print(rest, err[-1500:], sep="\n")
    finally:
        decoy.kill()
        decoy.wait()
        agent.kill()
        agent.wait()
    assert agent_ignores == (False, False), "the agent inherited an ignored SIGIO or SIGURG"
    assert states["gate"][0] in "SRD", f"the gate is not alive: {states['gate']}"
    assert states["proxy"][0] in "SRD", f"the proxy is not alive: {states['proxy']}"
    assert ignored == {"gate": (True, True), "proxy": (True, True)}
    assert "gate answers: errno 13" in rest
    assert "proxy answers: <urlopen error Tunnel connection failed: 403" in rest


COMMAND = """
import signal
print("command SIGIO default", signal.getsignal(signal.SIGIO) == signal.SIG_DFL,
      "SIGURG default", signal.getsignal(signal.SIGURG) == signal.SIG_DFL, flush=True)
"""
WANT = "command SIGIO default True SIGURG default True"


def test_a_confined_command_keeps_default_sigio_and_sigurg_under_run_and_spawn():
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--net", "api.example.com", "--",
         sys.executable, "-c", COMMAND],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": SRC}, timeout=120, check=False,
        cwd="/tmp",
    )
    print("hlyn run:", done.stdout, done.stderr[-800:], sep="\n")
    skip_if_too_old(done)
    assert WANT in done.stdout
    spawned = subprocess.run(
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {SRC!r})\nimport hlyn\n"
         f"hlyn.spawn([sys.executable, '-c', {COMMAND!r}], net=['api.example.com'], log=False)"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    print("hlyn.spawn:", spawned.stdout, spawned.stderr[-800:], sep="\n")
    skip_if_too_old(spawned)
    assert WANT in spawned.stdout
