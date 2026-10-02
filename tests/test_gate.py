# SPDX-License-Identifier: Apache-2.0
"""The gate: the sealed program's parent (DESIGN-host-allowlisting.md 5.2).

`gate.become` forks; the child runs the command, the parent turns into the
gate. These tests check what makes that layout invisible from outside, the
`tini` pattern: the original PID stays the command's, every signal sent to it
reaches the command, the command's exit code or death by signal comes back
unchanged, the command gets its own process group, and stopping it stops the
gate. Nothing here seals anything, so it runs on every platform. Each test
prints what it observed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from conftest import SRC

BOOT = textwrap.dedent(f"""
    import os, sys
    sys.path.insert(0, {SRC!r})
    from hlyn import gate
    cmd = sys.argv[2:]
    print("original pid", os.getpid(), flush=True)
    relay = sys.argv[1] == "forward"
    gate.become(lambda: os.execv(cmd[0], cmd), forward=relay, isolate=relay)
""")


def start(mode: str, *cmd: str) -> subprocess.Popen[str]:
    return subprocess.Popen([sys.executable, "-c", BOOT, mode, *cmd], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)


def finish(process: subprocess.Popen[str], timeout: float = 20) -> tuple[int, str, str]:
    out, err = process.communicate(timeout=timeout)
    print(f"returncode {process.returncode}\nstdout:\n{out}stderr:\n{err}")
    return process.returncode, out, err


def child_of(pid: int, timeout: float = 10) -> int:
    """The pid of `pid`'s child, once it exists."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        found = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True,
                               check=False).stdout.split()
        if found:
            return int(found[0])
        time.sleep(0.05)
    raise AssertionError(f"{pid} never had a child")


def state(pid: int) -> str:
    done = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
    return done.stdout.strip()


@pytest.mark.parametrize("code", [0, 7, 255])
def test_the_exit_code_comes_back_unchanged(code):
    got, _, _ = finish(start("forward", "/bin/sh", "-c", f"exit {code}"))
    assert got == code


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGSEGV, signal.SIGABRT, signal.SIGKILL,
                                    signal.SIGUSR1])
def test_a_death_by_signal_comes_back_as_that_signal(number):
    """As tini does, the gate dies by the command's signal. Except on macOS
    for a signal that makes a crash report (SIGSEGV, SIGABRT and the like):
    there a Python dying of it is reported as "Python quit unexpectedly",
    blaming hlyn for the command's crash, so the gate exits with 128 + the
    signal instead, the status a shell gives for that death."""
    reports = _reports()
    got, _, _ = finish(start("forward", "/bin/sh", "-c", f"kill -{int(number)} $$"))
    crash = sys.platform == "darwin" and number in (signal.SIGSEGV, signal.SIGABRT)
    want = 128 + number if crash else -number
    new = _reports() - reports
    for _ in range(30 if number in (signal.SIGSEGV, signal.SIGABRT) else 0):
        if new:
            break
        time.sleep(0.1)  # macOS writes a crash report a moment after the death
        new = _reports() - reports
    print(f"got {got}, wanted {want} ({number.name}); new Python crash reports: {sorted(new)}")
    assert got == want
    assert not new, "the gate left a crash report"


def _reports() -> set[str]:
    """Python crash reports macOS has written for this user (read only)."""
    where = os.path.expanduser("~/Library/Logs/DiagnosticReports")
    if sys.platform != "darwin" or not os.path.isdir(where):
        return set()
    return {name for name in os.listdir(where) if name.startswith("Python")}


def test_the_gate_keeps_the_original_pid_and_the_command_is_its_child():
    process = start("forward", "/bin/sh", "-c", "echo sh $$ parent $PPID; sleep 1")
    got, out, _ = finish(process)
    original = int(out.split("original pid ")[1].split()[0])
    sh, parent = out.split("sh ")[1].split()[0], out.split("parent ")[1].split()[0]
    assert original == process.pid and int(parent) == process.pid and int(sh) != process.pid and got == 0


@pytest.mark.parametrize("number", [
    signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGUSR1, signal.SIGUSR2,
])
def test_a_signal_sent_to_the_original_pid_reaches_the_command(number):
    name = number.name[3:]
    process = start("forward", "/bin/sh", "-c",
                    f"trap 'echo command got {name}; exit 42' {name}; while :; do sleep 0.05; done")
    child_of(process.pid)
    time.sleep(0.5)  # the trap is set once "ready" could be printed; give the shell a beat
    os.kill(process.pid, number)
    got, out, _ = finish(process)
    assert f"command got {name}" in out and got == 42


def test_the_command_gets_its_own_process_group():
    process = start("forward", "/bin/sleep", "2")
    kid = child_of(process.pid)
    groups = (os.getpgid(process.pid), os.getpgid(kid))
    print(f"gate {process.pid} in group {groups[0]}; command {kid} in group {groups[1]}")
    os.kill(process.pid, signal.SIGTERM)
    finish(process)
    assert groups[1] == kid and groups[0] != groups[1]


def test_stopping_the_command_stops_the_gate_and_continuing_the_gate_continues_both():
    process = start("forward", "/bin/sh", "-c", "sleep 1; echo woke")
    kid = child_of(process.pid)
    os.kill(kid, signal.SIGSTOP)
    end = time.monotonic() + 5
    while "T" not in state(process.pid) and time.monotonic() < end:
        time.sleep(0.05)
    stopped = (state(process.pid), state(kid))
    os.kill(process.pid, signal.SIGCONT)
    got, out, _ = finish(process)
    print(f"after SIGSTOP to the command: gate {stopped[0]!r}, command {stopped[1]!r}")
    assert "T" in stopped[0] and "T" in stopped[1]
    assert "woke" in out and got == 0


def test_without_forwarding_the_gate_only_waits_and_reports_the_status():
    """`hlyn.run(fn)`'s gate: no forwarding, no new group, same status."""
    got, _, _ = finish(start("wait", "/bin/sh", "-c", "exit 3"))
    assert got == 3
    got, _, _ = finish(start("wait", "/bin/sh", "-c", "kill -TERM $$"))
    assert got == -signal.SIGTERM


def test_a_signal_sent_while_the_gate_starts_never_orphans_the_command():
    """Signals are blocked across the fork and the gate's exec, then handed to
    its handlers. So a TERM sent the moment the command exists -- while the
    gate is still starting its interpreter -- reaches the command, and the
    gate never dies leaving the command running without it."""
    for attempt in range(5):
        process = start("forward", "/bin/sh", "-c", "trap 'echo got TERM; exit 9' TERM; sleep 5 & wait")
        kid = child_of(process.pid)
        os.kill(process.pid, signal.SIGTERM)
        got, _, _ = finish(process)
        try:
            os.kill(kid, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        print(f"attempt {attempt}: gate status {got}, command {kid} still running: {alive}")
        # 9: the trap ran. -SIGTERM: the TERM reached the shell before it set
        # the trap, so it died of it and the gate reproduced that.
        assert got in (9, -signal.SIGTERM) and not alive


def test_the_gate_helper_loads_nothing_slow():
    """A gate starts per hlyn.run(fn) call, from a fresh interpreter when the
    caller has threads (target: under 50 ms a call, design section 9). Each
    of these cost it milliseconds and it needs none of them; an innocent
    import elsewhere brought each back once (FINDINGS.md)."""
    import subprocess

    from conftest import SRC

    probe = (
        "import sys, types; package = types.ModuleType('hlyn'); "
        f"package.__path__ = [{SRC + '/hlyn'!r}]; sys.modules['hlyn'] = package; "
        "import hlyn.gate, hlyn.core.guard, hlyn.core.notify; "
        "print(' '.join(sorted(sys.modules)))"
    )
    done = subprocess.run([sys.executable, "-I", "-S", "-c", probe],
                          capture_output=True, text=True, check=True)
    loaded = set(done.stdout.split())
    slow = {"asyncio", "typing", "ctypes.util", "hlyn.policy", "hlyn.proxy", "subprocess", "platform",
            "argparse"}
    # Python 3.13's dataclasses imports inspect, which imports typing (measured in
    # python:3.13: `typing` loads with no hlyn import of it). So on 3.13+ typing
    # is allowed to arrive that way, and what we check instead is that none of
    # the gate's own modules imports it.
    if sys.version_info >= (3, 13) and "dataclasses" in loaded:
        slow.discard("typing")
        import ast

        for name in ("gate.py", "core/guard.py", "core/notify.py"):
            tree = ast.parse(open(f"{SRC}/hlyn/{name}").read())
            for node in tree.body:  # top level only: `if TYPE_CHECKING:` blocks are inside an `If`
                names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) else [])
                assert "typing" not in names, f"{name} imports typing when loaded"
    print(f"{len(loaded)} modules loaded; slow ones among them: {sorted(loaded & slow)}")
    assert not loaded & slow
