# SPDX-License-Identifier: Apache-2.0
"""`hlyn run` at an interactive shell: job control on a real terminal.

An interactive bash runs on a pseudo-terminal, the way a person's terminal
runs it, and is typed at: `hlyn run -- AGENT`, then Ctrl-Z, `jobs`, `fg`, a
line of input for the agent, and Ctrl-C. In host mode the command runs under
the gate, in its own process group with the terminal handed to it
(gate.py), so this is what checks that the layout is invisible to the
person at the keyboard:

- Ctrl-Z stops the job, and the shell says so and gives its prompt back.
- `fg` continues it, and the agent owns the terminal again: it reads the
  next line typed, rather than being stopped for reading from the background.
- Ctrl-C reaches the agent once (not once directly and again through the
  gate), and the shell sees its exit status.

The same steps run without hosts (the command in hlyn's own group) and with
them. Each test prints the whole terminal session it saw.
"""

from __future__ import annotations

import contextlib
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import textwrap
import time

import pytest
from conftest import SRC, enforces

pytestmark = [
    pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)"),
    pytest.mark.skipif(not shutil.which("bash"), reason="needs bash for an interactive shell"),
]

PROMPT = "hlyn-test> "  # a pattern too: no regex specials

AGENT = textwrap.dedent("""
    import os, signal, sys
    def interrupted(number, frame):
        print("agent got INT", flush=True)
        raise SystemExit(130)
    signal.signal(signal.SIGINT, interrupted)
    print("agent ready", os.getpid(), flush=True)
    print("agent read:", sys.stdin.readline().strip(), flush=True)
    sys.stdin.readline()  # waits here for Ctrl-C
""")


class Terminal:
    """An interactive bash on a pseudo-terminal, with everything it printed."""

    def __init__(self, cwd: str) -> None:
        import pty

        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.path.expanduser("~"),
            "PS1": PROMPT,
            "TERM": "dumb",
            "PYTHONPATH": SRC,
            "BASH_SILENCE_DEPRECATION_WARNING": "1",  # macOS's note that zsh is the default
        }
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd)
            os.execve(shutil.which("bash") or "/bin/bash", ["bash", "--norc", "--noprofile", "-i"], env)  # noqa: S606
        self.seen = ""
        self.pos = 0
        self.expect(PROMPT)

    def send(self, text: str) -> None:
        os.write(self.fd, text.encode())

    def expect(self, pattern: str, timeout: float = 30) -> re.Match[str]:
        """Read until `pattern` appears in what was printed after the last
        match, and return the match."""
        end = time.monotonic() + timeout
        while True:
            found = re.compile(pattern).search(self.seen, self.pos)
            if found:
                self.pos = found.end()
                return found
            left = end - time.monotonic()
            if left <= 0:
                raise AssertionError(f"never saw {pattern!r}; the terminal showed:\n{self.seen}")
            ready, _, _ = select.select([self.fd], [], [], left)
            if ready:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:  # EIO: the shell has gone
                    chunk = b""
                if not chunk:
                    raise AssertionError(f"the terminal closed before {pattern!r}:\n{self.seen}")
                self.seen += chunk.decode(errors="replace").replace("\r\n", "\n")

    def close(self) -> None:
        """End the shell. Its output is read while it exits: macOS drains a
        terminal's output when the last process on it closes it, so a shell
        whose output nobody reads can't finish exiting, even when killed."""
        with contextlib.suppress(OSError):
            self.send("exit\n")
        end = time.monotonic() + 5
        while not os.waitpid(self.pid, os.WNOHANG)[0]:
            if time.monotonic() > end:
                os.kill(self.pid, signal.SIGKILL)
                end = float("inf")
            if select.select([self.fd], [], [], 0.05)[0]:
                with contextlib.suppress(OSError):
                    self.seen += os.read(self.fd, 4096).decode(errors="replace").replace("\r\n", "\n")
        os.close(self.fd)


def state(pid: int) -> str:
    return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True,
                          check=False).stdout.strip()


def stopped(pid: int, timeout: float = 10) -> str:
    end = time.monotonic() + timeout
    while "T" not in state(pid) and time.monotonic() < end:
        time.sleep(0.05)
    return state(pid)


@pytest.mark.parametrize("net", [[], ["--net", "443"], ["--net", "example.com"]],
                         ids=["no network", "ports", "hosts"])
def test_ctrl_z_fg_and_ctrl_c_at_an_interactive_shell(tmp_path, net):
    script = tmp_path / "agent.py"
    script.write_text(AGENT)
    term = Terminal(str(tmp_path))
    try:
        term.send(f"{sys.executable} -m hlyn.cli run --no-log --read {script} {' '.join(net)} "
                  f"-- {sys.executable} {script}\n")
        agent = int(term.expect(r"agent ready (\d+)")[1])

        term.send("\x1a")  # Ctrl-Z
        term.expect(r"Stopped")
        term.expect(PROMPT)
        when_stopped = stopped(agent)
        term.send("jobs\n")
        jobs = term.expect(r"\[1\]\+\s+Stopped[^\n]*")[0]
        term.expect(PROMPT)

        term.send("fg\n")
        time.sleep(0.5)  # let the job take the terminal back before typing at it
        after_fg = state(agent)
        term.send("hello\n")
        term.expect(r"agent read: hello")

        term.send("\x03")  # Ctrl-C
        term.expect(r"agent got INT")
        term.expect(PROMPT)
        term.send("echo status=$?\n")
        status = term.expect(r"status=(\d+)")[1]
        term.expect(PROMPT)
    finally:
        term.close()
        print(f"--- terminal session ({' '.join(net) or 'no network'}) ---\n{term.seen}\n---")
    print(f"agent {agent}: after Ctrl-Z {when_stopped!r}; jobs said {jobs!r}; after fg {after_fg!r}; "
          f"exit status {status}")
    assert "T" in when_stopped and "T" not in after_fg
    assert term.seen.count("agent got INT") == 1
    assert status == "130"


REFUSING = textwrap.dedent("""
    import signal, sys
    def interrupted(number, frame):
        raise SystemExit(130)
    signal.signal(signal.SIGINT, interrupted)
    for path in sys.argv[1:]:
        try:
            open(path)
        except PermissionError:
            pass
    print("agent ready", flush=True)
    sys.stdin.readline()  # waits here for Ctrl-C
""")


@pytest.mark.parametrize("net", [[], ["--net", "443"], ["--net", "example.com"]],
                         ids=["no network", "ports", "hosts"])
def test_ctrl_c_still_gives_the_report(tmp_path, net):
    """Ctrl-C is sent to the terminal's whole foreground job. It must end the
    agent, not what hlyn uses to hear its refusals (on macOS, a `log stream`
    it starts), or the report of what was blocked is lost with it."""
    script = tmp_path / "agent.py"
    script.write_text(REFUSING)
    outside = tmp_path / "outside"
    outside.mkdir()
    # Five files, so five separate reports: macOS's log loses one now and then.
    secrets = [outside / f"secret{i}.txt" for i in range(5)]
    for path in secrets:
        path.write_text("x")
    term = Terminal(str(tmp_path))
    try:
        term.send(f"{sys.executable} -m hlyn.cli run --no-log --read {script} {' '.join(net)} "
                  f"-- {sys.executable} {script} {' '.join(map(str, secrets))}\n")
        term.expect(r"agent ready")
        term.send("\x03")  # Ctrl-C
        term.expect(r"the command exited with code 130")
        term.expect(PROMPT)
    finally:
        term.close()
        print(f"--- terminal session ({' '.join(net) or 'no network'}) ---\n{term.seen}\n---")
    report = term.seen.split("the command exited with code 130", 1)[1]
    assert "fell behind" not in report and "could not be listed" not in report
    assert "secret" in report and "allow with --read" in report
