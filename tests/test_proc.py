# SPDX-License-Identifier: Apache-2.0
"""Linux: programs `hlyn claude` starts get their own /proc, and only the agent's.

Claude Code's Bash tool starts every command as a new process. A `claude`
there aborted (Bun reads /proc/self/cgroup, then `abort()`), and Node's
`process.memoryUsage()` threw EACCES (it reads /proc/self/statm), because
only Claude Code itself had a /proc/PID granted. The command now runs in a pid
namespace with a procfs of its own (src/hlyn/procns.py): every program in the
tree reads its own /proc/self, and nothing outside the tree is there to read.

Real Claude Code against the scripted model (tests/claudemodel.py), as in
tests/test_claude.py. Skipped where the namespaces can't be made (Docker's
default profile, an AppArmor rule against user namespaces): there the command
keeps its own /proc/PID only, as before.
"""

# ruff: noqa: F811, S105, S103, S606
# F811: `place` is a fixture imported from test_claude. S105: the "secret" is a test canary. S103/S606: the
# ordinary-user test opens up its own temp folders; the Ctrl-C test runs a pty child.
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import SRC, enforces
from test_claude import CLAUDE, place, session, show  # noqa: F401 - `place` is a fixture

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux: /proc and namespaces"),
    pytest.mark.skipif(CLAUDE is None, reason="Claude Code (claude) is not installed"),
]

SECRET = "REMOVED-VARIABLE-VALUE-7c1f"
MARKER = "hlyn-argv-marker-9d3e"

# Runs inside the agent's Bash tool: what is in /proc, and whether the removed
# variable or hlyn's own command line is anywhere in it.
LOOK = r'''
import json, os, sys
secret, marker, outside = (a.replace("+", "") for a in sys.argv[1:4])
pids = sorted(int(n) for n in os.listdir("/proc") if n.isdigit())
nonpid = sorted(n for n in os.listdir("/proc") if not n.isdigit())
found, unread = [], {}
def grab(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(1 << 16)
    except OSError as exc:
        return exc
for pid in pids:
    for name in ("environ", "cmdline", "status", "stat", "statm", "cgroup", "maps", "mountinfo"):
        got = grab(f"/proc/{pid}/{name}")
        if isinstance(got, OSError):
            unread[f"{pid}/{name}"] = got.strerror
        elif secret.encode() in got or marker.encode() in got:
            found.append(f"/proc/{pid}/{name}")
    for tid in os.listdir(f"/proc/{pid}/task") if os.path.isdir(f"/proc/{pid}/task") else []:
        for name in ("environ", "cmdline", "stat", "status"):
            got = grab(f"/proc/{pid}/task/{tid}/{name}")
            if not isinstance(got, OSError) and (secret.encode() in got or marker.encode() in got):
                found.append(f"/proc/{pid}/task/{tid}/{name}")
own = grab("/proc/self/environ")
print("LOOK " + json.dumps({
    "pids": pids,
    "nonpid": nonpid,
    "sysctl_readable": not isinstance(grab("/proc/sys/vm/overcommit_memory"), OSError),
    "me": os.getpid(),
    "outside_visible": os.path.exists(f"/proc/{outside}"),
    "outside_cmdline": str(grab(f"/proc/{outside}/cmdline")),
    "pid1_environ": "refused" if isinstance(grab("/proc/1/environ"), OSError) else
                    ("blank" if not grab("/proc/1/environ").strip(b"\0") else "HAS TEXT"),
    "pid1_cmdline": "refused" if isinstance(grab("/proc/1/cmdline"), OSError) else
                    ("blank" if not grab("/proc/1/cmdline").strip(b"\0") else "HAS TEXT"),
    "found": found,
    "own_environ_has_secret": isinstance(own, bytes) and secret.encode() in own,
    "own_statm": str(grab("/proc/self/statm")),
    "unread_pid1": {k: v for k, v in unread.items() if k.startswith("1/")},
}))
'''


MEMORY = 'node -e "console.log(JSON.stringify(process.memoryUsage()))"'


def look(work):
    """The command that runs LOOK, with the secret and the marker split so the program's own command line
    doesn't hold them (it joins them again)."""
    return f"python3 {work / 'look.py'} {SECRET[:8]}+{SECRET[8:]} {MARKER[:8]}+{MARKER[8:]} {os.getpid()}"


def _look(done_model):
    for _error, text in done_model.results():
        for line in text.splitlines():
            if line.startswith("LOOK "):
                return json.loads(line[5:])
    return None


def needs_namespaces():
    from hlyn import procns

    if not procns.possible():
        pytest.skip("pid and user namespaces can't be made here (Docker's default profile, or a policy "
                    "against them): the command keeps its own /proc/PID only")


def test_programs_claude_code_starts_get_their_own_proc(place):
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    home, work = place
    steps = [
        ("Bash", {"command": f"{MEMORY}; echo \"node rc=$?\""}),
        ("Bash", {"command": "claude --version; echo \"claude rc=$?\""}),
        ("Bash", {"command": "echo own=$(cat /proc/self/cgroup) statm=$(cat /proc/self/statm); "
                             "echo \"cat rc=$?\""}),
    ]
    control, free = session(steps, home, work, confined=False)
    show("without hlyn", control, free, steps)
    done, model = session(steps, home, work)
    show("hlyn claude", done, model, steps)

    assert control.returncode == 0 and "rss" in free.results()[0][1], "the control run didn't work"
    assert done.returncode == 0, "Claude Code did not finish under hlyn claude"
    node, version, own = (text for _error, text in model.results())
    assert '"rss"' in node and "node rc=0" in node, f"node's memoryUsage failed: {node!r}"
    assert "(Claude Code)" in version and "claude rc=0" in version, \
        f"a claude started by Claude Code failed: {version!r}"
    assert "cat rc=0" in own and "statm=" in own and "own=" in own, f"/proc/self wasn't readable: {own!r}"


def test_the_agents_proc_holds_only_the_agents_own_processes(place, tmp_path):
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    home, work = place
    flag_dir = tmp_path / MARKER
    flag_dir.mkdir()
    (work / "look.py").write_text(LOOK)
    steps = [("Bash", {"command": look(work)})]
    done, model = session(steps, home, work, flags=("--read", str(flag_dir)), HLYN_TEST_SECRET=SECRET)
    show("hlyn claude", done, model, steps)
    assert done.returncode == 0, "Claude Code did not finish under hlyn claude"
    seen = _look(model)
    assert seen, "the program inside printed nothing"
    print(json.dumps(seen, indent=1))

    # Only the tree: Claude Code, its Bash tool and this program, and hlyn's pid 1. Not this test's process.
    assert seen["pids"][0] == 1 and 1 < len(seen["pids"]) < 20, seen["pids"]
    assert not seen["outside_visible"], "the process that started hlyn is visible in /proc"
    # Only per-process folders (procfs `subset=pid`): no /proc/net, /proc/meminfo or other machine-wide files.
    assert set(seen["nonpid"]) <= {"self", "thread-self"}, seen["nonpid"]
    assert "Errno 2" in seen["outside_cmdline"], seen["outside_cmdline"]  # not there at all
    # Pid 1 is hlyn's own, which holds the removed variable in its environment and the flag's marker
    # in its command line: it overwrote both, so neither says anything (a root agent can read them).
    assert seen["pid1_environ"] in ("refused", "blank"), seen["pid1_environ"]
    assert seen["pid1_cmdline"] in ("refused", "blank"), seen["pid1_cmdline"]
    # Nowhere in /proc, in any process's files, is the removed variable or hlyn's command line.
    assert seen["found"] == [], f"found in {seen['found']}"
    assert not seen["own_environ_has_secret"]
    assert seen["own_statm"].startswith("b'"), "own /proc/self/statm wasn't read"


@pytest.mark.skipif(os.geteuid() != 0, reason="drops to an ordinary user, which needs root")
def test_as_an_ordinary_user_the_view_comes_from_a_user_namespace(place, tmp_path):
    """The same two checks as a user who has no privilege: the namespaces
    come from a user namespace that maps the user to itself."""
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    home, work = place
    (work / "look.py").write_text(LOOK)
    for base in (home, work):
        for root, dirs, files in os.walk(base):
            for name in (root, *(os.path.join(root, n) for n in (*dirs, *files))):
                os.chown(name, 1000, 1000)
    for folder in (tmp_path, *tmp_path.parents):
        if str(folder) in ("/", "/tmp"):
            break
        os.chmod(folder, 0o755)
    steps = [
        ("Bash", {"command": f'{MEMORY}; echo "node rc=$?"; '
                             "claude --version; echo \"claude rc=$?\"; id -u"}),
        ("Bash", {"command": look(work)}),
    ]
    from claudemodel import Model

    with Model(steps) as model:
        env = {"HOME": str(home), "PATH": os.pathsep.join([os.path.dirname(CLAUDE), "/usr/bin", "/bin"]),
               "TERM": "dumb", "SHELL": "/bin/sh", "ANTHROPIC_BASE_URL": model.url,
               "ANTHROPIC_API_KEY": "sk-ant-not-a-real-key", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
               "PYTHONPATH": SRC, "HLYN_TEST_SECRET": SECRET}
        done = subprocess.run(
            [sys.executable, "-m", "hlyn.cli", "claude", "--no-log", "--json", "--", "-p", "go",
             "--setting-sources", "",
             "--permission-mode", "bypassPermissions", "--model", "sonnet", "--output-format", "json",
             "--no-session-persistence"],
            cwd=work, env=env, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
            user=1000, group=1000, check=False)
    show("hlyn claude as uid 1000", done, model, steps)
    assert done.returncode == 0, "Claude Code did not finish under hlyn claude as an ordinary user"
    first, _second = (text for _error, text in model.results())
    assert '"rss"' in first and "node rc=0" in first, first
    assert "(Claude Code)" in first and "claude rc=0" in first, first
    assert first.strip().endswith("1000"), "the command didn't run as the ordinary user"
    seen = _look(model)
    assert seen and seen["found"] == [] and not seen["outside_visible"], seen
    assert seen["pid1_environ"] in ("refused", "blank") and seen["pid1_cmdline"] in ("refused", "blank"), seen


# --- what stands between hlyn and the command: exit status, signals, orphans --------------------------

LAUNCH = """
import os, sys
from hlyn import cli
from hlyn.policy import Policy
own = os.environ.get("OWN", "1") == "1"
sys.exit(cli._launch([sys.executable, "-c", sys.argv[1]], Policy(write=(sys.argv[2],)), own=own, quiet=True))
"""


def launch(code, folder):
    """hlyn's launch with the own-/proc grant, as `hlyn claude` makes it; output to files, so a program
    that outlives the command can't hold this test's pipes open."""
    out, err = open(folder / "out", "w+"), open(folder / "err", "w+")  # noqa: SIM115 - read after the process
    return subprocess.Popen([sys.executable, "-c", LAUNCH, code, str(folder)],
                            env={**os.environ, "PYTHONPATH": SRC},
                            stdin=subprocess.DEVNULL, stdout=out, stderr=err, text=True)


def finish(proc, folder, timeout):
    proc.wait(timeout=timeout)
    return (folder / "out").read_text(), (folder / "err").read_text()


def host_processes_with(token):
    """Pids on this machine whose command line holds `token` (not this process)."""
    found = []
    for name in os.listdir("/proc"):
        if name.isdigit() and int(name) != os.getpid():
            try:
                with open(f"/proc/{name}/cmdline", "rb") as fh:
                    if token.encode() in fh.read():
                        found.append(int(name))
            except OSError:
                pass
    return found


@pytest.mark.parametrize(("code", "expected"), [
    ("import sys; sys.exit(7)", 7),
    ("import os, signal; os.kill(os.getpid(), signal.SIGKILL)", 137),
    ("import os, signal; os.kill(os.getpid(), signal.SIGTERM)", 143),
])
def test_the_commands_exit_status_comes_out_unchanged(tmp_path, code, expected):
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    proc = launch(code, tmp_path)
    _out, err = finish(proc, tmp_path, 60)
    print(f"{code!r}: exit {proc.returncode} (expected {expected}); stderr {err[-300:]!r}")
    assert proc.returncode == expected


def test_a_signal_sent_to_hlyn_reaches_the_command_and_nothing_outlives_it(tmp_path):
    """The command waits for a signal it doesn't handle, with a background
    program of its own. SIGTERM to hlyn's process ends the command (as it does
    without the namespace), and both are gone when hlyn is."""
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    token = "hlyn-orphan-token-5b2a"
    code = (f"import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)  # {token}'])\n"
            f"open({str(tmp_path / 'up')!r}, 'w').close()\n"
            f"time.sleep(60)  # {token}")
    proc = launch(code, tmp_path)
    for _ in range(100):
        if (tmp_path / "up").exists():
            break
        import time

        time.sleep(0.1)
    assert (tmp_path / "up").exists(), "the command didn't start"
    assert len(host_processes_with(token)) >= 2, "the command and its background program should be running"
    import signal

    os.kill(proc.pid, signal.SIGTERM)
    finish(proc, tmp_path, 20)
    print(f"hlyn exit {proc.returncode}; still running with the token: {host_processes_with(token)}")
    assert proc.returncode == 143, "SIGTERM to hlyn didn't end the command with SIGTERM"
    import time

    time.sleep(0.5)
    assert host_processes_with(token) == [], "a program the command started outlived it"


def test_ctrl_c_at_the_terminal_reaches_the_command(tmp_path):
    """The terminal sends Ctrl-C to everything in the command's process group:
    the command, and the two processes around it, which leave it to the
    command (they act only on signals sent by `kill`: `si_code` SI_USER, not
    SI_KERNEL). Measured with a debug line in both: each got `sig=2 code=128`
    and passed nothing on. This test can't tell once from twice: the kernel
    merges two SIGINTs that arrive together, so a planted forward of the
    terminal's signal still printed 1. It shows the real terminal path works."""
    if not enforces():
        pytest.skip("this machine can't enforce")
    needs_namespaces()
    import pty
    import time

    count = tmp_path / "count"
    code = ("import os, signal, time\n"
            f"count = open({str(count)!r}, 'w', buffering=1)\n"
            "signal.signal(signal.SIGINT, lambda *_: (count.write('x'), count.flush()))\n"
            f"open({str(tmp_path / 'up')!r}, 'w').close()\n"
            "time.sleep(4)\n")
    pid, master = pty.fork()
    if pid == 0:
        os.environ["PYTHONPATH"] = SRC
        os.environ["OWN"] = os.environ.get("OWN", "1")
        os.execv(sys.executable, [sys.executable, "-c", LAUNCH, code, str(tmp_path)])
    for _ in range(100):
        if (tmp_path / "up").exists():
            break
        time.sleep(0.1)
    assert (tmp_path / "up").exists(), "the command didn't start"
    os.write(master, b"\x03")
    time.sleep(1)
    heard = count.read_text()
    os.waitpid(pid, 0)
    print(f"Ctrl-C heard {len(heard)} time(s)")
    assert heard == "x", f"the command heard Ctrl-C {len(heard)} times, not once"


JOB_AGENT = """
import os, signal, sys
signal.signal(signal.SIGINT, lambda *a: (print("agent got INT", flush=True), sys.exit(130)))
print("agent ready", flush=True)
print("agent read:", sys.stdin.readline().strip(), flush=True)
sys.stdin.readline()
"""


@pytest.mark.parametrize("own", [False, True], ids=["plain", "own proc"])
def test_ctrl_z_fg_and_ctrl_c_work_through_the_namespace_layers(tmp_path, own):
    # hlyn claude is interactive: suspending it (Ctrl-Z), resuming it (fg) and
    # interrupting it (Ctrl-C) must reach it through the three processes the
    # pid namespace adds, as they do without them. An interactive bash on a pty.
    import pty
    import re
    import select
    import time

    if not enforces():
        pytest.skip("this machine can't enforce")
    agent = tmp_path / "agent.py"
    agent.write_text(JOB_AGENT)
    launch = (f"import sys; sys.path.insert(0, {SRC!r}); from hlyn import cli; "
              f"from hlyn.policy import Policy; "
              f"sys.exit(cli._launch([sys.executable, {str(agent)!r}], "
              f"Policy(read=({str(agent)!r},), log=False), quiet=True, own={own}))")
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(tmp_path)
        os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-i"],
                  {"PS1": "P> ", "TERM": "dumb", "PATH": "/usr/bin:/bin"})
    seen = ""

    def expect(pattern):
        nonlocal seen
        end = time.time() + 30
        while not re.search(pattern, seen):
            assert time.time() < end, f"never saw {pattern!r}:\n{seen}"
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    seen += os.read(fd, 4096).decode(errors="replace")
                except OSError:
                    break

    try:
        expect("P> ")
        os.write(fd, f"{sys.executable} -c \"{launch}\"\n".encode())
        expect("agent ready")
        os.write(fd, b"\x1a")  # Ctrl-Z
        expect("Stopped")
        os.write(fd, b"fg\n")
        time.sleep(1)
        os.write(fd, b"hello\n")
        expect("agent read: hello")
        os.write(fd, b"\x03")  # Ctrl-C
        expect("agent got INT")
        os.write(fd, b"echo rc=$?\n")
        expect(r"rc=\d+")
    finally:
        print(seen)
        os.write(fd, b"exit\n")
        time.sleep(0.3)
        os.close(fd)
        os.waitpid(pid, 0)
    assert seen.count("agent got INT") == 1 and "rc=130" in seen
