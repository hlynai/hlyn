# SPDX-License-Identifier: Apache-2.0
"""`hlyn run` says what it blocked: end to end, against the real kernel.

Every test here runs the real command line, which confines a real child, and
reads the report it prints. On macOS the refusals come from the sandbox's own
reports in the system log, which drops a few percent of them (see
`core/oslog.py`), so a macOS test that needs one particular refusal runs the
command again, up to three times, rather than trusting one report to arrive.
Repeating the attempt inside one run is no second chance: Seatbelt reports
the first of a process's identical refusals at once and the rest as one
"N duplicate reports" line a moment later, usually after the run has ended.

The Linux half also attacks the reporter: the confined program owns the
writing end of the pipe, so it gets to send whatever it likes down it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable

import pytest
from conftest import SRC, TOO_OLD, skip_if_too_old

LINUX = sys.platform == "linux"
MAC = sys.platform == "darwin"


def _ready() -> bool:
    if MAC:
        return True
    if not LINUX:
        return False
    sys.path.insert(0, SRC)
    from hlyn.core import preload

    return preload.find() is not None


here = pytest.mark.skipif(not _ready(), reason="no enforcement backend or no reporter on this platform")
linux = pytest.mark.skipif(not (LINUX and _ready()), reason="the Linux reporter")

# Attempts inside one run: a refusal repeated TRIES times, for the counts.
TRIES = 5 if MAC else 1
# Whole runs of a command whose one refusal a test must see (module docstring).
RUNS = 3 if MAC else 1


def hlyn(*args: str, env: dict[str, str] | None = None, cwd: str | None = None,
         timeout: int = 120) -> subprocess.CompletedProcess:
    base = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": os.path.expanduser("~")}
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        base["HLYN_SHIM"] = shim
    base.update(env or {})
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", *args],
        capture_output=True, text=True, timeout=timeout, env=base, cwd=cwd, check=False,
    )
    # What the run showed, so the log has the report and not just a verdict.
    print(f"$ hlyn {' '.join(args)}\nexit {done.returncode}\nstdout:\n{done.stdout}stderr:\n{done.stderr}")
    skip_if_too_old(done)
    return done


def agent(tmp_path, body: str) -> str:
    """Writes a Python agent into `tmp_path` and returns its path."""
    path = tmp_path / "agent.py"
    path.write_text(textwrap.dedent(body))
    return str(path)


def report(done: subprocess.CompletedProcess) -> dict:
    """The JSON report from a run made with --json."""
    for line in reversed(done.stderr.splitlines()):
        if line.startswith('{"exit"'):
            return json.loads(line)
    raise AssertionError(f"no report was printed:\n{done.stderr}")


def programs(*names: str) -> list[str]:
    """`--exec` flags for these programs, by their real paths.

    Only paths that exist: hlyn refuses to grant one that does not, and which
    shell /bin/sh is (dash, bash) differs between distributions.
    """
    out: list[str] = []
    for name in names:
        if os.path.exists(name):
            out += ["--exec", os.path.realpath(name)]
    return out


def real(text: str) -> str:
    """A path as the report shows it, resolved: `~` expanded, symlinks followed.

    The report writes paths the way people type them -- `~/x`, `/var/...`
    rather than macOS's resolved `/private/var/...` -- so tests compare what
    the paths mean, not how they are spelled.
    """
    return os.path.realpath(os.path.expanduser(text))


def blocked(done: subprocess.CompletedProcess) -> dict[str, dict]:
    """Each refused target, keyed by its resolved path."""
    return {real(item["target"]): item for item in report(done)["blocked"]}


def allows(done: subprocess.CompletedProcess) -> set[str]:
    """Each suggested flag, with its path resolved: `--read /real/path`."""
    out = set()
    for item in report(done)["blocked"]:
        if item["allow"]:
            name, _, value = item["allow"].partition(" ")
            out.add(f"{name} {real(value) if value.startswith(('/', '~')) else value}")
    return out


def run(tmp_path, body: str, *flags: str, until: Callable[[subprocess.CompletedProcess], bool] | None = None,
        **kw) -> subprocess.CompletedProcess:
    script = agent(tmp_path, body)
    argv = ["run", "--no-log", "--json", "--read", script, *flags, "--", sys.executable, script]
    return heard(lambda: hlyn(*argv, **kw), until)


def heard(attempt: Callable[[], subprocess.CompletedProcess],
          until: Callable[[subprocess.CompletedProcess], bool] | None) -> subprocess.CompletedProcess:
    """`attempt()`, run again (RUNS in all) until `until` holds of it. Each run
    is a new process, so a report the log lost isn't lost again for that
    reason; every run's output is printed, the lost ones included."""
    done = attempt()
    for number in range(1, RUNS):
        if until is None or until(done):
            break
        print(f"run {number}: the refusal the test needs wasn't reported; running it again")
        done = attempt()
    return done


@pytest.fixture
def outside(tmp_path_factory):
    """A folder no policy here grants, holding one readable file."""
    box = tmp_path_factory.mktemp("outside")
    (box / "secret.txt").write_text("x")
    return box


# ---------------------------------------------------------------------------
# each kind of refusal is heard and explained
# ---------------------------------------------------------------------------


@here
def test_a_refused_read_is_listed_with_its_flag(tmp_path, outside):
    target = outside / "secret.txt"
    done = run(tmp_path, f"""
        for _ in range({TRIES}):
            try: open({str(target)!r})
            except PermissionError: pass
        raise SystemExit(1)
    """, until=lambda done: real(str(target)) in blocked(done))
    item = blocked(done)[real(str(target))]
    assert item["kind"] == "read"
    assert f"--read {real(str(target))}" in allows(done)


@here
def test_a_refused_new_file_suggests_its_folder(tmp_path, outside):
    done = run(tmp_path, f"""
        for i in range({TRIES}):
            try: open({str(outside)!r} + f"/new{{i}}.txt", "w")
            except PermissionError: pass
    """, until=lambda done: f"--write {real(str(outside))}" in allows(done))
    assert f"--write {real(str(outside))}" in allows(done)


@here
def test_a_refused_program_run_by_a_child_is_listed(tmp_path):
    done = run(tmp_path, f"""
        import subprocess
        for _ in range({TRIES}):
            try: subprocess.run(["/bin/ls"], capture_output=True)
            except PermissionError: pass
    """, until=lambda done: any(item["kind"] == "exec" for item in report(done)["blocked"]))
    execs = [item for item in report(done)["blocked"] if item["kind"] == "exec"]
    assert execs, done.stderr
    assert execs[0]["allow"].startswith("--exec ")
    assert execs[0]["allow"].endswith("/ls")


@here
@pytest.mark.parametrize("call", ["system", "popen"])
def test_a_shell_the_c_library_starts_is_listed(tmp_path, call):
    # glibc starts /bin/sh for system() and popen() through its internal
    # posix_spawn, which no other wrapper sees; before these two were
    # wrapped, the run reported nothing (checked against the previous build).
    done = run(tmp_path, f"""
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.popen.restype = ctypes.c_void_p
        for _ in range({TRIES}):
            libc.{call}(b"echo hi", *([b"r"] if "{call}" == "popen" else []))
    """)
    execs = [item for item in report(done)["blocked"] if item["kind"] == "exec"]
    print(execs)
    assert execs, done.stderr
    shell = os.path.realpath("/bin/sh")
    assert execs[0]["allow"] == f"--exec {shell}"


@here
def test_a_refused_port_is_listed_with_its_flag(tmp_path):
    done = run(tmp_path, f"""
        import socket
        for _ in range({TRIES}):
            try: socket.create_connection(("127.0.0.1", 5432), timeout=1)
            except PermissionError: pass
            except OSError: pass
    """, "--net", "443", until=lambda done: "--net 5432" in allows(done))
    assert "--net 5432" in allows(done), done.stderr


@here
@pytest.mark.skipif(sys.platform != "linux", reason="TCP Fast Open is refused by the Linux backend")
def test_a_refused_fast_open_send_is_listed(tmp_path):
    done = run(tmp_path, f"""
        import socket
        for _ in range({TRIES}):
            try: socket.socket().sendto(b"x", socket.MSG_FASTOPEN, ("127.0.0.1", 5432))
            except OSError: pass
    """, "--net", "443")
    item = next((i for i in report(done)["blocked"] if i["target"].startswith("TCP Fast Open")), None)
    assert item is not None, done.stderr
    assert item["allow"] == "--net-any"
    assert item["target"] == "TCP Fast Open to port 5432 (127.0.0.1)"


@here
def test_a_credential_is_named_and_never_suggested(tmp_path):
    home = tmp_path / "home"
    key = home / ".ssh" / "id_ed25519"
    key.parent.mkdir(parents=True)
    key.write_text("k")
    done = run(tmp_path, f"""
        for _ in range({TRIES}):
            try: open({str(key)!r})
            except PermissionError: pass
    """, env={"HOME": str(home)},
       until=lambda done: any(i["target"].endswith(".ssh/id_ed25519") for i in report(done)["blocked"]))
    # Found by name: the report writes the key relative to the run's HOME,
    # which is not this test process's.
    item = next(i for i in report(done)["blocked"] if i["target"].endswith(".ssh/id_ed25519"))
    assert item["credential"] is True
    assert item["allow"] is None


@here
def test_the_human_report_says_what_to_do(tmp_path, outside):
    target = outside / "secret.txt"
    script = agent(tmp_path, f"""
        for _ in range({TRIES}):
            try: open({str(target)!r})
            except PermissionError: pass
        raise SystemExit(4)
    """)
    done = heard(lambda: hlyn("run", "--no-log", "--read", script, "--", sys.executable, script),
                 lambda done: target.name in done.stderr)
    assert done.returncode == 4
    assert "hlyn: the command exited with code 4. hlyn blocked" in done.stderr
    assert "allow with --read " in done.stderr
    assert target.name in done.stderr


@here
def test_a_success_that_worked_around_a_refusal_still_says_so(tmp_path, outside):
    target = outside / "secret.txt"
    script = agent(tmp_path, f"""
        for _ in range({TRIES}):
            try: open({str(target)!r})
            except PermissionError: pass
    """)
    done = heard(lambda: hlyn("run", "--no-log", "--read", script, "--", sys.executable, script),
                 lambda done: target.name in done.stderr)
    assert done.returncode == 0
    assert "the command finished, but hlyn blocked" in done.stderr


@here
def test_no_report_means_no_report(tmp_path, outside):
    target = outside / "secret.txt"
    script = agent(tmp_path, f"open({str(target)!r})")
    done = hlyn("run", "--no-log", "--no-report", "--read", script, "--", sys.executable, script)
    assert done.returncode == 1
    assert "hlyn blocked" not in done.stderr


@here
def test_refusals_reach_the_log_as_they_happen(tmp_path, outside):
    target = outside / "secret.txt"
    record = tmp_path / "log.jsonl"
    script = agent(tmp_path, f"""
        for _ in range({TRIES}):
            try: open({str(target)!r})
            except PermissionError: pass
    """)

    def denials() -> list[dict]:
        rows = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
        return [row for row in rows if row["kind"] == "deny"]

    heard(lambda: hlyn("run", "--log", str(record), "--read", script, "--", sys.executable, script),
          lambda _: any(real(row["target"]) == real(str(target)) for row in denials()))
    print(record.read_text())
    assert any(real(row["target"]) == real(str(target)) for row in denials())


@here
def test_the_exit_code_is_passed_on_unchanged(tmp_path):
    done = run(tmp_path, "raise SystemExit(7)")
    assert done.returncode == 7
    assert report(done)["exit"] == 7


@here
def test_killing_hlyn_stops_the_command_and_still_reports(tmp_path):
    script = agent(tmp_path, "import time; time.sleep(60)")
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~")}
    if os.environ.get("HLYN_SHIM"):
        env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
    proc = subprocess.Popen(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--read", script, "--", sys.executable, script],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(1.5)
    began = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    _, err = proc.communicate(timeout=20)
    # A Popen, not a `hlyn()` call, so it bypasses that helper's own check;
    # the command may have already exited refusing to seal, before SIGTERM
    # was ever sent, which is not what this test means to exercise.
    found = TOO_OLD.search(err)
    if found:
        pytest.skip(f"this kernel cannot fully seal (see `hlyn probe`): {found.group()}")
    assert time.monotonic() - began < 10
    assert proc.returncode == 128 + signal.SIGTERM, err


@here
def test_a_background_child_does_not_hold_the_run_open(tmp_path):
    # The command exits; something it started carries on. hlyn returns with
    # the command, not with the last process in the tree.
    script = agent(tmp_path, """
        import subprocess
        subprocess.Popen(["/bin/sleep", "30"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    """)
    began = time.monotonic()
    done = hlyn("run", "--no-log", "--exec", "/bin/sleep", "--read", script, "--", sys.executable, script)
    assert time.monotonic() - began < 15
    assert done.returncode == 0, done.stderr


# ---------------------------------------------------------------------------
# Linux: exact counts, and a hostile program on the other end of the pipe
# ---------------------------------------------------------------------------


@linux
def test_a_retry_loop_is_one_line_with_a_count(tmp_path, outside):
    target = outside / "secret.txt"
    done = run(tmp_path, f"""
        for _ in range(5000):
            try: open({str(target)!r})
            except PermissionError: pass
    """)
    item = blocked(done)[real(str(target))]
    assert item["count"] >= 4096


@linux
def test_every_process_in_the_tree_is_heard_and_named(tmp_path, outside):
    target = outside / "secret.txt"
    done = run(tmp_path, f"""
        import subprocess
        subprocess.run(["/bin/sh", "-c", "cat {target} 2>/dev/null; echo x > {outside}/sh.txt"])
    """, *programs("/bin/sh", "/bin/cat"))
    found = blocked(done)
    assert "cat" in found[real(str(target))]["by"]
    assert "sh" in found[real(str(outside / "sh.txt"))]["by"]


@linux
def test_threads_and_processes_hammering_at_once_are_all_heard(tmp_path, outside):
    # 8 processes x 8 threads x 100 distinct paths, all refused at once: a
    # burst far larger than a default pipe holds between two reads.
    done = run(tmp_path, f"""
        import os, threading
        def hammer(tag):
            for i in range(100):
                try: open(f"{outside}/p{{tag}}-{{i}}", "w")
                except PermissionError: pass
        kids = []
        for p in range(8):
            pid = os.fork()
            if pid == 0:
                ts = [threading.Thread(target=hammer, args=(f"{{p}}-{{t}}",)) for t in range(8)]
                [t.start() for t in ts]; [t.join() for t in ts]
                os._exit(0)
            kids.append(pid)
        for pid in kids: os.waitpid(pid, 0)
    """, timeout=300)
    out = report(done)
    mine = [i for i in out["blocked"] if real(i["target"]).startswith(real(str(outside)) + "/")]
    # Anything else (CPython reads /proc/self/stat on fork) was heard before
    # the burst began, so every refusal past the cap is one of these.
    assert len(mine) + out["more"] == 6400, (len(mine), out["more"])
    assert {i["allow"] for i in mine} == {f"--write {os.path.realpath(outside)}"}


@linux
def test_forged_records_cannot_turn_into_advice(tmp_path, outside):
    # The program writes its own records: one claiming a path the policy
    # grants was refused, junk, an oversized line, a terminal escape -- and one
    # plausible forgery, which is shown, because it is indistinguishable from
    # the truth and asks for nothing the policy has not already refused.
    granted = tmp_path / "granted.txt"
    granted.write_text("x")
    done = run(tmp_path, f"""
        import os
        pipe = os.environ["HLYN_REPORT"]
        fd = os.open(pipe, os.O_WRONLY | os.O_NONBLOCK)
        lines = [
            b"hlyn1\\tread\\topen\\t13\\t{granted}\\t1\\tpy\\t0\\t1\\n",
            b"garbage\\n" * 1000,
            b"x" * 100000 + b"\\n",
            b"hlyn1\\tread\\topen\\t13\\t{outside}/secret.txt\\t1\\t\\x1b[2Jpy\\t0\\t1\\n",
            b"hlyn1\\tread\\topen\\t13\\t/%\\t1\\tpy\\t0\\t1\\n",
        ]
        for line in lines:
            try: os.write(fd, line)
            except BlockingIOError: pass
    """, "--read", str(granted))
    found = blocked(done)
    assert real(str(granted)) not in found
    assert set(found) <= {real(str(outside / "secret.txt"))}
    assert "\x1b" not in done.stderr


@linux
def test_a_flood_down_the_pipe_is_survived(tmp_path):
    done = run(tmp_path, """
        import os
        fd = os.open(os.environ["HLYN_REPORT"], os.O_WRONLY)
        chunk = b"hlyn1\\twrite\\topen\\t13\\t/tmp/z\\t1\\tpy\\t0\\t1\\n" * 1000
        for _ in range(500):
            os.write(fd, chunk)
    """, timeout=300)
    assert done.returncode == 0
    report(done)


@linux
def test_repointing_the_pipe_at_a_file_writes_nothing_there(tmp_path, outside):
    # The variable is in the program's own environment, so it can aim its
    # children's reports anywhere it can write. The reporter only ever writes
    # to a pipe, so a file named instead is left as it was.
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL")
    done = run(tmp_path, f"""
        import os, subprocess
        env = dict(os.environ, HLYN_REPORT={str(victim)!r})
        subprocess.run(["/bin/cat", {str(outside / 'secret.txt')!r}], env=env, capture_output=True)
    """, "--write", str(victim), *programs("/bin/cat"))
    assert done.returncode == 0, done.stderr
    assert victim.read_text() == "ORIGINAL"


@linux
def test_a_kept_preload_is_kept_alongside_the_reporter(tmp_path):
    import ctypes.util

    lib = ctypes.util.find_library("m")
    found = next((p for p in ("/lib/aarch64-linux-gnu", "/lib/x86_64-linux-gnu",
                              "/usr/lib/aarch64-linux-gnu", "/usr/lib/x86_64-linux-gnu")
                  if lib and os.path.exists(os.path.join(p, lib))), None)
    if not found:
        pytest.skip("no libm to preload")
    theirs = os.path.join(found, lib)
    done = run(tmp_path, "import os; print(os.environ['LD_PRELOAD'])", "--env", "LD_PRELOAD",
               env={"LD_PRELOAD": theirs})
    assert done.returncode == 0, done.stderr
    preloads = done.stdout.strip().split(":")
    assert preloads[0].endswith("libhlyn_report.so")
    assert preloads[1] == theirs


@linux
def test_odd_bytes_in_a_path_arrive_intact_and_print_harmlessly(tmp_path, outside):
    name = "a\tb\nc%d\x1b[31me"
    done = run(tmp_path, f"""
        try: open({str(outside)!r} + "/" + {name!r}, "w")
        except PermissionError: pass
        raise SystemExit(1)
    """)
    target = f"{outside}/{name}".replace("\t", "\\x09").replace("\n", "\\x0a").replace("\x1b", "\\x1b")
    assert target in blocked(done)
    human = hlyn("run", "--no-log", "--read", str(tmp_path / "agent.py"), "--", sys.executable,
                 str(tmp_path / "agent.py"))
    assert "\x1b" not in human.stderr
    assert "hlyn blocked 1 thing" in human.stderr


@linux
def test_a_path_longer_than_a_record_is_cut_not_lost(tmp_path):
    deep = tmp_path / "d"
    deep.mkdir()
    done = run(tmp_path, f"""
        base = {str(deep)!r} + "/" + "%" * 200
        try: open(base * 1 + "/" + "x" * 250 + "/" * 3000 + "y", "w")
        except OSError: pass
    """)
    assert done.returncode == 0, done.stderr
    report(done)


@linux
def test_a_program_started_outside_hlyn_is_unaffected(tmp_path):
    # The reporter only acts when its pipe is named, so preloading it by hand
    # into an ordinary program changes nothing about that program.
    sys.path.insert(0, SRC)
    from hlyn.core import preload

    lib = preload.find()
    done = subprocess.run(
        ["/bin/sh", "-c", "cat /etc/hostname; cat /nonexistent; echo rc=$?"],
        capture_output=True, text=True, env={"LD_PRELOAD": lib, "PATH": "/usr/bin:/bin"}, check=False,
    )
    assert "rc=1" in done.stdout
    assert "No such file" in done.stderr
