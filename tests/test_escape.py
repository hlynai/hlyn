"""Escapes that worked, and must never work again.

Every test here corresponds to a hole that was real: written against a green
suite, found by attacking the thing rather than by testing it. They are kept
apart from the other escape tests because their value is historical as much as
technical -- each one is a shape of mistake the rest of the suite did not
catch, and the shape is the reusable part.

Two of them share a cause worth naming: a boundary that is enforced *somewhere*
was assumed to be enforced *everywhere*. `exec=True` was enforced per path and
not over the whole tree it resolved to; Landlock was enforced on the thread
that asked and not on the ones already running. A test that only ever checks
the intended case cannot see either.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot

pytestmark = pytest.mark.linux


if sys.platform != "linux":
    pytest.skip("Landlock is Linux-only", allow_module_level=True)


# ---------------------------------------------------------------------------
# `exec=True` and `write=True` used to grant read over the whole filesystem
# ---------------------------------------------------------------------------
#
# `_paths(True)` resolves a blanket grant to a rule on `/`, and the exec and
# write masks both carried ReadFile. So asking to run programs, or to write
# anywhere, silently made every file on the machine readable and every `read`
# list decorative. `hlyn.on("coder")` -- the first example in the README --
# could read /etc/shadow.


def test_allowing_any_program_does_not_grant_reading_everything():
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except OSError:
            print("refused")
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_allowing_writing_anywhere_does_not_grant_reading_everything():
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], write=True, log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except OSError:
            print("refused")
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_the_coder_preset_confines_the_filesystem():
    """The README's headline example. It read /etc/shadow."""
    done = boot(
        """
        import os, hlyn
        os.makedirs("/tmp/work", exist_ok=True)
        os.chdir("/tmp/work")
        hlyn.on("coder", log=False)
        try:
            open("/etc/shadow").read()
            print("ESCAPED")
        except OSError:
            print("refused")
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_allowing_any_program_still_runs_programs():
    """The other half. A fix that made exec=True unusable would be no fix."""
    done = boot(
        """
        import subprocess, hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        got = subprocess.run(["/bin/echo", "ran"], capture_output=True)
        print("ran" if got.returncode == 0 else f"BROKE rc={got.returncode}")
        """
    )
    assert "ran" in done.stdout, done.stdout + done.stderr


def test_a_named_program_is_readable_because_the_policy_says_so():
    """Naming a program in `exec` adds it to `read`, which is where it belongs.

    That is what makes dropping ReadFile from the exec mask a fix rather than a
    trade: the grant still exists, bounded and visible in `hlyn show`, instead
    of arriving invisibly over `/`.
    """
    done = boot(
        """
        import subprocess, hlyn
        open("/tmp/granted.txt", "w").write("hello")
        hlyn.on(read=["/tmp"], exec=["/bin/cat"], log=False)
        got = subprocess.run(["/bin/cat", "/tmp/granted.txt"], capture_output=True)
        print(f"cat rc={got.returncode} out={got.stdout!r}")
        """
    )
    assert "cat rc=0" in done.stdout, done.stdout + done.stderr
    assert "hello" in done.stdout, done.stdout


# ---------------------------------------------------------------------------
# threads that existed before the seal
# ---------------------------------------------------------------------------
#
# `landlock_restrict_self` applies to the calling thread, and credentials on
# Linux are per-task, so a thread already running keeps the access it had.
# seccomp has TSYNC and covers every thread; Landlock has no equivalent, so
# the filesystem and the port rules simply did not apply to it.


def test_sealing_a_process_with_another_thread_is_refused():
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        try:
            hlyn.on(read=["/tmp"], log=False)
            print("SEALED ANYWAY")
        except hlyn.Unsupported as exc:
            print("refused:", exc)
        """
    )
    assert "refused:" in done.stdout, done.stdout + done.stderr
    assert "threads" in done.stdout


def test_the_refusal_says_how_to_fix_it():
    """A refusal nobody can act on gets worked around rather than heeded."""
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        try:
            hlyn.on(log=False)
        except hlyn.Unsupported as exc:
            print(str(exc))
        """
    )
    assert "hlyn.run" in done.stdout, done.stdout
    assert "before anything starts a thread" in done.stdout, done.stdout


def test_a_single_threaded_process_still_seals():
    """The check must not fire on the ordinary case."""
    done = boot(
        """
        import hlyn
        hlyn.on(read=["/tmp"], log=False)
        print("sealed")
        """
    )
    assert "sealed" in done.stdout, done.stdout + done.stderr


def test_run_still_works_from_a_threaded_parent():
    """The documented way out: fork drops every thread but the caller's."""
    done = boot(
        """
        import threading, time, hlyn
        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()
        time.sleep(0.2)
        def work():
            try:
                open("/etc/shadow").read()
                return "ESCAPED"
            except OSError:
                return "refused"
        print(hlyn.run(work, read=["/tmp"], log=False))
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


def test_threads_started_after_sealing_are_confined():
    """The case that already worked, kept so a fix cannot trade one for the other."""
    done = boot(
        """
        import threading, hlyn
        hlyn.on(read=["/tmp"], log=False)
        out = []
        def work():
            try:
                open("/etc/shadow").read()
                out.append("ESCAPED")
            except OSError:
                out.append("refused")
        t = threading.Thread(target=work)
        t.start()
        t.join()
        print(out[0])
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr


# ---------------------------------------------------------------------------
# closing the network used to close local IPC with it
# ---------------------------------------------------------------------------
#
# `connect`, `bind`, `sendto` and friends carry no address family, so refusing
# them by syscall number to close the network refused them on AF_UNIX too. The
# old test only *created* an AF_UNIX socket and so never noticed; anything that
# actually used one -- multiprocessing, a local database, SysLogHandler -- was
# broken by `net=False`.


def test_a_unix_socket_still_connects_when_the_network_is_closed():
    done = boot(
        """
        import os, socket, time, hlyn
        os.makedirs("/tmp/ipc", exist_ok=True)
        s = "/tmp/ipc/s.sock"
        if os.path.exists(s): os.unlink(s)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(s); srv.listen(1)
        if os.fork() == 0:
            try:
                srv.settimeout(8); conn, _ = srv.accept(); conn.send(b"ok"); time.sleep(1)
            except Exception: pass
            os._exit(0)
        srv.close(); time.sleep(0.3)
        hlyn.on(read=["/tmp/ipc"], write=["/tmp/ipc"], net=False, log=False)
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.settimeout(5)
        try:
            c.connect(s); print("connected", c.recv(4), flush=True)
        except OSError as exc:
            print("BROKEN", type(exc).__name__, flush=True)
        os._exit(0)
        """
    )
    assert "connected" in done.stdout, done.stdout + done.stderr


def test_tcp_is_still_refused_when_the_network_is_closed():
    """The other half: local IPC working must not have reopened the network."""
    done = boot(
        """
        import socket, hlyn
        hlyn.on(read=["/tmp"], net=False, log=False)
        try:
            socket.socket().connect(("127.0.0.1", 80))
            print("ESCAPED")
        except OSError as exc:
            print("refused", type(exc).__name__)
        """
    )
    assert "refused" in done.stdout, done.stdout + done.stderr
    assert "ESCAPED" not in done.stdout


def test_sealing_with_a_network_socket_already_open_is_refused():
    """An open connection survives sealing: writing to it is an ordinary write.

    Nothing in the filter can tell that descriptor from a file, so the only
    honest answer is to refuse before the boundary is claimed.
    """
    done = boot(
        """
        import socket, hlyn
        s = socket.socket(); s.settimeout(1)
        try: s.connect(("127.0.0.1", 9))
        except OSError: pass
        try:
            hlyn.on(read=["/tmp"], net=False, log=False)
            print("SEALED ANYWAY")
        except hlyn.Unsupported as exc:
            print("refused:", exc)
        """
    )
    assert "refused:" in done.stdout, done.stdout + done.stderr
    assert "already open" in done.stdout


def test_a_socket_open_is_fine_when_the_network_is_not_closed():
    """The check must only fire when the policy actually claims a closed network."""
    done = boot(
        """
        import socket, hlyn
        s = socket.socket()
        hlyn.on(read=["/tmp"], net=True, log=False)
        print("sealed")
        """
    )
    assert "sealed" in done.stdout, done.stdout + done.stderr


def test_a_child_cannot_shed_the_boundary():
    """fork, exec, and a new session all inherit the domain."""
    done = boot(
        """
        import os, subprocess, sys, hlyn
        hlyn.on(read=["/tmp"], exec=True, log=False)
        code = ("try:\\n open('/etc/shadow').read(); print('ESCAPED')\\n"
                "except OSError: print('refused')\\n")
        for argv in ([sys.executable, "-c", code],
                     ["/usr/bin/setsid", sys.executable, "-c", code]):
            got = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            print(argv[0].split("/")[-1], got.stdout.strip())
        """
    )
    assert "ESCAPED" not in done.stdout, done.stdout + done.stderr
    assert done.stdout.count("refused") == 2, done.stdout + done.stderr
