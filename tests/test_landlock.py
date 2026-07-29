"""Filesystem and inter-agent confinement, exercised against a real kernel.

These are escape attempts. Each one must fail the build if the escape works.
The suite also proves the opposite direction: that a policy which grants
something actually grants it, because a boundary that denies everything is
easy and useless.
"""

from __future__ import annotations

import os
import socket
import sys

import pytest

from conftest import jail

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock is a Linux kernel facility"
)

SEAL = "landlock.load"


@pytest.fixture
def box(tmp_path):
    """A directory the policy will allow, holding a file it will not."""
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "ok.txt").write_text("granted")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("classified")
    return inside, outside


# ---------------------------------------------------------------------------
# the interpreter must survive real deny-by-default
# ---------------------------------------------------------------------------


def test_python_survives_the_default_policy():
    # The whole bootstrap set in one assertion: seal reads to nothing but the
    # runtime, then force the lazy imports that would die if it were wrong.
    done = jail(
        """
        import json, ssl, socket, hashlib, uuid, base64, random, sqlite3
        import email, gzip, zipfile, threading, queue, select, asyncio
        assert hashlib.sha256(b"x").hexdigest()
        assert len(os.urandom(16)) == 16
        print("ALIVE")
        """,
        before="import os",
        seal=SEAL,
    )
    assert done.returncode == 0, f"deny-by-default broke the interpreter:\n{done.stderr}"
    assert "ALIVE" in done.stdout


# ---------------------------------------------------------------------------
# reads
# ---------------------------------------------------------------------------


def test_a_granted_path_is_readable(box):
    inside, _ = box
    done = jail(
        f"print(open({str(inside / 'ok.txt')!r}).read())",
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a granted path was not readable:\n{done.stderr}"
    assert "granted" in done.stdout


def test_a_path_outside_the_grant_is_refused(box):
    inside, outside = box
    done = jail(
        f"""
        try:
            open({str(outside / 'secret.txt')!r}).read()
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"read escaped the boundary: {done.stdout}"
    assert "REFUSED" in done.stdout


def test_the_home_directory_is_refused_by_default():
    done = jail(
        """
        import os
        home = os.path.expanduser("~")
        try:
            os.listdir(home)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"the home directory was readable: {done.stdout}"


def test_etc_shadow_is_refused_by_default():
    done = jail(
        """
        try:
            open("/etc/shadow", "rb").read()
        except (PermissionError, FileNotFoundError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"/etc/shadow was readable: {done.stdout}"


# ---------------------------------------------------------------------------
# writes
# ---------------------------------------------------------------------------


def test_a_granted_path_is_writable(box):
    inside, _ = box
    done = jail(
        f"""
        open({str(inside / 'new.txt')!r}, "w").write("hello")
        print(open({str(inside / 'new.txt')!r}).read())
        """,
        policy=f"Policy(write=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a granted path was not writable:\n{done.stderr}"
    assert "hello" in done.stdout


def test_writing_outside_the_grant_is_refused(box):
    inside, outside = box
    done = jail(
        f"""
        try:
            open({str(outside / 'planted.txt')!r}, "w").write("owned")
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(write=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"write escaped the boundary: {done.stdout}"
    assert not (outside / "planted.txt").exists(), "the file was actually created"


def test_read_only_grant_does_not_allow_writing(box):
    inside, _ = box
    done = jail(
        f"""
        try:
            open({str(inside / 'ok.txt')!r}, "w").write("tampered")
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a read grant allowed writing: {done.stdout}"
    assert (inside / "ok.txt").read_text() == "granted", "the file was modified"


# ---------------------------------------------------------------------------
# the ways out
# ---------------------------------------------------------------------------


def test_a_symlink_cannot_leave_the_grant(box):
    inside, outside = box
    os.symlink(str(outside / "secret.txt"), str(inside / "escape"))
    done = jail(
        f"""
        try:
            open({str(inside / 'escape')!r}).read()
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a symlink walked out of the boundary: {done.stdout}"


def test_dotdot_cannot_leave_the_grant(box):
    inside, outside = box
    done = jail(
        f"""
        try:
            open({str(inside / '..' / 'outside' / 'secret.txt')!r}).read()
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"path traversal left the boundary: {done.stdout}"


def test_proc_self_environ_is_refused():
    # Scrubbing os.environ does not clear the environment block captured at
    # exec time, so this file still holds the original secrets. It is the
    # reason /proc is absent from the runtime grant.
    done = jail(
        """
        try:
            open("/proc/self/environ", "rb").read()
        except (PermissionError, FileNotFoundError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"/proc/self/environ was readable: {done.stdout}"


def test_other_processes_in_proc_are_refused():
    done = jail(
        """
        import os
        try:
            os.listdir("/proc/1")
        except (PermissionError, FileNotFoundError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"another process's /proc entry was readable: {done.stdout}"


# ---------------------------------------------------------------------------
# reaching another agent
# ---------------------------------------------------------------------------


def test_signalling_outside_the_domain_is_refused():
    # LANDLOCK_SCOPE_SIGNAL. The parent created this process and sits outside
    # its domain, so it stands in for a sibling agent.
    done = jail(
        """
        import os
        try:
            os.kill(os.getppid(), 0)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"an agent signalled outside its domain: {done.stdout}"


def test_abstract_unix_socket_outside_the_domain_is_refused():
    # LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET. The listener lives in this process,
    # outside the child's domain, so the child must not be able to reach it.
    name = "\0hlyn-scope-probe"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(name)
        server.listen(1)
        done = jail(
            f"""
            import socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect({name!r})
            except (PermissionError, ConnectionRefusedError, FileNotFoundError):
                print("REFUSED"); raise SystemExit(0)
            print("ESCAPED"); raise SystemExit(1)
            """,
            seal=SEAL,
        )
    finally:
        server.close()
    assert done.returncode == 0, f"an agent reached an abstract socket outside it: {done.stdout}"


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------


def test_running_a_program_outside_the_grant_is_refused():
    done = jail(
        """
        import subprocess
        try:
            subprocess.run(["/bin/echo", "ESCAPED"], capture_output=True)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(exec=False)",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a program ran with exec=False: {done.stdout}"
    assert "ESCAPED" not in done.stdout


# ---------------------------------------------------------------------------
# what the machine reports
# ---------------------------------------------------------------------------


def test_abi_is_reported():
    from hlyn.core import landlock

    assert landlock.abi() >= 1, "no Landlock on this kernel"


def test_ready_agrees_with_abi():
    from hlyn.core import landlock

    assert landlock.ready() == (landlock.abi() > 0)


def test_a_missing_path_is_refused_loudly(tmp_path):
    # A typo in a security policy must never be silently dropped.
    from hlyn.core import landlock
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    with pytest.raises(Invalid) as caught:
        landlock.load(Policy(read=[str(tmp_path / "nope")]))
    assert "nope" in str(caught.value)
