"""Seatbelt confinement, exercised on a real macOS kernel.

`sandbox_init` is deprecated API on a very new OS, so the first thing these
tests establish is that it still enforces at all. Everything else is worthless
if it does not.
"""

from __future__ import annotations

import os
import sys

import pytest
from conftest import jail

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Seatbelt is a macOS facility"
)

SEAL = "mac.load"


@pytest.fixture
def box(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "ok.txt").write_text("granted")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("classified")
    return inside, outside


# ---------------------------------------------------------------------------
# does it still work at all
# ---------------------------------------------------------------------------


def test_seatbelt_still_enforces():
    # The deprecation check. If Apple ever turns this into a no-op that still
    # returns success, this test is how we find out.
    done = jail(
        """
        try:
            open("/etc/hosts").read()
        except PermissionError:
            print("ENFORCED"); raise SystemExit(0)
        print("NOT ENFORCED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"sandbox_init reported success but did not enforce: {done.stdout}"
    assert "ENFORCED" in done.stdout


def test_python_survives_deny_by_default():
    # (deny default) on its own kills the interpreter before it reaches user
    # code. This proves the base allowances are sufficient.
    done = jail(
        """
        import json, hashlib, uuid, base64, random, threading, queue
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
# reads and writes
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


def test_ssh_keys_are_refused_by_default():
    done = jail(
        """
        import os
        try:
            os.listdir(os.path.expanduser("~/.ssh"))
        except (PermissionError, FileNotFoundError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"~/.ssh was readable: {done.stdout}"


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


# ---------------------------------------------------------------------------
# execution and network
# ---------------------------------------------------------------------------


def test_running_a_program_is_refused_by_default():
    done = jail(
        """
        import subprocess
        try:
            subprocess.run(["/bin/echo", "ESCAPED"], capture_output=True)
        except (PermissionError, OSError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"a program ran with exec denied: {done.stdout}"
    assert "ESCAPED" not in done.stdout


def test_network_is_refused_by_default():
    done = jail(
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(("1.1.1.1", 80))
        except (PermissionError, OSError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"the network was reachable by default: {done.stdout}"


# ---------------------------------------------------------------------------
# the profile itself
# ---------------------------------------------------------------------------


def test_profile_denies_by_default():
    from hlyn.core import mac
    from hlyn.policy import Policy

    text = mac.profile(Policy())
    assert "(deny default)" in text
    assert text.startswith("(version 1)")


def test_profile_resolves_symlinked_paths():
    # The trap: /tmp is a symlink to /private/tmp, and Seatbelt matches after
    # resolution. An unresolved rule does not error, it simply never matches.
    from hlyn.core import mac
    from hlyn.policy import Policy

    text = mac.profile(Policy(read=["/tmp"]))
    assert "/private/tmp" in text, "paths were not resolved, so the rule cannot match"


def test_profile_uses_literal_for_files_and_subpath_for_directories():
    from hlyn.core import mac
    from hlyn.policy import Policy

    # The paths are asserted post-resolution, because that is the only form
    # Seatbelt ever sees. /etc and /usr/share/zoneinfo are both symlinks on
    # current macOS, which is exactly why the rule is written this way.
    text = mac.profile(Policy(read=["/etc/hosts", "/usr/share/zoneinfo"]))
    assert f'(literal "{os.path.realpath("/etc/hosts")}")' in text
    assert f'(subpath "{os.path.realpath("/usr/share/zoneinfo")}")' in text


def test_profile_refuses_a_path_that_does_not_exist():
    # It used to skip it. A typo in a security policy was therefore an error on
    # Linux and a silently missing rule on macOS -- and policies get written on
    # macOS and deployed on Linux, so the platform that drops the rule is the
    # one where nobody finds out.
    from hlyn.core import mac
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    with pytest.raises(Invalid) as caught:
        mac.profile(Policy(read=["/tmp", "/definitely/not/here"]))
    assert "/definitely/not/here" in str(caught.value)


def test_profile_refuses_paths_it_cannot_express():
    from hlyn.core import mac
    from hlyn.error import Invalid

    with pytest.raises(Invalid):
        mac.quote('/tmp/we"ird')


def test_ready_is_true_here():
    from hlyn.core import mac

    assert mac.ready()


def test_profile_grants_the_root_directory_node():
    # Without this a spawned program dies inside dyld with SIGABRT and no
    # diagnostic. A subpath rule on a child never matches the root node, so
    # this is the one grant that cannot be inferred from the policy's paths.
    from hlyn.core import mac
    from hlyn.policy import Policy

    assert '(allow file-read* (literal "/"))' in mac.profile(Policy())


def test_framework_python_can_reach_its_inner_interpreter():
    # bin/pythonX.Y is a stub that re-execs Resources/Python.app. Granting
    # execute on the stub alone fails with a bare posix_spawn error.
    import os as _os

    from hlyn.policy import loader

    inner = _os.path.join(sys.prefix, "Resources")
    if not _os.path.exists(inner):
        pytest.skip("not a framework build")
    assert inner in loader()


def test_a_virtualenv_python_runs_under_hlyn_run(tmp_path):
    # A venv's python is a link to a framework stub that re-execs the real
    # interpreter in Resources/Python.app. Only the stub used to be granted,
    # so `hlyn run -- .venv/bin/python` failed every time on python.org builds.
    import subprocess as _sp

    from conftest import SRC

    venv = tmp_path / "venv"
    _sp.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    done = _sp.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", "--",
         str(venv / "bin" / "python"), "-c", "print('UP')"],
        capture_output=True, text=True, env={"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin"}, check=False,
    )
    assert "UP" in done.stdout, done.stderr


def test_companion_finds_the_framework_interpreter():
    from hlyn.policy import companion

    inner = companion(sys.executable)
    if "/Python.framework/" not in os.path.realpath(sys.executable):
        assert inner is None
    else:
        assert inner and inner.endswith("/Resources/Python.app")
    assert companion("/bin/ls") is None
