# SPDX-License-Identifier: Apache-2.0
"""Descriptors the launcher hands down (FINDINGS.md, "Inherited file descriptors").

Landlock and Seatbelt check opening a path, not using a descriptor that is
already open. A file outside every grant, opened by the launcher as
descriptor 9 (dash only supports 0-9), or a connected unix socket, is usable
by the agent unless hlyn drops it. Every test has an unconfined control that
reads the canary, so an EBADF can't be a descriptor that never arrived.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import textwrap

import pytest
from conftest import SRC, boot, skip_if_too_old

here = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend here")

CANARY = "FD-CANARY-9d1c"

# What the agent does: use descriptor 9, then open the same file by name.
AGENT = """
import errno, os
try:
    print("fd 9:", os.pread(9, 64, 0))
except OSError as exc:
    print("fd 9:", errno.errorcode[exc.errno])
try:
    open(PATH).read()
    print("by name: readable")
except OSError as exc:
    print("by name:", errno.errorcode[exc.errno])
"""


def _agent(path: str) -> str:
    return f"PATH = {path!r}\n{AGENT}"


@pytest.fixture
def canary(tmp_path):
    folder = tmp_path / "outside"
    folder.mkdir()
    file = folder / "secret.txt"
    file.write_text(CANARY + "\n")
    return str(file)


def _sh(canary: str, argv: list[str]) -> subprocess.CompletedProcess:
    """`argv`, started by a launcher that opened the canary as descriptor 9."""
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin", "CANARY": canary}
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        env["HLYN_SHIM"] = shim
    done = subprocess.run(
        ["/bin/sh", "-c", 'exec "$@" 9<"$CANARY"', "sh", *argv],
        capture_output=True, text=True, timeout=120, env=env, check=False,
    )
    skip_if_too_old(done)
    return done


def _show(done: subprocess.CompletedProcess) -> None:
    print("stdout:", done.stdout)
    print("stderr:", done.stderr[-600:])


def test_the_control_reads_the_canary_through_descriptor_9(canary):
    done = _sh(canary, [sys.executable, "-c", _agent(canary)])
    _show(done)
    assert f"fd 9: b'{CANARY}\\n'" in done.stdout
    assert "by name: readable" in done.stdout


# ---------------------------------------------------------------------------
# hlyn run
# ---------------------------------------------------------------------------


@here
@pytest.mark.parametrize("net", [[], ["--net-any"], ["--net", "example.com"]],
                         ids=["no-net", "net-any", "host"])
def test_run_closes_a_descriptor_the_launcher_left_open(canary, net):
    done = _sh(canary, [sys.executable, "-m", "hlyn.cli", "run", "--no-log", *net, "--",
                        sys.executable, "-c", _agent(canary)])
    _show(done)
    assert "fd 9: EBADF" in done.stdout
    assert CANARY not in done.stdout + done.stderr
    # The file was outside every grant: by name it is refused too (that is
    # what makes the descriptor the only way in).
    assert "by name: EPERM" in done.stdout or "by name: EACCES" in done.stdout


@here
@pytest.mark.parametrize("net", [[], ["--net", "example.com"]], ids=["no-net", "host"])
def test_run_keep_fd_passes_the_descriptor_on_purpose(canary, net):
    done = _sh(canary, [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--keep-fd", "9", *net, "--",
                        sys.executable, "-c", _agent(canary)])
    _show(done)
    assert f"fd 9: b'{CANARY}\\n'" in done.stdout


@here
def test_run_keep_fd_names_a_descriptor_that_is_not_open():
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--keep-fd", "7", "--", "true"],
        capture_output=True, text=True, timeout=60, check=False,
        env={"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin"},
    )
    _show(done)
    assert done.returncode == 2
    assert "descriptor 7 isn't open" in done.stderr and "--keep-fd 7" in done.stderr


@here
@pytest.mark.parametrize("net", [[], ["--net", "example.com"]], ids=["no-net", "host"])
def test_run_closes_a_connected_unix_socket(net):
    a, b = socket.socketpair()
    code = f"import os\nos.write({b.fileno()}, b'SECRET')\nprint('wrote')"
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin"}
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        env["HLYN_SHIM"] = shim
    base = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", *net, "--", sys.executable, "-c", code]

    def heard(argv: list[str]) -> tuple[bytes, subprocess.CompletedProcess]:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=env, check=False,
                              pass_fds=[b.fileno()])
        skip_if_too_old(done)
        a.settimeout(2)
        try:
            return a.recv(100), done
        except TimeoutError:
            return b"(nothing)", done

    try:
        control, plain = heard([sys.executable, "-c", code])
        print("control:", control, plain.stdout, plain.stderr[-200:])
        assert control == b"SECRET", "the control must be able to write, or the test proves nothing"
        got, done = heard(base)
        _show(done)
        print("peer heard:", got)
        assert got == b"(nothing)"
        assert "EBADF" in done.stderr or "Bad file descriptor" in done.stderr
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# hlyn.spawn, hlyn.run(fn), hlyn.on()
# ---------------------------------------------------------------------------

OPEN9 = """
    import os, sys, errno, hlyn
    path = {canary!r}
    fd = os.open(path, os.O_RDONLY)
    os.dup2(fd, 9)
    os.close(fd)
    os.set_inheritable(9, True)
    def agent():
        try:
            print("fd 9:", os.pread(9, 64, 0))
        except OSError as exc:
            print("fd 9:", errno.errorcode[exc.errno])
        try:
            open(path).read()
            print("by name: readable")
        except OSError as exc:
            print("by name:", errno.errorcode[exc.errno])
"""


def _open9(canary: str, body: str = "") -> str:
    """The launcher's half (descriptor 9 open on the canary, `agent` defined)
    followed by `body`."""
    return textwrap.dedent(OPEN9).format(canary=canary) + textwrap.dedent(body)


@here
@pytest.mark.parametrize("net", ["False", "['example.com']"], ids=["no-net", "host"])
def test_spawn_closes_a_descriptor_the_caller_left_open(canary, net):
    done = boot(_open9(canary, f"""
    kid = os.fork()
    if kid == 0:
        hlyn.spawn([sys.executable, "-c", {_agent(canary)!r}], net={net})
    os.waitpid(kid, 0)
    """))
    _show(done)
    assert "fd 9: EBADF" in done.stdout
    assert "by name: EPERM" in done.stdout or "by name: EACCES" in done.stdout


@here
@pytest.mark.parametrize("net", ["False", "['example.com']"], ids=["no-net", "host"])
def test_spawn_keep_fds_passes_it_on_purpose(canary, net):
    done = boot(_open9(canary, f"""
    kid = os.fork()
    if kid == 0:
        hlyn.spawn([sys.executable, "-c", {_agent(canary)!r}], net={net}, keep_fds=[9])
    os.waitpid(kid, 0)
    """))
    _show(done)
    assert f"fd 9: b'{CANARY}\\n'" in done.stdout


@here
@pytest.mark.parametrize("net", ["False", "['example.com']"], ids=["no-net", "host"])
def test_run_fn_closes_a_descriptor_the_caller_left_open(canary, net):
    done = boot(_open9(canary, f"""
    hlyn.run(agent, net={net})
    print("parent still reads fd 9:", os.pread(9, 64, 0))
    """))
    _show(done)
    # The number stays taken, now /dev/null (as for sockets, `route.neutralise`):
    # it reads nothing, and the canary is not in the output.
    assert "fd 9: b''" in done.stdout
    assert "by name: EPERM" in done.stdout or "by name: EACCES" in done.stdout
    # Only the child lost it: the caller still needs its own.
    assert f"parent still reads fd 9: b'{CANARY}\\n'" in done.stdout


@here
@pytest.mark.parametrize("net", ["False", "['example.com']"], ids=["no-net", "host"])
def test_run_fn_keep_fds_passes_it_on_purpose(canary, net):
    done = boot(_open9(canary, f"""
    hlyn.run(agent, net={net}, keep_fds=[9])
    """))
    _show(done)
    assert f"fd 9: b'{CANARY}\\n'" in done.stdout


@here
def test_run_fn_closes_a_connected_unix_socket():
    done = boot("""
    import socket, hlyn
    a, b = socket.socketpair()
    def leak():
        try:
            b.sendall(b"SECRET")
            return "sent"
        except OSError as exc:
            return f"refused ({exc.strerror})"
    a.settimeout(2)
    print("child:", hlyn.run(leak, net=False))
    b.close()
    print("peer heard:", a.recv(100))
    control = socket.socketpair()
    control[1].sendall(b"SECRET")
    print("control heard:", control[0].recv(100))
    """)
    _show(done)
    assert "control heard: b'SECRET'" in done.stdout
    assert "child: refused" in done.stdout and "child: sent" not in done.stdout
    assert "peer heard: b''" in done.stdout


@here
def test_run_fn_keeps_what_hlyn_needs_to_return_the_result_and_report(tmp_path):
    # The result pipe is hlyn's own: closing it would look like a crash.
    done = boot("""
    import hlyn
    print("returned:", hlyn.run(lambda: 6 * 7, net=['example.com']))
    """)
    _show(done)
    assert "returned: 42" in done.stdout


@here
def test_on_warns_about_a_file_outside_the_grants_and_still_seals(canary):
    done = boot(_open9(canary, """
    import warnings
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        hlyn.on()
    print("warnings:", [(w.category.__name__, str(w.message)) for w in seen])
    print("sealed:", hlyn.sealed())
    agent()
    """))
    _show(done)
    assert "('Inherited'," in done.stdout
    assert "fd 9 file " in done.stdout and "secret.txt" in done.stdout
    assert "close them in the child" in done.stdout
    assert "sealed: True" in done.stdout
    # The warning is the only protection on() can give: it can't take the
    # descriptor from a caller that still needs it, and says so.
    assert f"fd 9: b'{CANARY}\\n'" in done.stdout


@here
def test_on_says_nothing_when_the_file_is_inside_the_grants(canary):
    folder = os.path.dirname(canary)
    done = boot(_open9(canary, f"""
    import warnings
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        hlyn.on(read=[{folder!r}])
    print("warnings:", [w.category.__name__ for w in seen])
    """))
    _show(done)
    assert "warnings: []" in done.stdout


@here
def test_on_says_nothing_when_nothing_was_left_open():
    done = boot("""
    import warnings, hlyn
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        hlyn.on()
    print("warnings:", [w.category.__name__ for w in seen])
    print("sealed:", hlyn.sealed())
    """)
    _show(done)
    assert "warnings: []" in done.stdout and "sealed: True" in done.stdout


@here
def test_on_warns_about_a_write_open_file_when_only_reading_is_granted(canary):
    folder = os.path.dirname(canary)
    done = boot(f"""
    import os, warnings, hlyn
    fd = os.open({canary!r}, os.O_RDWR)
    os.dup2(fd, 9)
    os.close(fd)
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        hlyn.on(read=[{folder!r}])
    print("warnings:", [str(w.message) for w in seen])
    """)
    _show(done)
    assert "(open to write)" in done.stdout


@here
def test_on_warns_about_a_connected_unix_socket():
    done = boot("""
    import socket, warnings, hlyn
    a, b = socket.socketpair()
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        hlyn.on()
    print("warnings:", [str(w.message) for w in seen])
    """)
    _show(done)
    assert "unix socket (to another process)" in done.stdout


@here
def test_on_can_be_made_to_refuse_with_the_warning_as_an_error(canary):
    done = boot(_open9(canary, """
    import warnings
    warnings.simplefilter("error", hlyn.Inherited)
    try:
        hlyn.on()
    except hlyn.Inherited as exc:
        print("refused:", str(exc).splitlines()[0])
    print("sealed:", hlyn.sealed())
    """))
    _show(done)
    assert "refused: hlyn: 1 open descriptor points outside the grants (fd 9 file " in done.stdout
    assert "sealed: False" in done.stdout


def test_keep_fds_must_name_open_descriptors_above_2():
    import hlyn
    from hlyn.fds import keeps

    assert keeps(None) == () and keeps([]) == ()
    with pytest.raises(hlyn.Invalid, match="isn't open"):
        keeps([8123])
    with pytest.raises(hlyn.Invalid, match="stdin, stdout or stderr"):
        keeps([1])
    with pytest.raises(hlyn.Invalid, match="whole numbers"):
        keeps(["9"])  # type: ignore[list-item]
