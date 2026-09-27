# SPDX-License-Identifier: Apache-2.0
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

if sys.platform == "linux":
    from hlyn.core import landlock as _landlock

    _ABI = _landlock.abi()
else:
    _ABI = 0


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
    inside, _ = box
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
# network ports: the one enforcement path seccomp cannot help with
#
# A named-port net policy (net=[8080]) is deliberately left alone by seccomp
# (core/seccomp.py only writes socket()-domain rules for the bool cases): a
# classic BPF filter cannot dereference the sockaddr connect() is given, so it
# has no way to tell "port 8080" from "port 9000". Only Landlock's NetPort can
# express that distinction, which makes this the one place where the whole
# boundary rests on a single backend with no second layer behind it. That is
# exactly why it needs to be proven directly rather than trusted by inspection.
# ---------------------------------------------------------------------------


def test_a_granted_port_is_reachable():
    # ECONNREFUSED (nothing listening) proves the connect() itself was let
    # through. A PermissionError here would mean the grant does nothing.
    done = jail(
        """
        import socket
        try:
            socket.create_connection(("127.0.0.1", 8080), timeout=1)
        except ConnectionRefusedError:
            print("REACHED"); raise SystemExit(0)
        except PermissionError:
            print("BLOCKED"); raise SystemExit(1)
        print("UNEXPECTED"); raise SystemExit(1)
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a granted port was not reachable: {done.stdout} {done.stderr}"


def test_an_ungranted_port_is_refused():
    done = jail(
        """
        import socket
        try:
            socket.create_connection(("127.0.0.1", 9000), timeout=1)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"connected to a port outside the grant: {done.stdout}"


def test_an_adjacent_port_is_refused():
    # An off-by-one in the port comparison would be invisible unless the port
    # right next to a granted one is checked specifically.
    done = jail(
        """
        import socket
        for port in (8079, 8081):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1)
            except PermissionError:
                continue
            print("ESCAPED", port); raise SystemExit(1)
        print("REFUSED"); raise SystemExit(0)
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"an adjacent port was reachable: {done.stdout}"


def test_ipv6_gets_the_same_port_enforcement_as_ipv4():
    # Landlock's net rules are matched by port number, not address family.
    # Nothing in core/seccomp.py distinguishes AF_INET from AF_INET6 either
    # (net is False is the only condition it checks), so IPv6 traffic for a
    # named-port policy reaches Landlock exactly as unfiltered as IPv4 does.
    # If Landlock's own port match were somehow IPv4-only, this is the test
    # that would catch it.
    # socket.has_ipv6 says how Python was built, not whether this kernel has
    # IPv6: a container without it answers EAFNOSUPPORT at socket().
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
    except OSError as exc:
        pytest.skip(f"no IPv6 on this machine ({exc})")
    done = jail(
        """
        import socket
        # Only PermissionError counts: catching every OSError would also catch
        # ConnectionRefusedError, which means "nothing is listening" and says
        # nothing about the policy -- the same shape of false pass as trusting
        # any OSError anywhere else.
        try:
            socket.create_connection(("::1", 9000), timeout=1)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    print(done.stdout, done.stderr[-500:])
    assert done.returncode == 0, f"IPv6 bypassed port enforcement: {done.stdout}"


def test_a_connect_only_grant_does_not_allow_binding():
    # policy.py grants outbound reach for named ports, deliberately not a
    # listener (jail.py comment: "accepting inbound connections... an agent
    # should have to ask for separately"). A bind() succeeding here would mean
    # that design decision silently is not what ships.
    done = jail(
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", 8080))
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"bound a listener from a connect-only grant: {done.stdout}"


def test_socket_creation_itself_is_not_gated():
    # Landlock and seccomp both hook bind()/connect(), not socket(). A policy
    # denying socket() outright would be a stricter boundary than documented
    # and would break anything that constructs a socket object before
    # deciding whether to use it.
    done = jail(
        """
        import socket
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("OK")
        """,
        policy="Policy(net=[8080])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"plain socket() was blocked: {done.stdout} {done.stderr}"
    assert "OK" in done.stdout


# ---------------------------------------------------------------------------
# the limit of a named port, pinned so it cannot drift quietly
# ---------------------------------------------------------------------------
#
# Landlock's network rules cover TCP bind and connect and nothing else, so a
# policy naming ports does not restrict UDP. That is a documented limit rather
# than a bug -- seccomp cannot read a UDP port number any more than it can read
# a host name, so the only alternative is refusing all of UDP, which breaks
# every hostname lookup an agent makes.
#
# Both tests below run the whole backend, not just Landlock, because a limit
# proved against one layer says nothing about what a user actually gets.

BOTH = "linux.load"


def test_a_named_port_does_not_restrict_udp():
    # If this test ever fails, the limit has been closed and the docstrings on
    # `ports` and `Policy`, plus the CLI help, are now lying in the other
    # direction. Fix them, then delete this test.
    done = jail(
        """
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"x", ("127.0.0.1", 9))  # discard port, nothing listening
        print("UDP OPEN")
        """,
        before="from hlyn.core import linux",
        policy="Policy(net=[443])",
        seal=BOTH,
    )
    assert "UDP OPEN" in done.stdout, (
        "UDP is now restricted by a named port. That is an improvement, but the "
        f"documented behaviour no longer matches: {done.stdout} {done.stderr}"
    )


def test_closing_the_network_closes_udp_too():
    # The remedy the documentation points at has to actually work: net=False
    # refuses the socket itself, so there is no UDP to send on.
    done = jail(
        """
        import socket
        try:
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        before="from hlyn.core import linux",
        policy="Policy(net=False)",
        seal=BOTH,
    )
    assert "REFUSED" in done.stdout, f"net=False left UDP reachable: {done.stdout}"


# ---------------------------------------------------------------------------
# what the machine reports
# ---------------------------------------------------------------------------


def test_abi_is_reported():
    from hlyn.core import landlock

    assert landlock.abi() >= 1, "no Landlock on this kernel"


def test_ready_agrees_with_abi():
    from hlyn.core import landlock

    # Not `abi() > 0`: `load` always asks for ABI 6's signal/socket scoping,
    # whatever the policy, so anything less always refuses to seal. `ready`
    # promising less than that would be the exact lie this test exists to
    # catch -- found, on real ABI-4 hardware, as `probe` saying "yes" and
    # every subsequent seal then refusing.
    assert landlock.ready() == (landlock.abi() >= 6)


def test_an_unopenable_path_is_named_in_the_error(tmp_path):
    # A path that exists but cannot be opened gets past the existence check and
    # fails inside the shim, which answers with one code for every rule failure.
    # "a path could not be opened" is useless when the policy names forty of
    # them, so the message has to say which one and why.
    import os

    from hlyn.core import landlock
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    if os.geteuid() == 0:
        pytest.skip("root can open anything, so no path is unopenable")

    shed = tmp_path / "shed"
    shed.mkdir()
    (shed / "tool").write_text("x")
    shed.chmod(0o000)  # no search permission, so the child cannot be opened
    try:
        with pytest.raises(Invalid) as caught:
            landlock.load(Policy(read=[str(shed / "tool")]))
    finally:
        shed.chmod(0o755)

    said = str(caught.value)
    assert "tool" in said, f"the error did not name the path: {said}"
    # The file is there. Saying it is not would send the reader hunting for a
    # typo instead of at the permissions.
    assert "denied" in said.lower(), f"the error blamed the wrong thing: {said}"
    assert "not exist" not in said, f"an existing file was reported missing: {said}"


def test_a_missing_path_is_refused_loudly(tmp_path):
    # A typo in a security policy must never be silently dropped.
    from hlyn.core import landlock
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    with pytest.raises(Invalid) as caught:
        landlock.load(Policy(read=[str(tmp_path / "nope")]))
    assert "nope" in str(caught.value)


# ---------------------------------------------------------------------------
# under-enforcement: the failure mode that looks like success
# ---------------------------------------------------------------------------
#
# On an older kernel the ruleset is applied with whatever rights that kernel
# understands and the rest are dropped, which is what `BestEffort` means. The
# process ends up confined less than the caller asked for, and every syscall
# after that succeeds normally -- there is nothing to notice. `load` is the one
# place that can catch it, and only if it treats anything short of full
# enforcement as a failure.
#
# The kernel here is new enough that it never under-enforces, so the shim's
# answer is substituted directly. That is the whole point: these tests are
# about what this side does with the answer, on a machine where the real answer
# can never be anything but FULL.


class _Shim:
    """Stands in for the loaded library, reporting whatever it is told to."""

    def __init__(self, seal: int, abi: int = 6):
        self._seal = seal
        self._abi = abi

    def hlyn_seal(self, _plan):
        return self._seal

    def hlyn_abi(self):
        return self._abi


@pytest.fixture
def shim(monkeypatch):
    """Swap in a shim that reports a chosen enforcement level.

    Nothing is applied to this process: the fake never reaches the kernel, so
    these tests can run in the test runner itself rather than a child.
    """

    def use(level: int, abi: int = 6):
        from hlyn.core import landlock

        monkeypatch.setattr(landlock, "_lib", _Shim(level, abi))
        return landlock

    return use


def test_partial_enforcement_raises_instead_of_returning(shim):
    from hlyn.error import Failed
    from hlyn.policy import Policy

    landlock = shim(1)  # SOME: the kernel took part of the ruleset
    with pytest.raises(Failed) as caught:
        landlock.load(Policy())
    said = str(caught.value)
    assert "part" in said, f"the message does not say what went wrong: {said}"
    # The caller has to be able to tell "weaker than asked" from "not confined
    # at all", because only one of those leaves them with a live process that
    # believes it is safe.
    assert "IS confined" in said


def test_no_enforcement_at_all_raises(shim):
    from hlyn.error import Failed
    from hlyn.policy import Policy

    landlock = shim(0)  # NOT: nothing was applied
    with pytest.raises(Failed) as caught:
        landlock.load(Policy())
    assert "NOT confined" in str(caught.value)


def test_full_enforcement_is_the_only_case_that_returns(shim):
    landlock = shim(2)  # FULL
    from hlyn.policy import Policy

    assert landlock.load(Policy()) == 6


# Found by running on real ABI-4 hardware (a Linux 6.8 kernel, below hlyn's
# floor): `ready()` and `probe()` used to say yes at ABI 1, while `load`
# above always asks for ABI 6's scoping and so always refused there anyway.
# `probe` telling the truth is the only thing standing between a user and
# discovering that gap the hard way, mid-run.
@pytest.mark.parametrize("abi", [0, 1, 4, 5])
def test_ready_is_false_below_the_floor(shim, abi):
    landlock = shim(2, abi)
    assert landlock.ready() is False


@pytest.mark.parametrize("abi", [6, 7])
def test_ready_is_true_at_the_floor_and_above(shim, abi):
    landlock = shim(2, abi)
    assert landlock.ready() is True


def test_probe_refuses_to_claim_enforcement_below_the_floor(monkeypatch):
    from hlyn.core import landlock, linux

    monkeypatch.setattr(landlock, "abi", lambda: 4)
    out = linux.probe()
    assert out["enforce"] is False
    assert out["scope"] is False
    assert out["ports"] is False
    assert "ABI 4 is too old" in str(out["why"])
    assert "no policy can be sealed" in str(out["why"])


def test_probe_agrees_with_ready_at_the_floor(monkeypatch):
    from hlyn.core import landlock, linux

    monkeypatch.setattr(landlock, "abi", lambda: 6)
    out = linux.probe()
    # seccomp's own availability is a real fact about this machine, same as
    # every other test in this file already assumes; only the Landlock half
    # is faked here.
    from hlyn.core import seccomp

    assert out["enforce"] == seccomp.ready()
    assert out["scope"] is True
    assert out["ports"] is True


@pytest.mark.parametrize(
    ("code", "why"),
    [
        (-1, "arguments"),
        (-2, "ruleset"),
        (-3, "path"),
        (-4, "refused"),
        (-99, "unknown"),
    ],
)
def test_every_shim_failure_raises_and_says_which(shim, code, why):
    # A negative code is the shim reporting it could not do its job. None of
    # them may be mistaken for a confined process, including one this version
    # has never heard of.
    from hlyn.error import Failed
    from hlyn.policy import Policy

    landlock = shim(code)
    with pytest.raises(Failed) as caught:
        landlock.load(Policy())
    assert why in str(caught.value)


# ---------------------------------------------------------------------------
# socket files: Landlock ResolveUnix (ABI 9, Linux 7.1+; DESIGN 5.3, phase 6)
# ---------------------------------------------------------------------------
#
# From ABI 9 the shim limits connecting (and sending with an address) to a
# socket file to the write-granted folders, whenever Landlock handles the
# network (net is not True). Below ABI 9 nothing here governs socket files.
# These run on every kernel: below 9 they pin today's behaviour, from 9 they
# require the refusal. Rows 22 and 23 of the design's matrix, at the kernel.

SOCKETS = """
import errno, socket
def attempt(name, fn):
    try:
        fn()
        print(name, "=>", "OK", flush=True)
    except OSError as exc:
        print(name, "=>", errno.errorcode.get(exc.errno, exc.errno), flush=True)
def stream(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
def sendto(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", path)
def sendmsg(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.sendmsg([b"x"], [], 0, path)
"""


@pytest.fixture
def listening(tmp_path):
    """A stream and a datagram socket in a folder the policy grants, and the
    same pair in one it does not. Nothing accepts: a listening socket's
    backlog and a datagram socket's queue take what is sent."""
    made = []
    for folder in ("granted", "outside"):
        (tmp_path / folder).mkdir()
        for name, kind in (("s.sock", socket.SOCK_STREAM), ("d.sock", socket.SOCK_DGRAM)):
            sock = socket.socket(socket.AF_UNIX, kind)
            sock.bind(str(tmp_path / folder / name))
            if kind == socket.SOCK_STREAM:
                sock.listen(16)
            made.append(sock)
    yield tmp_path / "granted", tmp_path / "outside"
    for sock in made:
        sock.close()


@pytest.mark.parametrize("net", ["False", "[443]", "True"])
def test_socket_files_need_a_write_grant_from_abi_9(listening, net):
    granted, outside = listening
    done = jail(
        SOCKETS + "\n".join(
            f"attempt({label!r}, lambda: {call}({str(folder / name)!r}))"
            for folder, where in ((granted, "granted"), (outside, "outside"))
            for label, call, name in (
                (f"{where} connect", "stream", "s.sock"),
                (f"{where} sendto", "sendto", "d.sock"),
                (f"{where} sendmsg", "sendmsg", "d.sock"),
            )
        ),
        policy=f"Policy(net={net}, write=[{str(granted)!r}])",
        seal=SEAL,
    )
    print(f"Landlock ABI {_ABI}, net={net}:\n{done.stdout}{done.stderr}")
    # The seal itself is FULL on every kernel: asking for ResolveUnix where
    # the kernel lacks it would have made it partial, and refused (FINDINGS.md).
    assert done.returncode == 0, done.stderr
    got = dict(line.split(" => ") for line in done.stdout.splitlines())
    closed = _ABI >= 9 and net != "True"
    for call in ("connect", "sendto", "sendmsg"):
        assert got[f"granted {call}"] == "OK"
        assert got[f"outside {call}"] == ("EACCES" if closed else "OK"), call
