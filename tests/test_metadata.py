# SPDX-License-Identifier: Apache-2.0
"""Changing a file's mode, owner, times or attributes is allowed only inside a write grant (Linux).

Landlock has no right for these calls, so a confined program with no write
grant could still change any file it could see (measured on 7.0.14). The gate
now answers them: inside a write grant it does the call itself on the object it
checked; anywhere else the call fails with EPERM and the report names the
`--write` folder that would allow it. Each test prints what the confined
program saw, and each refusal has an allowed twin in a granted folder.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import struct
import subprocess
import sys
import textwrap

import pytest
from conftest import ROOT, SRC, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="the gate is Linux's"),
    pytest.mark.skipif(sys.platform == "linux" and not enforces(), reason="this kernel cannot seal"),
]

THEN = 1_000_000_000  # a fixed time, in seconds


def agent(body: str, *, write: list[str], read: list[str] = (), writes_open: bool = False, timeout: int = 60) -> dict[str, str]:
    """Run `body` (which fills `seen`) confined with the given write grants;
    what it saw, name -> result, printed in full."""
    head = textwrap.dedent(f"""
        import sys, json, errno, os
        sys.path.insert(0, {SRC!r})
        import hlyn

        def attempt(seen, name, fn):
            try:
                fn()
                seen[name] = "ok"
            except OSError as exc:
                seen[name] = errno.errorcode.get(exc.errno, str(exc.errno))

        def work():
            seen = {{}}
    """)
    tail = textwrap.dedent(f"""
            return seen

        print(json.dumps(hlyn.run(work, write={True if writes_open else write!r}, read={list(read)!r}, log=False)))
    """)
    code = head + textwrap.indent(textwrap.dedent(body), "    ") + "\n" + tail
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=timeout, check=False)
    print(done.stdout, done.stderr)
    assert done.returncode == 0, done.stderr
    seen: dict[str, str] = json.loads(done.stdout.strip().splitlines()[-1])
    return seen


def make(folder, name="f", mode=0o600):
    path = folder / name
    path.write_text("data")
    path.chmod(mode)
    os.utime(path, (THEN, THEN))
    return str(path)


def test_changes_outside_the_grants_are_refused_and_change_nothing(tmp_path):
    kept = tmp_path / "kept"
    box = tmp_path / "box"
    kept.mkdir()
    box.mkdir()
    target = make(kept)
    seen = agent(f"""
        t = {target!r}
        uid, gid = os.getuid(), os.getgid()
        attempt(seen, "chmod", lambda: os.chmod(t, 0o644))
        attempt(seen, "chown", lambda: os.chown(t, uid, gid))
        attempt(seen, "utime", lambda: os.utime(t, (1, 1)))
        attempt(seen, "utime now", lambda: os.utime(t, None))
        attempt(seen, "utime ns", lambda: os.utime(t, ns=(5, 5)))
        attempt(seen, "setxattr", lambda: os.setxattr(t, "user.hlyn", b"x"))
        attempt(seen, "removexattr", lambda: os.removexattr(t, "user.hlyn"))
        fd = os.open(t, os.O_RDONLY)
        attempt(seen, "fchmod", lambda: os.fchmod(fd, 0o644))
        attempt(seen, "fchown", lambda: os.fchown(fd, uid, gid))
        attempt(seen, "futimens", lambda: os.utime(fd, (1, 1)))
        attempt(seen, "fsetxattr", lambda: os.setxattr(fd, "user.hlyn", b"x"))
        dirfd = os.open({str(kept)!r}, os.O_RDONLY)
        attempt(seen, "chmod under a descriptor", lambda: os.chmod("f", 0o644, dir_fd=dirfd))
        os.chdir({str(kept)!r})
        attempt(seen, "chmod relative", lambda: os.chmod("f", 0o644))
    """, write=[str(box)], read=[str(kept)])
    after = os.stat(target)
    print("seen:", seen, "| mode after:", oct(stat.S_IMODE(after.st_mode)), "| mtime after:", after.st_mtime)
    assert set(seen.values()) == {"EPERM"}, seen
    assert len(seen) == 13
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert after.st_mtime == THEN
    assert b"user.hlyn" not in b"".join(n.encode() for n in os.listxattr(target))


def test_the_same_changes_inside_a_grant_work_and_take_effect(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    target = make(box)
    seen = agent(f"""
        t = {target!r}
        uid, gid = os.getuid(), os.getgid()
        attempt(seen, "chmod", lambda: os.chmod(t, 0o640))
        attempt(seen, "chown", lambda: os.chown(t, uid, gid))
        attempt(seen, "utime", lambda: os.utime(t, (1234, 5678)))
        fd = os.open(t, os.O_RDONLY)
        attempt(seen, "fchmod", lambda: os.fchmod(fd, 0o604))
        attempt(seen, "futimens", lambda: os.utime(fd, ns=(7 * 10**9 + 5, 9 * 10**9 + 6)))
        dirfd = os.open({str(box)!r}, os.O_RDONLY)
        attempt(seen, "chmod under a descriptor", lambda: os.chmod("f", 0o660, dir_fd=dirfd))
        os.chdir({str(box)!r})
        attempt(seen, "chmod relative", lambda: os.chmod("f", 0o620))
    """, write=[str(box)])
    after = os.stat(target)
    print("seen:", seen, "| mode after:", oct(stat.S_IMODE(after.st_mode)), "| times after:",
          after.st_atime_ns, after.st_mtime_ns)
    assert set(seen.values()) == {"ok"}, seen
    assert len(seen) == 7
    assert stat.S_IMODE(after.st_mode) == 0o620  # the last change, so every earlier one did not stick by luck
    assert (after.st_atime_ns, after.st_mtime_ns) == (7 * 10**9 + 5, 9 * 10**9 + 6)


def test_an_attribute_inside_a_grant_is_set_and_removed(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    target = make(box)
    try:  # the control: this folder's filesystem takes user attributes at all
        os.setxattr(target, "user.control", b"1")
    except OSError as exc:
        pytest.skip(f"no user attributes on this filesystem: {exc}")
    seen = agent(f"""
        t = {target!r}
        attempt(seen, "setxattr", lambda: os.setxattr(t, "user.hlyn", b"hello"))
        seen["value"] = os.getxattr(t, "user.hlyn").decode()
        attempt(seen, "create twice", lambda: os.setxattr(t, "user.hlyn", b"x", os.XATTR_CREATE))
        attempt(seen, "removexattr", lambda: os.removexattr(t, "user.control"))
    """, write=[str(box)])
    print("seen:", seen, "| attributes after:", os.listxattr(target))
    assert seen == {"setxattr": "ok", "value": "hello", "create twice": "EEXIST", "removexattr": "ok"}
    assert sorted(os.listxattr(target)) == ["user.hlyn"]


def test_a_link_inside_a_grant_does_not_reach_a_file_outside_it(tmp_path):
    kept = tmp_path / "kept"
    box = tmp_path / "box"
    kept.mkdir()
    box.mkdir()
    target = make(kept)
    (box / "link").symlink_to(target)
    own = make(box, "own")
    seen = agent(f"""
        attempt(seen, "chmod through the link", lambda: os.chmod({str(box / "link")!r}, 0o644))
        attempt(seen, "utime through the link", lambda: os.utime({str(box / "link")!r}, (1, 1)))
        attempt(seen, "the link itself", lambda: os.utime({str(box / "link")!r}, (42, 42), follow_symlinks=False))
        attempt(seen, "a file next to it", lambda: os.chmod({own!r}, 0o640))
    """, write=[str(box)])
    after = os.stat(target)
    print("seen:", seen, "| target mode:", oct(stat.S_IMODE(after.st_mode)), "| target mtime:", after.st_mtime,
          "| link mtime:", os.lstat(box / "link").st_mtime)
    assert seen == {"chmod through the link": "EPERM", "utime through the link": "EPERM",
                    "the link itself": "ok", "a file next to it": "ok"}
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert after.st_mtime == THEN
    assert os.lstat(box / "link").st_mtime == 42
    assert stat.S_IMODE(os.stat(own).st_mode) == 0o640


def test_a_descriptor_to_a_file_that_was_removed_is_refused(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    target = make(box)
    seen = agent(f"""
        fd = os.open({target!r}, os.O_RDONLY)
        attempt(seen, "before", lambda: os.fchmod(fd, 0o640))
        os.unlink({target!r})
        attempt(seen, "after", lambda: os.fchmod(fd, 0o600))
    """, write=[str(box)])
    print("seen:", seen)
    assert seen == {"before": "ok", "after": "EPERM"}


def test_with_writes_open_nothing_is_trapped_and_the_call_just_runs(tmp_path):
    target = make(tmp_path)
    code = textwrap.dedent(f"""
        import sys, os
        sys.path.insert(0, {SRC!r})
        import hlyn
        hlyn.run(lambda: os.chmod({target!r}, 0o644), write=True, log=False)
        print("mode", oct(os.stat({target!r}).st_mode & 0o7777))
    """)
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False)
    print(done.stdout, done.stderr)
    assert done.returncode == 0, done.stderr
    assert "mode 0o644" in done.stdout


def test_the_report_names_the_folder_to_grant(tmp_path):
    kept = tmp_path / "kept"
    kept.mkdir()
    target = make(kept)
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--", sys.executable, "-c",
         f"import os; os.chmod({target!r}, 0o644)"],
        capture_output=True, text=True, timeout=60, check=False, cwd=ROOT,
        env={**os.environ, "PYTHONPATH": SRC, "HLYN_NO_COLOR": "1", "NO_COLOR": "1"})
    print(done.stdout, done.stderr)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert f"--write {kept}" in done.stdout + done.stderr


def test_the_filter_sends_these_calls_to_the_gate_only_when_asked():
    from hlyn import Policy
    from hlyn.core import seccomp

    plan = Policy(write=[], net=False)
    plain = seccomp.program(plan)
    guarded = seccomp.program(plan, meta=True)
    print("filter bytes: plain", len(plain), "| guarded", len(guarded))
    assert len(guarded) > len(plain)
    assert len(seccomp.program(plan, meta=False)) == len(plain)


class _OldLibseccomp:
    """The installed libseccomp, but one that has never heard of `setxattrat`
    and refuses its number (what Ubuntu 24.04's 2.5.5 did on CI: error 14)."""

    def __init__(self, real):
        self.real = real
        self.seccomp_syscall_resolve_name = self._resolve
        self.seccomp_rule_add_array = self._add

    def _resolve(self, name):
        return -1 if name == b"setxattrat" else self.real.seccomp_syscall_resolve_name(name)

    def _add(self, ctx, action, number, count, block):
        return -14 if number == 463 else self.real.seccomp_rule_add_array(ctx, action, number, count, block)

    def __getattr__(self, name):
        return getattr(self.real, name)


def test_a_libseccomp_that_does_not_know_a_newer_call_still_builds_the_filter_and_says_what_is_left(monkeypatch):
    from hlyn import Policy
    from hlyn.core import seccomp

    real = seccomp.lib()
    plan = Policy(write=[], net=False)
    whole = len(seccomp.program(plan, meta=True))
    monkeypatch.setattr(seccomp, "lib", lambda: _OldLibseccomp(real))
    old = len(seccomp.program(plan, meta=True))
    left = seccomp.unfiltered()
    print("filter bytes: this libseccomp", whole, "| one that refuses setxattrat", old, "| left out:", left)
    assert 0 < old <= whole  # builds; the other 19 calls are still sent to the gate
    import platform

    major, minor = (int(part) for part in platform.release().split(".")[:2])
    # Left out exactly when this kernel has the call (6.13 and newer).
    assert left == (["setxattrat"] if (major, minor) >= (6, 13) else [])


FLAGS = """
import fcntl, struct
GET, SET, DUMP = 0x80086601, 0x40086602, 0x40
def flags(fd):
    buf = bytearray(8)
    fcntl.ioctl(fd, GET, buf, True)
    return struct.unpack("l", buf)[0]
"""


def test_file_attribute_ioctls_follow_the_same_rule_as_chmod(tmp_path):
    kept = tmp_path / "kept"
    box = tmp_path / "box"
    kept.mkdir()
    box.mkdir()
    outside, inside = make(kept), make(box)
    body = FLAGS + """
for name, path in (("outside", {outside!r}), ("inside", {inside!r})):
    fd = os.open(path, os.O_RDONLY)
    seen[name + " before"] = flags(fd)
    attempt(seen, name + " set", lambda: fcntl.ioctl(fd, SET, struct.pack("l", flags(fd) | DUMP)))
    seen[name + " after"] = flags(fd)
    attempt(seen, name + " nread", lambda: fcntl.ioctl(fd, 0x541B, bytearray(4), True))  # FIONREAD, untouched
"""
    # The control: this filesystem takes the flag at all.
    probe = os.open(outside, os.O_RDONLY)
    try:
        fcntl.ioctl(probe, 0x40086602, struct.pack("l", 0x40))
    except OSError as exc:
        pytest.skip(f"no file flags on this filesystem: {exc}")
    finally:
        os.close(probe)
    # the control set the flag on `outside`: undo it
    undo = os.open(outside, os.O_RDONLY)
    fcntl.ioctl(undo, 0x40086602, struct.pack("l", 0))
    os.close(undo)
    seen = agent(body.format(outside=outside, inside=inside), write=[str(box)], read=[str(kept)])
    print("seen:", seen)
    assert seen["outside set"] == "EPERM" and seen["outside after"] == seen["outside before"]
    assert seen["inside set"] == "ok" and seen["inside after"] == seen["inside before"] | 0x40
    assert seen["outside nread"] == "ok" and seen["inside nread"] == "ok"


def _guard(box, identity):
    from hlyn.core import guard

    config = guard.Config(port=0, rules=(), writes=(str(box),), meta=True,
                          anchors=((str(box), *identity),))
    return guard.Guard(-1, config)  # the descriptor is never read by these checks


def test_the_gate_acts_only_beneath_the_grant_that_was_checked(tmp_path):
    from hlyn.core import notify

    box, kept = tmp_path / "box", tmp_path / "kept"
    box.mkdir()
    kept.mkdir()
    inside, outside = make(box), make(kept)
    info = os.stat(box)
    gate = _guard(box, (info.st_dev, info.st_ino))
    root = gate._root(inside)
    assert root is not None
    held = gate._beneath(root)
    found = os.fstat(held)
    print("grant kept:", len(gate.anchors), "| opened beneath it:", found.st_ino == os.stat(inside).st_ino)
    assert len(gate.anchors) == 1 and found.st_ino == os.stat(inside).st_ino
    os.close(held)
    assert gate._root(outside) is None  # not in the grant by name
    with pytest.raises(OSError) as refused:  # and the open itself cannot climb out of it
        notify.pin("../kept/f", under=gate.anchors[0][1], beneath=True)
    print("climbing out:", refused.value)


def test_a_grant_replaced_after_it_was_checked_is_not_honoured_by_the_gate(tmp_path):
    box = tmp_path / "box"
    box.mkdir()
    make(box)
    info = os.stat(box)
    checked = (info.st_dev, info.st_ino)
    kept = _guard(box, checked)
    box.rename(tmp_path / "box.old")  # another folder now has the name
    box.mkdir()
    make(box)
    swapped = _guard(box, checked)
    print("same folder: grants kept", len(kept.anchors), "| replaced folder: grants kept", len(swapped.anchors))
    assert len(kept.anchors) == 1 and swapped.anchors == [] and swapped._root(str(box / "f")) is None


def test_ioctls_that_change_a_file_for_good_are_refused_while_writes_are_limited(tmp_path):
    """fs-verity enable and the encryption policy and key calls need only the file's mode, which
    Landlock ignores. The refusal comes before the filesystem is asked, so any file shows it."""
    box = tmp_path / "box"
    box.mkdir()
    target = make(box)
    body = f"""
fd = os.open({target!r}, os.O_RDONLY)
for name, request, size in (("verity", 0x40806685, 128), ("policy", 0x800C6613, 12),
                            ("add key", 0xC0506617, 80), ("remove key", 0xC0406618, 64)):
    attempt(seen, name, lambda: __import__("fcntl").ioctl(fd, request, bytearray(size), True))
"""
    refused = agent(body, write=[str(box)], read=[str(box)])
    open_ = agent(body, write=[str(box)], read=[str(box)], writes_open=True)
    print("limited writes:", refused, "| writes open:", open_)
    assert set(refused.values()) == {"EPERM"}
    assert "EPERM" not in open_.values() and len(open_) == 4  # the filesystem answers instead
