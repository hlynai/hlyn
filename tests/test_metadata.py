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

import json
import os
import stat
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


def agent(body: str, *, write: list[str], read: list[str] = (), timeout: int = 60) -> dict[str, str]:
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

        print(json.dumps(hlyn.run(work, write={write!r}, read={list(read)!r}, log=False)))
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
