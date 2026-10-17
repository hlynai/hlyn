# SPDX-License-Identifier: Apache-2.0
"""Where the surrounding environment refuses `openat2`, hlyn refuses to seal.

hlyn opens each granted path with `openat2(RESOLVE_NO_SYMLINKS)` so a link
swapped in after the check can't redirect the rule. An older container
profile (Docker before 20.10) answers `EPERM` to that call. An ordinary open
would work there, and would follow the swapped link: so the seal fails,
naming the cause, and nothing is confined or granted on a weaker open.

The test installs the same refusal (a seccomp filter returning EPERM for
`openat2`) in a fresh interpreter, then asks for a seal.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="openat2 is Linux"),
    pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)"),
]

# The filter, in classic BPF: load the syscall number, answer EPERM for 437
# (openat2, the same number on every architecture), allow the rest.
REFUSE = """
import ctypes, struct, os
NR_OPENAT2 = 437
prog = [
    (0x20, 0, 0, 0),                       # ld  [syscall number]
    (0x15, 0, 1, NR_OPENAT2),              # jeq openat2 ? next : skip one
    (0x06, 0, 0, 0x00050000 | 1),          # ret ERRNO(EPERM)
    (0x06, 0, 0, 0x7FFF0000),              # ret ALLOW
]
raw = b"".join(struct.pack("HBBI", *ins) for ins in prog)
buf = ctypes.create_string_buffer(raw)
class Prog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
fprog = Prog(len(prog), ctypes.addressof(buf))
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(38, 1, 0, 0, 0) == 0          # PR_SET_NO_NEW_PRIVS
assert libc.prctl(22, 2, ctypes.byref(fprog)) == 0  # PR_SET_SECCOMP, FILTER
"""


def test_a_refused_openat2_makes_the_seal_fail_and_name_why(tmp_path):
    done = boot(REFUSE + f"""
import hlyn
try:
    hlyn.on(read=[{str(tmp_path)!r}], log=False)
    print("SEALED")
except hlyn.Error as exc:
    print("REFUSED", type(exc).__name__, exc)
""")
    print(done.stdout, done.stderr)
    assert "SEALED" not in done.stdout
    assert "REFUSED" in done.stdout and "openat2" in done.stdout and "seccomp" in done.stdout


def test_the_same_seal_works_without_the_refusal(tmp_path):
    # The control: nothing differs but the filter, so the refusal above is the cause.
    done = boot(f"""
import hlyn
hlyn.on(read=[{str(tmp_path)!r}], log=False)
print("SEALED")
""")
    print(done.stdout, done.stderr)
    assert "SEALED" in done.stdout
