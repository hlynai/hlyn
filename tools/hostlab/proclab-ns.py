# Option (c) of the /proc lab: a user + pid + mount namespace made before the seal, a fresh procfs
# mounted in it, then the whole of /proc granted. Usage (uid 1000, in the test bed): python3 proclab-ns.py PID
import ctypes
import os
import sys

from hlyn import cli
from hlyn.policy import Policy

libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID = 0x00020000, 0x10000000, 0x20000000
uid, gid = os.getuid(), os.getgid()
if libc.unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) != 0:
    sys.exit(f"unshare failed: {os.strerror(ctypes.get_errno())}")
with open("/proc/self/setgroups", "w") as fh:
    fh.write("deny")
with open("/proc/self/uid_map", "w") as fh:
    fh.write(f"{uid} {uid} 1")
with open("/proc/self/gid_map", "w") as fh:
    fh.write(f"{gid} {gid} 1")
pid = os.fork()
if pid:
    sys.exit(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
# PID 1 of the new namespace.
MS_REC, MS_PRIVATE = 0x4000, 1 << 18
if libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
    sys.exit(f"remount private: {os.strerror(ctypes.get_errno())}")
if libc.mount(b"proc", b"/proc", b"proc", 0x2 | 0x4 | 0x8, None) != 0:  # nosuid nodev noexec
    sys.exit(f"mount proc: {os.strerror(ctypes.get_errno())}")
plan = Policy(read=("/w/tools/hostlab", "/proc"))
sys.exit(cli._launch(["python3", "/w/tools/hostlab/proclab-inner.py", sys.argv[1]], plan))
