# SPDX-License-Identifier: Apache-2.0
"""Measure: can a confined program reach SysV IPC / POSIX mqueue objects made outside?

Defensive check only. `outside` makes the objects unconfined; `inside` runs under
`hlyn run` with the default policy and tries to read them; `cleanup` removes them.
FINDINGS.md, "a confined program reaches SysV shared memory".

    python3 tools/hostlab/ipclab.py outside
    hlyn run -- python3 tools/hostlab/ipclab.py inside
    python3 tools/hostlab/ipclab.py cleanup
"""
import ctypes
import ctypes.util
import errno
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.restype = ctypes.c_void_p
libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
IPC_CREAT = 0o1000
IPC_RMID = 0
SHM_STAT = 13
KEY = 0x484C594E
SECRET = b"SECRET-FROM-OUTSIDE"


class Msg(ctypes.Structure):
    _fields_ = [("mtype", ctypes.c_long), ("mtext", ctypes.c_char * 64)]


def err(what):
    e = ctypes.get_errno()
    return f"{what}: -1 {errno.errorcode.get(e, e)}"


def outside():
    shm = libc.shmget(KEY, 4096, IPC_CREAT | 0o600)
    addr = libc.shmat(shm, None, 0)
    ctypes.memmove(addr, SECRET, len(SECRET))
    q = libc.msgget(KEY, IPC_CREAT | 0o600)
    m = Msg(1, SECRET)
    libc.msgsnd(q, ctypes.byref(m), len(SECRET), 0)
    if sys.platform == "darwin":
        print("(no POSIX mq on macOS)")
        return
    rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
    rt.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    mq = rt.mq_open(b"/hlynprobe", os.O_CREAT | os.O_RDWR, 0o600, None)
    rt.mq_send(mq, SECRET, len(SECRET), 0)
    print(f"outside: shm id {shm}, msg queue {q}, mq fd {mq}")


def inside():
    shm = libc.shmget(KEY, 0, 0)
    if shm < 0:
        print(err("shmget by key"))
    else:
        addr = libc.shmat(shm, None, 0)
        if addr in (None, ctypes.c_void_p(-1).value):
            print(err("shmat"))
        else:
            print("shm by key READ:", ctypes.string_at(addr, len(SECRET)))
    # Finding a segment without knowing its key: SHM_STAT walks the kernel's table.
    buf = ctypes.create_string_buffer(512)
    found = [libc.shmctl(i, SHM_STAT, buf) for i in range(4)]
    print("shmctl SHM_STAT ids:", [f for f in found if f >= 0] or err("shmctl"))
    q = libc.msgget(KEY, 0)
    if q < 0:
        print(err("msgget"))
    else:
        m = Msg()
        n = libc.msgrcv(q, ctypes.byref(m), 64, 0, 0o4000)  # IPC_NOWAIT
        print("msg queue READ:", m.mtext[:n] if n >= 0 else err("msgrcv"))
    if sys.platform == "darwin":
        print("(no POSIX mq on macOS)")
        return
    rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1", use_errno=True)
    rt.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    mq = rt.mq_open(b"/hlynprobe", os.O_RDONLY, 0, None)
    if mq < 0:
        print(err("mq_open"))
    else:
        b = ctypes.create_string_buffer(8192)
        n = rt.mq_receive(mq, b, 8192, None)
        print("posix mq READ:", b.raw[:n] if n >= 0 else err("mq_receive"))


def cleanup():
    libc.shmctl(libc.shmget(KEY, 0, 0), IPC_RMID, None)
    libc.msgctl(libc.msgget(KEY, 0), IPC_RMID, None)
    if sys.platform == "darwin":
        return
    rt = ctypes.CDLL(ctypes.util.find_library("rt") or "librt.so.1")
    rt.mq_unlink(b"/hlynprobe")


{"outside": outside, "inside": inside, "cleanup": cleanup}[sys.argv[1]]()
