# SPDX-License-Identifier: Apache-2.0
"""Connecting a unix socket by a pinned object, not by its path (decision 1, 2026-09-28).

Checks, on Linux 5.6+: a socket file opened with openat2(O_PATH,
RESOLVE_NO_SYMLINKS) can be connected through /proc/self/fd/N; after the
folder holding it is swapped for a symlink, the pinned connect still reaches
the checked socket while a connect by path reaches the other one (the
CVE-2026-79994 pattern); openat2 refuses the swapped path; SO_PEERCRED names
the connecting process, not the one that asked.

    tools/linuxtest.sh --sh 'python3 tools/hostlab/pinlab.py'
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import tempfile
import threading

libc = ctypes.CDLL(None, use_errno=True)
OPENAT2 = 437
NO_SYMLINKS = 0x04


def openat2(path: str) -> int:
    how = struct.pack("QQQ", os.O_PATH | os.O_CLOEXEC, 0, NO_SYMLINKS)
    fd = libc.syscall(OPENAT2, -100, path.encode(), how, len(how))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)
    return int(fd)


def serve(path: str, name: str) -> None:
    """A listener at `path` that answers every connection with `name`."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(8)

    def loop() -> None:
        while True:
            conn, _ = srv.accept()
            conn.sendall(name.encode())
            conn.close()

    threading.Thread(target=loop, daemon=True).start()


def answer(address: str) -> str:
    with socket.socket(socket.AF_UNIX) as c:
        c.connect(address)
        return c.recv(16).decode()


def main() -> None:
    evil = tempfile.mkdtemp()
    serve(os.path.join(evil, "s.sock"), "EVIL")

    work = os.path.join(tempfile.mkdtemp(), "ws")
    os.mkdir(work)
    path = os.path.join(work, "s.sock")
    serve(path, "GOOD")

    pinned = openat2(path)
    kind = os.fstat(pinned).st_mode & 0o170000
    print("pinned a socket:", kind == 0o140000)
    print("connect via /proc/self/fd ->", answer(f"/proc/self/fd/{pinned}"))

    # The agent swaps the folder for a symlink to somewhere else.
    os.rename(work, work + ".old")
    os.symlink(evil, work)
    print("after the swap, pinned connect ->", answer(f"/proc/self/fd/{pinned}"))
    print("after the swap, connect by path ->", answer(path))
    try:
        openat2(path)
        print("openat2 on the swapped path: opened (BAD)")
    except OSError as e:
        print("openat2 on the swapped path:", e.strerror)

    cred = os.path.join(evil, "cred.sock")
    with socket.socket(socket.AF_UNIX) as srv, socket.socket(socket.AF_UNIX) as c:
        srv.bind(cred)
        srv.listen(1)
        c.connect(cred)
        peer, _ = srv.accept()
        pid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
        print("SO_PEERCRED names the connecting process:", pid == os.getpid())
        peer.close()


if __name__ == "__main__":
    main()
