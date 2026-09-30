# SPDX-License-Identifier: Apache-2.0
"""Unix sockets with the network off or limited to ports, before Linux 7.1.

Landlock checks socket files only from ABI 9 (Linux 7.1). Before that, with
`net=False` (the default) or ports, a confined program reached any unix
socket on the machine: measured 2026-09-28, the user's systemd bus (which
can start a program outside the environment) and `docker.sock` (root, for a
member of the docker group). So on those kernels every entry point starts
the gate for these modes too, and a unix connect gets host mode's rules: a
write grant on the folder, never a refused socket, connected by the gate
itself (guard's pinned swap). IP sockets are let through to Landlock, which
checks ports as before. On 7.1+ the kernel does it and no gate starts.

Each test prints what the confined program saw.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading

import pytest
from conftest import ROOT, SRC, boot, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Landlock and the gate are Linux's"),
    pytest.mark.skipif(sys.platform == "linux" and not enforces(), reason="this kernel cannot seal"),
]

AGENT = """
import errno, socket, sys
def attempt(name, fn):
    try:
        got = fn()
        print(name + ":", "OK" if got is None else got, flush=True)
    except OSError as exc:
        print(name + ":", errno.errorcode.get(exc.errno, exc.errno), flush=True)
def unix(path):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(path)
        return s.recv(32).decode()
def tcp(port):
    with socket.socket() as s:
        s.connect(("127.0.0.1", port))
        return s.recv(32).decode()
attempt("granted", lambda: unix(GRANTED))
attempt("not granted", lambda: unix(OTHER))
attempt("docker.sock", lambda: unix(DOCKER))
if LISTED:
    attempt("tcp listed", lambda: tcp(LISTED))
    attempt("tcp unlisted", lambda: tcp(UNLISTED))
"""


class Place:
    """Listeners the agent tries: one unix socket in a write-granted folder,
    one outside every grant, a docker.sock outside every grant, and two TCP
    ports. Each answers with its name."""

    def __init__(self) -> None:
        self.box = tempfile.mkdtemp(prefix="hlyn-ug-")
        self.other = tempfile.mkdtemp(prefix="hlyn-ug-other-")
        self.socks: list[socket.socket] = []
        self.granted = self._unix(f"{self.box}/app.sock", "app")
        self.private = self._unix(f"{self.other}/private.sock", "PRIVATE")
        self.docker = self._unix(f"{self.other}/docker.sock", "DOCKER")
        self.listed = self._tcp("listed")
        self.unlisted = self._tcp("UNLISTED")
        self.script = f"{self.box}/agent.py"

    def _serve(self, sock: socket.socket, name: str) -> None:
        sock.listen(64)
        self.socks.append(sock)

        def loop() -> None:
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                conn.sendall(name.encode())
                conn.close()

        threading.Thread(target=loop, daemon=True).start()

    def _unix(self, path: str, name: str) -> str:
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(path)
        self._serve(sock, name)
        return path

    def _tcp(self, name: str) -> int:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self._serve(sock, name)
        return int(sock.getsockname()[1])

    def write(self, ports: bool) -> str:
        listed = str(self.listed) if ports else "0"
        code = (AGENT.replace("GRANTED", repr(self.granted)).replace("OTHER", repr(self.private))
                .replace("DOCKER", repr(self.docker))
                .replace("UNLISTED", str(self.unlisted)).replace("LISTED", listed))
        with open(self.script, "w") as fh:
            fh.write(code)
        return code

    def close(self) -> None:
        for sock in self.socks:
            sock.close()


@pytest.fixture
def place():
    served = Place()
    yield served
    served.close()


def said(out: str) -> dict[str, str]:
    return dict(line.split(": ", 1) for line in out.splitlines() if ": " in line and not line.startswith(" "))


def check(out: str, ports: bool) -> None:
    got = said(out)
    assert got.get("granted") == "app", got
    assert got.get("not granted") == "EACCES", got
    assert got.get("docker.sock") == "EACCES", got
    if ports:
        assert got.get("tcp listed") == "listed", got
        assert got.get("tcp unlisted") == "EACCES", got


MODES = {"off": False, "ports": True}


@pytest.mark.parametrize("mode", MODES)
def test_hlyn_run(place, mode):
    ports = MODES[mode]
    place.write(ports)
    cmd = [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--read", place.box, "--write", place.box,
           *(["--net", str(place.listed)] if ports else []), "--", sys.executable, place.script]
    done = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC),
                          timeout=120, check=False)
    print(done.stdout, done.stderr, sep="\n")
    check(done.stdout, ports)
    # The report names each refusal and the flag that would allow the one
    # that can be allowed.
    assert f"local socket {place.private}" in done.stderr
    assert f"--write {place.other}" in done.stderr
    assert f"local socket {place.docker}" in done.stderr


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("threads", [1, 2])
def test_hlyn_run_fn(place, mode, threads):
    ports = MODES[mode]
    code = place.write(ports)
    done = boot(f"""
import threading, hlyn
if {threads} > 1:
    threading.Thread(target=threading.Event().wait, daemon=True).start()
def fn():
    exec(compile({code!r}, "agent", "exec"), {{}})
hlyn.run(fn, read=[{place.box!r}], write=[{place.box!r}], net={[place.listed] if ports else False!r},
         log=False)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    check(done.stdout, ports)


@pytest.mark.parametrize("mode", MODES)
def test_hlyn_spawn(place, mode):
    ports = MODES[mode]
    place.write(ports)
    done = boot(f"""
import sys, hlyn
hlyn.spawn([sys.executable, {place.script!r}], read=[{place.box!r}], write=[{place.box!r}],
           net={[place.listed] if ports else False!r}, log=False)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    check(done.stdout, ports)


@pytest.mark.parametrize("mode", MODES)
def test_hlyn_on(place, mode):
    ports = MODES[mode]
    code = place.write(ports)
    done = boot(f"""
import hlyn
got = hlyn.on(read=[{place.box!r}], write=[{place.box!r}], net={[place.listed] if ports else False!r},
              log=False)
print("helpers:", got.get("helpers"))
exec(compile({code!r}, "agent", "exec"), {{}})
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    check(done.stdout, ports)


def test_net_false_inside_host_mode_still_seals_and_the_outer_gate_checks_sockets(place):
    """Linux allows one notification listener per process tree. Inside host
    mode the inner seal can't add its own gate; it seals without one, and
    the outer gate's rules still apply to its unix connects."""
    place.write(False)
    done = boot(f"""
import subprocess, sys, hlyn
inner = '''
import sys; sys.path.insert(0, {SRC!r})
import hlyn
got = hlyn.on(read=[{place.box!r}], write=[{place.box!r}], log=False)
print("inner: SEALED, helpers", got.get("helpers"))
exec(open({place.script!r}).read(), {{}})
'''
def nested():
    done = subprocess.run([sys.executable, "-c", inner], capture_output=True, text=True)
    return done.stdout + done.stderr[-1500:]
print(hlyn.run(nested, net=["api.example.com"], exec=[sys.executable], read=[{ROOT!r}, {place.box!r}],
               write=[{place.box!r}], log=False))
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    assert "inner: SEALED" in done.stdout
    check(done.stdout, False)


@pytest.mark.parametrize("net", [False, ["api.example.com"]], ids=["off", "hosts"])
def test_hlyn_on_s_gate_holds_none_of_the_callers_descriptors(net):
    """`on()`'s gate outlives the call. If it kept a copy of a descriptor the
    caller had open, closing it in the caller would close nothing: here, the
    reader of a pipe would never see its end. It also says how long `on()`
    took, since starting this gate is most of it before Linux 7.1."""
    done = boot(f"""
import os, select, time, hlyn
r, w = os.pipe()
start = time.perf_counter()
got = hlyn.on(net={net!r}, log=False)
took = (time.perf_counter() - start) * 1000
print("on() took", round(took, 1), "ms; helpers", got.get("helpers"))
os.close(w)
ready, _, _ = select.select([r], [], [], 5)
print("pipe end seen:", bool(ready) and os.read(r, 1) == b"")
""")
    print(done.stdout, done.stderr[-800:])
    assert "pipe end seen: True" in done.stdout
