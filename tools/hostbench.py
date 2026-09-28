# SPDX-License-Identifier: Apache-2.0
"""What naming hosts costs (DESIGN-host-allowlisting.md section 9; README "Performance").

    python3 tools/hostbench.py [startup] [calls] [connect] [bytes]

startup  medians of `hlyn run --no-report --no-log -- true`: no network,
         `--net 443`, `--net pypi.org`
calls    `hlyn.run(fn)` per call, after the first, from a caller with one
         thread and with two: no network, a port, a host
connect  connect() latency from a sealed client, median and p99: directly to
         a local listener unconfined, then under `--net localhost:PORT` (on
         Linux the gate hands the connection to the proxy; on macOS
         `localhost:PORT` is reached directly), then through the proxy with a
         CONNECT tunnel
bytes    one connection's throughput, 512 MB over loopback, the same three ways

Everything here is local: no packet leaves the machine. All four by default.
Every figure is printed with the samples it came from.
"""

from __future__ import annotations

import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import hlyn  # noqa: E402

HLYN = [sys.executable, "-m", "hlyn.cli"]
ENV = {**os.environ, "PYTHONPATH": SRC}
TRUE = shutil.which("true") or "/usr/bin/true"
RUNS = 15
SIZE = 512 << 20
CHUNK = 1 << 20

# The sealed client: connects COUNT times (or once and reads SIZE bytes), either
# directly or through HTTPS_PROXY with a CONNECT, and prints what it measured.
CLIENT = r"""
import os, socket, sys, time
how, port, count, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])

def dial():
    if how == "direct":
        return socket.create_connection(("127.0.0.1", port))
    proxy = os.environ["HTTPS_PROXY"].rsplit(":", 1)
    s = socket.create_connection((proxy[0].split("//")[-1], int(proxy[1])))
    s.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        more = s.recv(1)
        if not more:
            raise SystemExit(f"proxy closed: {head!r}")
        head += more
    if b" 200" not in head.split(b"\r\n")[0]:
        raise SystemExit(f"proxy said {head!r}")
    return s

if size:
    s = dial()
    got, start = 0, time.perf_counter()
    buf = bytearray(1 << 20)
    while got < size:
        n = s.recv_into(buf)
        if not n:
            break
        got += n
    spent = time.perf_counter() - start
    print(f"bytes {got} seconds {spent:.4f}")
else:
    times = []
    for _ in range(count):
        start = time.perf_counter()
        s = dial()
        times.append((time.perf_counter() - start) * 1e6)
        s.close()
    print("us " + " ".join(f"{t:.1f}" for t in times))
"""


def median_ms(samples: list[float]) -> str:
    return f"{statistics.median(samples):.1f} ms"


def startup() -> None:
    print(f"=== hlyn run startup: median of {RUNS} runs of `true` ===")
    for label, flags in (("no network", []), ("--net 443", ["--net", "443"]),
                         ("--net pypi.org", ["--net", "pypi.org"])):
        cmd = [*HLYN, "run", "--no-report", "--no-log", "--exec", TRUE, *flags, "--", TRUE]
        samples = []
        for _ in range(RUNS):
            start = time.perf_counter()
            done = subprocess.run(cmd, env=ENV, capture_output=True, text=True, check=False)
            samples.append((time.perf_counter() - start) * 1000)
            if done.returncode:
                raise SystemExit(f"{' '.join(cmd)} failed: {done.stderr}")
        print(f"{label:>16}: {median_ms(samples)}  (samples {' '.join(f'{s:.0f}' for s in samples)})")
    samples = []
    for _ in range(RUNS):
        start = time.perf_counter()
        subprocess.run([TRUE], check=True)
        samples.append((time.perf_counter() - start) * 1000)
    print(f"{'bare true':>16}: {median_ms(samples)}")


def calls() -> None:
    print(f"\n=== hlyn.run(fn) per call, median of {RUNS} after the first ===")
    for threads in (1, 2):
        if threads == 2:
            threading.Thread(target=threading.Event().wait, daemon=True).start()
        for label, net in (("no network", False), ("a port", [443]), ("a host", ["pypi.org"])):
            samples = []
            for _ in range(RUNS + 1):
                start = time.perf_counter()
                hlyn.run(lambda: 1, net=net, log=False)
                samples.append((time.perf_counter() - start) * 1000)
            print(f"{threads} caller thread{'s' if threads > 1 else ' '}, {label:>10}: "
                  f"{median_ms(samples[1:])}  (first {samples[0]:.1f} ms)")


def serve(size: int) -> tuple[socket.socket, int]:
    """A local listener that sends `size` bytes to each connection (0: none)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(512)
    block = b"x" * CHUNK

    def loop() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=feed, args=(conn,), daemon=True).start()

    def feed(conn: socket.socket) -> None:
        with conn:
            try:
                sent = 0
                while sent < size:
                    conn.sendall(block)
                    sent += len(block)
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


def client(how: str, port: int, count: int, size: int, confined: bool) -> str:
    with tempfile.TemporaryDirectory() as box:
        script = os.path.join(box, "client.py")
        with open(script, "w") as f:
            f.write(CLIENT)
        args = [sys.executable, script, how, str(port), str(count), str(size)]
        if confined:
            args = [*HLYN, "run", "--no-report", "--no-log", "--read", box,
                    "--net", f"localhost:{port}", "--", *args]
        done = subprocess.run(args, env=ENV, capture_output=True, text=True, check=False, cwd=box)
        if done.returncode:
            raise SystemExit(f"client {how} failed ({done.returncode}): {done.stdout}{done.stderr}")
        return done.stdout.strip().splitlines()[-1]


def ways() -> list[tuple[str, str, bool]]:
    via = "the gate, to the proxy" if sys.platform == "linux" else "Seatbelt, directly"
    return [("unconfined", "direct", False), (f"--net localhost ({via})", "direct", True),
            ("--net localhost, CONNECT via HTTPS_PROXY", "proxy", True)]


def connect() -> None:
    print("\n=== connect() to a local listener, 1000 connections ===")
    srv, port = serve(0)
    try:
        for label, how, confined in ways():
            line = client(how, port, 1000, 0, confined)
            times = sorted(float(t) for t in line.split()[1:])
            p99 = times[int(0.99 * (len(times) - 1))]
            print(f"{label:>44}: median {statistics.median(times):7.1f} us, p99 {p99:7.1f} us")
    finally:
        srv.close()


def throughput() -> None:
    print(f"\n=== one connection's throughput, {SIZE >> 20} MB over loopback, best of 3 ===")
    srv, port = serve(SIZE)
    try:
        for label, how, confined in ways():
            rates = []
            for _ in range(3):
                parts = client(how, port, 1, SIZE, confined).split()
                got, spent = int(parts[1]), float(parts[3])
                if got < SIZE:
                    raise SystemExit(f"{label}: only {got} bytes arrived")
                rates.append(got / spent / 1e6)
            print(f"{label:>44}: {max(rates):7.0f} MB/s  (runs {' '.join(f'{r:.0f}' for r in rates)})")
    finally:
        srv.close()


def main() -> int:
    what = sys.argv[1:] or ["startup", "calls", "connect", "bytes"]
    fit = hlyn.probe()
    print(f"{fit['platform']} {fit['kernel']} on {fit['machine']}, Python {sys.version.split()[0]}\n")
    steps = {"startup": startup, "calls": calls, "connect": connect, "bytes": throughput}
    for name in what:
        if name not in steps:
            raise SystemExit(f"unknown part {name}: use startup, calls, connect or bytes")
        steps[name]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
