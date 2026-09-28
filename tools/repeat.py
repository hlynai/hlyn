# SPDX-License-Identifier: Apache-2.0
"""Many `hlyn.run(fn)` calls in a row, from one caller (REMAINING #14).

Each call's child tries two things that must be refused, reading a file the
policy doesn't grant and connecting to a port it doesn't list, and with
--live (hosts only) fetches a listed host through the proxy, which must
work. Every call must see what the first saw, and the caller must hold the
same open files, child processes, hlyn helper processes and threads after the last call as after
the first.

    python3 tools/repeat.py [--count N] [--threads] [--live] [MODE ...]

MODE is `off` (net=False), `ports` (net=[443]) or `hosts`
(net=["pypi.org"]); all three by default. `--threads` starts a thread in the
caller first, which takes the slower path. Every call is printed.
"""

from __future__ import annotations

import argparse
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
sys.path.insert(0, os.path.join(ROOT, "src"))

import hlyn  # noqa: E402

MODES: dict[str, object] = {"off": False, "ports": [443], "hosts": ["pypi.org"]}
UNLISTED = ("1.1.1.1", 80)
LISTED = "https://pypi.org/simple/six/"


def attempt(secret: str, live: bool) -> dict[str, str]:
    """Runs in the confined child."""
    seen: dict[str, str] = {}
    try:
        with open(secret) as f:
            f.read()
        seen["read"] = "allowed"
    except OSError as e:
        seen["read"] = f"refused errno {e.errno}"
    try:
        # With the network off, Linux refuses the socket itself.
        with socket.socket() as s:
            s.settimeout(5)
            s.connect(UNLISTED)
        seen["connect"] = "connected"
    except TimeoutError:
        seen["connect"] = "timeout"
    except OSError as e:
        seen["connect"] = f"refused errno {e.errno}"
    if live:
        import urllib.request

        try:
            with urllib.request.urlopen(LISTED, timeout=20) as r:
                seen["fetch"] = str(r.status)
        except Exception as e:  # noqa: BLE001 - reported, not handled
            seen["fetch"] = f"failed {e}"
    return seen


def fds() -> int:
    return len(os.listdir("/dev/fd"))


def children() -> list[int]:
    done = subprocess.run(["pgrep", "-P", str(os.getpid())], capture_output=True, text=True,
                          check=False)
    return sorted(int(p) for p in done.stdout.split())


def helpers() -> int:
    """hlyn's helper processes (the shared proxy detaches, so it isn't a child)."""
    done = subprocess.run(["pgrep", "-f", "hlyn.helpers import main"], capture_output=True,
                          text=True, check=False)
    return len(done.stdout.split())


def wrong(seen: dict[str, str], live: bool) -> list[str]:
    bad = [f"{k} {seen[k]}" for k in ("read", "connect") if not seen[k].startswith("refused")]
    if live and seen.get("fetch") != "200":
        bad.append(f"fetch {seen.get('fetch')}")
    return bad


def mode(name: str, count: int, secret: str, live: bool) -> bool:
    net = MODES[name]
    live = live and name == "hosts"
    print(f"\n== {name}: net={net!r}, {count} calls, caller threads {threading.active_count()}",
          flush=True)
    times: list[float] = []
    first: dict[str, str] | None = None
    base: tuple[int, list[int], int, int] | None = None
    ok = True
    for n in range(1, count + 1):
        start = time.perf_counter()
        seen = hlyn.run(lambda: attempt(secret, live), net=net, log=False)
        ms = (time.perf_counter() - start) * 1000
        times.append(ms)
        state = (fds(), children(), helpers(), threading.active_count())
        if first is None:
            first, base = seen, state
        bad = wrong(seen, live)
        if seen != first:
            bad.append("differs from call 1")
        if state != base:
            bad.append(f"changed: fds, children, helpers, threads {base} -> {state}")
        ok = ok and not bad
        print(f"{n:4} {ms:8.1f} ms  {seen}  fds {state[0]} children {state[1]} "
              f"helpers {state[2]} threads {state[3]}"
              + (f"  WRONG: {'; '.join(bad)}" if bad else ""), flush=True)
    rest = times[1:] or times
    print(f"-- {name}: call 1 {times[0]:.1f} ms; after it median {statistics.median(rest):.1f} ms, "
          f"max {max(rest):.1f} ms; {'all as expected' if ok else 'FAILED'}", flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("modes", nargs="*", metavar="MODE", help="off, ports, hosts (default: all)")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--threads", action="store_true", help="start a thread in the caller first")
    ap.add_argument("--live", action="store_true", help="also fetch pypi.org through the proxy")
    args = ap.parse_args()
    names = args.modes or list(MODES)
    unknown = [m for m in names if m not in MODES]
    if unknown:
        ap.error(f"unknown mode {', '.join(unknown)}: use off, ports or hosts")
    if args.threads:
        threading.Thread(target=threading.Event().wait, daemon=True).start()
    scratch = tempfile.mkdtemp(prefix="hlyn-repeat-")
    secret = os.path.join(scratch, "secret.txt")
    with open(secret, "w") as f:
        f.write("not for the agent\n")
    print(f"{sys.platform}, Python {sys.version.split()[0]}, hlyn {hlyn.__version__}; "
          f"ungranted file {secret}; unlisted {UNLISTED[0]}:{UNLISTED[1]}")
    try:
        results = [mode(name, args.count, secret, args.live) for name in names]
    finally:
        shutil.rmtree(scratch)
    print("\nPASS" if all(results) else "\nFAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
