#!/usr/bin/env python3
"""Measure what confinement costs, since the claim is that it costs nothing.

The claim is architectural: nothing sits between the agent and the kernel, so
there is nothing there to add delay. This is the number behind it. Two costs
exist and they are different in kind.

    hlyn.on()   Paid once, at startup, and it is not free. The kernel opens a
                descriptor for every granted path and compiles a BPF program
                for the syscall filter.

    per call    Paid forever afterwards, and this is the one the claim is
                about. It is the kernel consulting a rule it already holds:
                no context switch to a supervisor, no userspace decision, no
                extra hop on a connection.

Method, because a benchmark that can be argued with is worth nothing:

  * Confinement is one-way, so a sealed process cannot be un-sealed to take a
    second sample. Every sample runs in its own forked process.
  * Each per-call figure is measured twice in the same process, before and
    after sealing, so both halves share a CPU, a cache state and one
    interpreter.
  * A control process does exactly the same thing and never seals. Its
    before/after difference is drift, and drift is the noise floor: an "added"
    figure smaller than the drift beside it has not been measured.
  * The absolute figures include Python's own call overhead, which is a large
    fraction of a cheap syscall. The difference does not -- it is identical on
    both sides of the seal.
  * Minimum of several rounds rather than the mean. Every source of noise here
    adds time and none removes it, so the fastest round is the least polluted.
  * After sealing, each process proves the boundary is real and that the calls
    being timed are the ones that cost something. A filter that silently
    failed to load would benchmark beautifully, and so would a connection the
    policy refuses outright.

    python tools/bench.py         both halves
    python tools/bench.py seal    startup cost only
    python tools/bench.py calls   steady-state cost only

Needs a kernel with Landlock; tools/bench.sh supplies one.
"""

from __future__ import annotations

import contextlib
import gc
import json
import os
import socket
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Sequence

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Run from a checkout, against the source in it, rather than whatever is
# installed -- the point is to measure this tree.
sys.path.insert(0, os.path.join(ROOT, "src"))

import hlyn  # noqa: E402
from hlyn.policy import Policy  # noqa: E402

SAMPLES = 31  # processes per startup measurement
SIZES = (1, 8, 64)  # granted paths, to see whether cost grows with the policy

# Iterations and rounds per call. A cheap call needs many iterations before the
# clock can see it; an expensive one does not, and asking for as many would
# only spend minutes proving it.
#
# `connect` gets far more rounds than anything else because it is the only call
# here that waits on the network stack. A refused loopback connection means a
# packet out, a reset back, and a softirq that has to interleave with this
# process, so the distribution has a long tail and the best of seven rounds
# lands wherever it lands. More, shorter rounds give the minimum something
# stable to be the minimum of.
WORK = {
    "clock_gettime": (50_000, 7),
    "getpid": (50_000, 7),
    "stat": (30_000, 7),
    "pread": (30_000, 7),
    "write /dev/null": (30_000, 7),
    "open+close": (20_000, 7),
    "socket+close": (20_000, 7),
    "bind": (20_000, 7),
    "connect": (4_000, 25),
}


# -- running a sample in its own process ------------------------------------


def apart(work: Callable[[], dict], *args: object) -> dict:
    """Run `work` in a fresh process and bring its numbers back.

    Nothing that seals can be measured in this process: one `on()` would
    confine the benchmark itself, and every later sample with it.
    """
    read, write = os.pipe()
    kid = os.fork()
    if kid == 0:  # child
        os.close(read)
        code = 0
        try:
            out = work(*args)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 - report it rather than die silently
            out, code = {"broke": f"{type(exc).__name__}: {exc}"}, 1
        with contextlib.suppress(Exception), os.fdopen(write, "w") as fh:
            json.dump(out, fh)
        os._exit(code)

    os.close(write)
    with os.fdopen(read) as fh:
        body = fh.read()
    _, status = os.waitpid(kid, 0)
    if not body:
        hurt = os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0
        blame = f" (signal {hurt}{', SIGSYS' if hurt == 31 else ''})" if hurt else ""
        raise SystemExit(f"a measurement process died without reporting{blame}")
    out = json.loads(body)
    if "broke" in out:
        raise SystemExit(f"a measurement process failed: {out['broke']}")
    return out


def alone() -> None:
    """Pin to one CPU and stop the collector, so the numbers are the kernel's.

    Neither is available everywhere and neither is essential -- both only
    remove noise from a figure that is a difference anyway.
    """
    with contextlib.suppress(OSError, AttributeError):
        os.sched_setaffinity(0, {0})
    gc.disable()


# -- the policy under measurement -------------------------------------------


def spread(root: str, count: int) -> list[str]:
    """`count` granted directories that do not nest.

    Nesting matters: `prune` collapses `/a/b` into `/a` when both are granted,
    which is correct and would quietly turn a 64-path policy into a 1-path one.
    """
    out = []
    for n in range(count):
        one = os.path.join(root, f"p{n:03d}")
        os.makedirs(one, exist_ok=True)
        out.append(one)
    return out


def grants(plan: Policy) -> int:
    """How many path rules the kernel is actually handed.

    Larger than the number asked for, always: a working interpreter needs its
    own files, and those are granted too.
    """
    total = 0
    for view in (plan.reads(), plan.writes(), plan.runs()):
        if isinstance(view, tuple):
            total += len(view)
    return total


def spare() -> tuple[int, int]:
    """Two ports nothing listens on: one to grant, one to prove refused.

    Nothing listening is deliberate. A refused connection is the cheapest one
    the kernel can perform, so the check under measurement shows up as the
    largest fraction it ever could.
    """
    out = []
    for _ in range(2):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        out.append(sock.getsockname()[1])
        sock.close()
    return out[0], out[1]


def reached(where: int) -> bool:
    """Whether the policy let a connection to `where` be attempted at all.

    Nothing is listening on either port, so the answer is never a connection.
    It is which refusal arrives: `EACCES` from Landlock before the attempt, or
    `ECONNREFUSED` from the far end after it.
    """
    sock = socket.socket()
    try:
        sock.connect(("127.0.0.1", where))
    except PermissionError:
        return False
    except OSError:
        return True
    else:
        return True
    finally:
        sock.close()


def enforced(denied: str, granted: int, shut: int) -> dict[str, bool]:
    """Check the boundary is real, before believing anything measured under it.

    Four questions, and each one has to be asked. Two prove the boundary is
    there at all. The other two prove the calls being timed are the calls that
    matter: a `connect` that Landlock refuses outright never reaches the
    network and is *cheaper* than a permitted one, so a policy that failed to
    grant the port would produce a flattering number rather than a wrong one.
    """
    out = {}

    try:
        with open(denied):
            out["an ungranted path is refused"] = False
    except OSError:
        out["an ungranted path is refused"] = True

    out["an ungranted port is refused"] = not reached(shut)
    out["the timed port is permitted"] = reached(granted)

    # AF_VSOCK is refused by the syscall filter with EPERM, and by a kernel
    # without vsock with EAFNOSUPPORT. seccomp runs before the kernel's own
    # handler, so EPERM arriving means the filter is loaded and nothing else
    # does. Without this, a filter that silently failed to load would leave
    # every syscall figure below describing an unconfined process.
    try:
        socket.socket(40, socket.SOCK_STREAM).close()
        out["the syscall filter is loaded"] = False
    except PermissionError:
        out["the syscall filter is loaded"] = True
    except OSError:
        out["the syscall filter is loaded"] = False

    return out


# -- what hlyn.on() costs once ----------------------------------------------


def staged(size: int) -> tuple[Policy, int]:
    """A policy of `size` granted paths, with its derived views already walked.

    The walk is not idle. Resolving a policy stats every path in it, including
    the interpreter's own files, and the first walk pays for a cold dentry
    cache. Doing it here means the timings below measure a warm one -- the same
    warm one, in every process -- rather than one process paying for the cache
    the next one gets free.
    """
    plan = Policy(read=spread(tempfile.mkdtemp(prefix="hlyn-bench-"), size), log=False)
    return plan, grants(plan)


def one_seal(size: int) -> dict:
    """Time a whole `hlyn.on()`, as a caller pays for it."""
    alone()
    plan, total = staged(size)

    start = time.perf_counter_ns()
    hlyn.on(plan)
    spent = time.perf_counter_ns() - start

    return {"grants": total, "whole": spent}


def one_half(size: int) -> dict:
    """Time the two halves separately, to say where the time goes.

    Each half is the call as `on()` makes it, so each includes resolving the
    policy again -- Landlock's half especially, which is most of what grows
    when the policy does.
    """
    alone()
    from hlyn.core import landlock, seccomp

    plan, _ = staged(size)

    start = time.perf_counter_ns()
    landlock.load(plan)
    middle = time.perf_counter_ns()
    seccomp.load(plan)
    end = time.perf_counter_ns()

    return {"landlock": middle - start, "seccomp": end - middle}


def spread_of(values: Sequence[float]) -> float:
    """The middle 80% of a sample, as a width. Reported so nobody reads noise.

    A startup cost of a couple of milliseconds varies by a few tenths from run
    to run, which is easily enough for a smaller policy to look dearer than a
    larger one. Printing the spread beside the median says which orderings in
    the table mean something.
    """
    ranked = sorted(values)
    low = ranked[int(0.1 * (len(ranked) - 1))]
    high = ranked[int(0.9 * (len(ranked) - 1))]
    return high - low


def startup() -> None:
    print("=== what hlyn.on() costs, once, at startup ===\n")
    print(
        f"{'policy':>12}  {'rules':>6}  {'landlock':>10}  {'seccomp':>10}  "
        f"{'on()':>10}  {'spread':>9}"
    )

    for size in SIZES:
        whole = [apart(one_seal, size) for _ in range(SAMPLES)]
        halves = [apart(one_half, size) for _ in range(SAMPLES)]
        rules = whole[0]["grants"]
        totals = [s["whole"] / 1e6 for s in whole]
        landlock = statistics.median(s["landlock"] for s in halves) / 1e6
        seccomp = statistics.median(s["seccomp"] for s in halves) / 1e6
        said = f"{size} path" + ("s" if size != 1 else "")
        print(
            f"{said:>12}  {rules:>6}  {landlock:>7.2f} ms  {seccomp:>7.2f} ms  "
            f"{statistics.median(totals):>7.2f} ms  {spread_of(totals):>6.2f} ms"
        )

    print(
        f"\nMedian of {SAMPLES} runs, each in a fresh process; `spread` is the middle 80% of\n"
        "the `on()` samples, so an ordering narrower than that is noise rather than a\n"
        "finding. `rules` is every path rule the kernel was handed, which is more than the\n"
        "policy names: a working interpreter needs its own files and gets them.\n"
        "\n"
        "seccomp does not read the policy's paths, so its half is flat by construction.\n"
        "Landlock opens a descriptor per rule, so its half is where growth shows. The two\n"
        "halves do not sum to `on()` because `on()` also creates the scratch directory and\n"
        "scrubs the environment before it seals. Paid once per process, at startup, before\n"
        "the agent does anything."
    )


# -- what it costs per call, afterwards -------------------------------------


def timed(work: Callable[[int], None], loops: int, rounds: int) -> float:
    """Nanoseconds per call, best of `rounds`."""
    best = None
    for _ in range(rounds):
        start = time.perf_counter_ns()
        work(loops)
        spent = (time.perf_counter_ns() - start) / loops
        best = spent if best is None else min(best, spent)
    assert best is not None
    return best


def calls(box: str, port: int) -> list[tuple[str, Callable[[int], None]]]:
    """The calls worth timing, chosen for what each one exercises.

    Landlock hooks the *opening* of a path and the *binding or connecting* of a
    socket, and nothing else. So `open`, `bind` and `connect` are the calls that
    pay for the policy; `pread` on a descriptor that is already open pays
    nothing for it, which is the point -- the cost is at the door, not on every
    byte through it.

    `bind` and `connect` consult the same port rules, and are both here because
    they fail differently as measurements. `connect` is what an agent actually
    does and waits on the network stack to do it, so it is realistic and noisy.
    `bind` reaches the same check and returns without a packet leaving, so it is
    the clean reading of what the check itself costs.

    `socket+close` is here to be subtracted from those two. Both of them open a
    socket first, and `socket` is the one call in this list the syscall filter
    inspects the *arguments* of -- four rules, to keep vsock, Bluetooth and the
    non-routing netlink protocols shut. Without this row that cost would be
    invisible and would read as the port check being dear.
    """
    probe = os.path.join(box, "probe")
    with open(probe, "wb") as fh:
        fh.write(b"x" * 4096)
    held = os.open(probe, os.O_RDONLY)
    sink = os.open(os.devnull, os.O_WRONLY)

    # Each body binds its callable to a local first. An attribute lookup per
    # iteration would be measured too, identically on both sides, but it is
    # noise in the absolute figures for no reason.

    def vdso(n: int) -> None:  # no syscall at all: the harness measuring itself
        now, which = time.clock_gettime, time.CLOCK_MONOTONIC
        for _ in range(n):
            now(which)

    def pid(n: int) -> None:  # the cheapest real syscall: the BPF filter, alone
        call = os.getpid
        for _ in range(n):
            call()

    def look(n: int) -> None:  # path resolution, which Landlock does not hook
        call = os.stat
        for _ in range(n):
            call(probe)

    def door(n: int) -> None:  # the filesystem check, once per open
        opens, shuts, flag = os.open, os.close, os.O_RDONLY
        for _ in range(n):
            shuts(opens(probe, flag))

    def take(n: int) -> None:  # already open, so no check is consulted
        call = os.pread
        for _ in range(n):
            call(held, 1, 0)

    def give(n: int) -> None:
        call, byte = os.write, b"x"
        for _ in range(n):
            call(sink, byte)

    def make_(n: int) -> None:  # the filter's argument comparisons, alone
        make, kind = socket.socket, socket.SOCK_STREAM
        for _ in range(n):
            make(socket.AF_INET, kind).close()

    def hold(n: int) -> None:  # the port check, without touching the network
        make, where, kind = socket.socket, ("127.0.0.1", port), socket.SOCK_STREAM
        for _ in range(n):
            sock = make(socket.AF_INET, kind)
            try:
                # Never listened on, so it never enters TIME_WAIT and the same
                # port is free again the moment it closes.
                sock.bind(where)
            except OSError:
                pass
            finally:
                sock.close()

    def reach(n: int) -> None:  # the port check, once per connection
        make, where, kind = socket.socket, ("127.0.0.1", port), socket.SOCK_STREAM
        for _ in range(n):
            sock = make(socket.AF_INET, kind)
            try:
                sock.connect(where)
            except OSError:  # nothing is listening; the check ran regardless
                pass
            finally:
                sock.close()

    return [
        ("clock_gettime", vdso),
        ("getpid", pid),
        ("stat", look),
        ("pread", take),
        ("write /dev/null", give),
        ("open+close", door),
        ("socket+close", make_),
        ("bind", hold),
        ("connect", reach),
    ]


def steady(size: int, seal: bool) -> dict:
    """Time every call twice in one process, sealing in between if asked.

    With `seal` false this is the control, and its before/after difference is
    the drift that any real figure has to clear.
    """
    alone()
    box = tempfile.mkdtemp(prefix="hlyn-bench-")
    away = tempfile.mkdtemp(prefix="hlyn-away-")  # never granted, so never reachable
    denied = os.path.join(away, "secret")
    with open(denied, "w") as fh:
        fh.write("x")

    port, shut = spare()
    work = calls(box, port)

    before = {name: timed(body, *WORK[name]) for name, body in work}

    proof = {}
    if seal:
        # `away` and `box` are siblings under separate roots, so granting one
        # cannot be collapsed into granting the other.
        plan = Policy(
            read=[*spread(tempfile.mkdtemp(prefix="hlyn-spread-"), size), box],
            write=[box],
            net=[port],
            log=False,
        )
        hlyn.on(plan)
        proof = enforced(denied, port, shut)

    after = {name: timed(body, *WORK[name]) for name, body in work}
    return {"before": before, "after": after, "proof": proof}


def per_call(size: int) -> None:
    sealed = apart(steady, size, True)
    control = apart(steady, size, False)

    print(f"=== what it costs per call afterwards, under a {size}-path policy ===\n")
    for said, held in sealed["proof"].items():
        print(f"  {'ok  ' if held else 'NO  '}{said}")
        if not held:
            print("      -- so every figure below describes something other than a boundary")
    print()

    print(f"{'call':>16}  {'unconfined':>11}  {'confined':>10}  {'added':>9}  {'drift':>7}")

    worst = 0.0
    for name in WORK:
        was, now = sealed["before"][name], sealed["after"][name]
        added = now - was
        drift = control["after"][name] - control["before"][name]
        worst = max(worst, added - abs(drift))
        print(f"{name:>16}  {was:>8.0f} ns  {now:>7.0f} ns  {added:>+6.0f} ns  {drift:>+4.0f} ns")

    print(
        "\n`drift` is the same before/after difference measured in a process that never\n"
        "sealed, so it is the noise floor. An `added` figure inside it is not a cost that\n"
        "has been measured -- which is most of this table. Absolute figures include\n"
        "Python's own call overhead; the difference does not.\n"
        f"\nWorst cost that clears the floor: {worst:.0f} ns per call."
    )
    print(
        "\nReading it: the calls that pay are the ones that ask permission, and they ask\n"
        "once. Opening a path costs tens of nanoseconds; binding a socket costs a few\n"
        "hundred, of which `socket+close` shows how little belongs to the syscall filter.\n"
        "Everything afterwards -- every read, every write, every byte through a descriptor\n"
        "or a connection already established -- is not checked again and does not pay.\n"
        "\nAnd `connect` is honestly unresolved: its own variance is larger than the check\n"
        "inside it, so the figure above bounds the cost rather than stating it. `bind`\n"
        "reaches the same rules without waiting on the network, which is why it is here."
    )
    print(
        "\nFor scale, the thing this is being compared against: a policy enforced by a\n"
        "proxy in the connection path pays an extra TCP handshake, and usually a TLS\n"
        "terminate and re-originate, per connection -- hundreds of microseconds to\n"
        "single-digit milliseconds. That is three to four orders of magnitude above the\n"
        "worst figure in this table, and it is paid per connection rather than once."
    )


def main(argv: Sequence[str]) -> int:
    fit = hlyn.probe()
    if not fit.get("enforce"):
        print(f"nothing to measure here: {fit.get('why', fit)}", file=sys.stderr)
        return 2
    print(f"kernel {fit['kernel']} on {fit['machine']}, Landlock ABI {fit['landlock']}\n")

    what = argv[0] if argv else "all"
    if what in ("all", "seal"):
        startup()
    if what == "all":
        print()
    if what in ("all", "calls"):
        for size in (1, 64):
            per_call(size)
            print()
    if what not in ("all", "seal", "calls"):
        print(f"usage: {sys.argv[0]} [seal|calls]", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
