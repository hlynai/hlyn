"""The command line.

    hlyn run -- python agent.py          confine, then run it
    hlyn probe                           what can this machine enforce
    hlyn show --read /src                what would this policy grant
    hlyn presets                         what is available out of the box

`run` is the whole onboarding story for anyone who would rather not touch their
code: the agent is confined before its first instruction, and nothing inside it
needs to know.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

from . import __version__, jail, spec
from .error import Error
from .policy import Policy, plain, ports, preset, presets

__all__ = ["build", "main"]


def build() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="hlyn",
        description="Runtime containment for AI agents. Denies everything not granted.",
    )
    top.add_argument("-V", "--version", action="version", version=f"hlyn {__version__}")
    sub = top.add_subparsers(dest="verb", required=True)

    def grants(p: argparse.ArgumentParser) -> None:
        p.add_argument("-p", "--preset", metavar="NAME", help=f"one of: {', '.join(sorted(presets))}")
        p.add_argument("-f", "--policy", metavar="FILE",
                       help="read the policy from a .toml, .json or .yaml file")
        p.add_argument("--read", action="append", metavar="PATH", default=[],
                       help="readable path (repeatable)")
        p.add_argument("--write", action="append", metavar="PATH", default=[],
                       help="writable path (repeatable)")
        p.add_argument("--exec", action="append", metavar="PATH", default=[],
                       help="runnable program (repeatable)")
        p.add_argument("--exec-any", action="store_true", help="allow running any program")
        # No `type=int`: a host is as valid here as a port.
        p.add_argument("--net", action="append", metavar="HOST|PORT", default=[],
                       help="reachable host (api.openai.com, *.example.com, localhost:5432, "
                            "10.0.0.5:5432) or TCP port (443: every host on it, UDP stays open); "
                            "hosts or ports, not both; repeatable")
        p.add_argument("--net-any", action="store_true", help="allow all network access")
        p.add_argument("--env", action="append", metavar="NAME", default=[],
                       help="environment variable to keep (repeatable)")
        p.add_argument("--env-any", action="store_true", help="keep the whole environment, secrets included")
        p.add_argument("--no-tmp", action="store_true", help="do not provide a private scratch directory")
        p.add_argument("--log", metavar="PATH", help="write the record here instead of stderr")
        p.add_argument("--no-log", action="store_true", help="record nothing")

    go = sub.add_parser("run", help="confine this shell's child, then run a command")
    grants(go)
    go.add_argument("--no-report", action="store_true",
                    help="do not list what was blocked when the command ends")
    go.add_argument("--json", action="store_true",
                    help="print the list of what was blocked as JSON (on stderr)")
    go.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run")

    check = sub.add_parser("probe", help="report what this machine can enforce")
    check.add_argument("--json", action="store_true", help="print as JSON")

    kinds = sub.add_parser("presets", help="list the built-in presets and what each grants")
    kinds.add_argument("--json", action="store_true", help="print as JSON")

    look = sub.add_parser(
        "watch", help="run a Python program unconfined and print the policy it would need",
    )
    look.add_argument("--json", action="store_true", help="print as JSON rather than TOML")
    look.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run")

    show = sub.add_parser("show", help="print the policy a set of flags produces")
    grants(show)
    show.add_argument("--intent", action="store_true",
                      help="print what was asked for, as a policy file, instead of what it resolves to")
    show.add_argument("--json", action="store_true", help="print as JSON rather than TOML")
    return top


def _policy(args: argparse.Namespace) -> Policy:
    """Turn flags into a policy, without applying anything.

    A file and a preset are both starting points, and flags add to whichever
    was given -- never replace or narrow it. They are mutually exclusive on
    purpose: silently layering a file on top of a preset would make the
    effective policy something neither document states.

    `--net` is the one field where that "always widen" rule is wrong (design
    4.1, gap 8.6). A bare port or host already means "reachable"; if the base
    already allows any network, naming one is the user asking to restrict to
    it, not to add it to "any". `--net` narrows an open network instead of
    being silently swallowed by it, and says so on stderr. `--net-any` is the
    explicit way to keep it open. Every other field (`--read`, `--write`,
    `--exec`, `--env`) only ever widens: naming a path or name on top of a
    field that already grants everything is a no-op, since the wider grant
    already covers it, so there is nothing misleading about leaving it be.
    """
    if args.preset and args.policy:
        raise Error("give either --preset or --policy, not both: each is a whole policy.")
    if args.policy:
        base = spec.load(args.policy)
    elif args.preset:
        base = jail._plan(args.preset, {})
    else:
        base = Policy()
    net_from = None
    if base.net is True:
        if args.policy:
            net_from = f"net = true in {args.policy}"
        elif args.preset:
            net_from = f"--preset {args.preset}"
    edits: dict[str, object] = {}
    if args.read:
        edits["read"] = _add(base.read, args.read)
    if args.write:
        edits["write"] = _add(base.write, args.write)
    if args.exec_any:
        edits["exec"] = True
    elif args.exec:
        edits["exec"] = _add(base.exec, args.exec)
    if args.net_any:
        edits["net"] = True
    elif args.net:
        edits["net"] = _narrow_net(base.net, args.net, net_from)
    if args.env_any:
        edits["env"] = True
    elif args.env:
        edits["env"] = _add(base.env, args.env)
    if args.no_tmp:
        edits["tmp"] = False
    if args.no_log:
        edits["log"] = False
    elif args.log:
        edits["log"] = args.log
    return base.with_(**edits) if edits else base


def _add(base: tuple[object, ...] | bool, extra: list[str]) -> object:
    """A field widened by flags. A field already granting everything stays so."""
    if base is True:
        return True
    return [*(base or ()), *extra]


def _narrow_net(base: tuple[object, ...] | bool, extra: list[str], source: str | None) -> object:
    """`--net` widens a list of ports or hosts, but
    *replaces* a base that already allows any network.

    This is the opposite of `_add`, on purpose (design 4.1, gap 8.6): naming a
    port when the base is "any network" is the one place widening would
    silently restrict nothing, which defeats the point of naming it at all.
    Reported on stderr so the change is never silent, with the flag that
    would keep the network open. `source` names where the "any network" came
    from (a preset or a policy file); it is only unset when `base` is not
    `True`, in which case this behaves exactly like `_add`.
    """
    if base is not True:
        return _add(base, extra)
    if source:
        try:
            shown = ", ".join(str(item) for item in ports(extra))  # type: ignore[union-attr]
        except Error:
            shown = ", ".join(extra)  # the policy will refuse it, with the reason
        print(
            f"hlyn: net was any network (from {source}); --net narrows it to "
            f"{shown}. Use --net-any to keep it open.",
            file=sys.stderr,
        )
    return list(extra)


SEED = """\
# Written by `hlyn watch`. Imported automatically by every Python that starts
# with this directory on PYTHONPATH, which is how the command being watched
# ends up recording without being modified.
import os, sys
try:
    import hlyn.watch
    hlyn.watch.start()
except Exception:
    pass
# Whatever sitecustomize would have run without us still has to run. Ours is
# first on the path, not instead of theirs.
_mine = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != _mine]
try:
    import sitecustomize  # noqa: F401
except ImportError:
    pass
"""


def _watch(cmd: list[str], as_json: bool) -> int:
    """Run `cmd` unconfined with recording turned on, then print what it needed.

    The command is not modified and does not have to cooperate. A generated
    `sitecustomize` on PYTHONPATH is imported by any Python that starts inside
    this run -- the command itself and any Python it spawns -- which is what
    makes the observation cover the whole tree rather than one process.
    """
    import subprocess
    import tempfile

    from . import watch

    box = tempfile.mkdtemp(prefix="hlyn-watch-")
    with open(os.path.join(box, "sitecustomize.py"), "w", encoding="utf-8") as fh:
        fh.write(SEED)

    seen = os.path.join(box, "seen.json")
    where = os.environ.copy()
    where[watch.CHANNEL] = seen
    where["PYTHONPATH"] = os.pathsep.join([box, *filter(None, [where.get("PYTHONPATH")])])
    # The package itself has to be importable by the child, which it is not if
    # hlyn is being run from a checkout rather than an install.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(os.path.join(root, "hlyn")):
        where["PYTHONPATH"] = os.pathsep.join([where["PYTHONPATH"], root])

    # Programs that use HTTPS_PROXY -- requests, httpx, curl, git, pip, npm,
    # Node, Go -- name their real destination only to the proxy they go
    # through, so they go through hlyn's own, in the mode that lets
    # everything through and says where each connection went. Chains
    # through the user's own proxy, as a run would (5.5).
    heard, recorder = _recorder(where)
    # And every program's own file, program and network calls, Python or not,
    # C extensions included, from the library `hlyn run` preloads to hear
    # refusals, told here to report what was allowed instead (Linux).
    ear = _uses(where)

    print("hlyn watch: running unconfined, recording what it touches", file=sys.stderr)
    # The command's own output goes to stderr, not stdout. Our stdout carries
    # exactly one thing -- the policy -- so `hlyn watch -- ... > policy.toml`
    # produces a file that parses. Mixing the agent's prints into it produces
    # one that does not, and the error arrives a step later where it makes no
    # sense. The user still sees everything; only the stream differs.
    try:
        process = subprocess.Popen(cmd, env=where, stdout=2)  # noqa: S603
    except OSError as exc:
        print(f"hlyn watch: couldn't start {cmd[0]}: {exc.strerror or exc}", file=sys.stderr)
        return 127
    uses: list[Any] = []
    while process.poll() is None:
        if ear is not None and ear.fileno() is not None:
            import select

            select.select([ear.fileno()], [], [], 0.2)
            uses.extend(ear.read())
        else:
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(0.2)
    code = process.returncode
    if ear is not None:
        uses.extend(ear.finish())
        ear.close()

    watch._load(seen)
    _heard(uses)
    if recorder is not None:
        _recorded(heard, recorder)
    if not watch.seen():
        print(
            "hlyn watch: nothing was recorded. The command may not be Python, or may "
            "have exited before importing anything.",
            file=sys.stderr,
        )
        return code or 1

    plan = watch.suggest()
    print(f"\n# observed over one run of: {' '.join(cmd)}", file=sys.stderr)
    print("# a draft to cut down, not a policy to trust\n", file=sys.stderr)
    sys.stdout.write(spec.dumps(plan) if as_json else _toml(spec.shape(plan)))
    return code


def _uses(where: dict[str, str]) -> Any:
    """`hlyn watch`'s preloaded listener, pointed at the allowed calls, and
    `where` set up to load it; or None where there is none (macOS, or a
    library that wasn't built)."""
    if sys.platform != "linux":
        return None
    from .core import preload

    ear = preload.Listener(uses=True)
    if ear.lib is None:
        ear.close()
        return None
    where.update(ear.env(where))
    return ear


def _heard(uses: list[Any]) -> None:
    """Add what the preloaded library saw the program use to watch's record,
    in the same form Python's own audit hooks give it."""
    from . import watch

    for use in uses:
        target = use.target
        if use.kind in ("read", "write") and target.startswith("/"):
            watch._seen.add((use.kind, os.path.normpath(target)))
        elif use.kind == "exec":
            watch._program(target, dict(os.environ))
        elif use.kind == "net":
            port, _, address = target.partition(" ")
            if port.isdigit() and address and not address.startswith("unix:"):
                watch._seen.add(("net", port))
                watch._seen.add(("addr", f"{address} {port}"))


def _recorder(where: dict[str, str]) -> tuple[int, Any]:
    """Start `hlyn watch`'s recording proxy and point `where` at it. Returns
    the pipe it reports on and the proxy, or `(-1, None)` if it can't start:
    then watch records what Python itself sees, as before, and says so."""
    from . import route

    heard, said = os.pipe()
    try:
        way = route.start((), events=said, record=True)
    except Error as exc:
        os.close(heard)
        print(f"hlyn watch: recording hosts through a proxy isn't possible here ({exc}); "
              f"hosts will be recorded from Python only.", file=sys.stderr)
        return -1, None
    finally:
        os.close(said)
    where.update(route.env(jail._port(way), base=where))
    return heard, way


def _recorded(heard: int, way: Any) -> None:
    """Add the hosts `hlyn watch`'s proxy saw, and forget the proxy itself:
    the program only connected to it because it was told to."""
    import ipaddress

    from . import watch

    way.close()  # the proxy exits, and its report pipe ends
    data = b""
    with os.fdopen(heard, "rb") as fh:
        data = fh.read()
    for line in data.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("kind") != "seen":
            continue
        host, _, port = str(event.get("target", "")).rpartition(":")
        if not port.isdigit() or not host:
            continue
        try:
            ipaddress.ip_address(host.strip("[]"))
            watch._seen.add(("target", f"{host.strip('[]')} {port}"))
        except ValueError:
            watch._seen.add(("host", f"{host} {port}"))
    for local in ("127.0.0.1", "::1"):
        watch._seen.discard(("addr", f"{local} {way.port}"))
    watch._seen.discard(("host", f"localhost {way.port}"))
    watch._seen.discard(("net", str(way.port)))


def _toml(data: dict[str, object]) -> str:
    """Render a policy as TOML, without taking on a dependency to write it.

    Only the shapes a policy actually holds -- lists of strings, lists of
    integers, strings and booleans -- so this is a rendering, not a TOML
    writer, and it is not exported as one.
    """
    out = []
    for field, value in data.items():
        if isinstance(value, bool):
            out.append(f"{field} = {str(value).lower()}")
        elif isinstance(value, str):
            out.append(f"{field} = {json.dumps(value)}")
        elif not value:
            out.append(f"{field} = []")
        elif isinstance(value, (list, tuple)):
            items = ",\n".join(f"  {json.dumps(item)}" for item in value)
            out.append(f"{field} = [\n{items},\n]")
        else:
            out.append(f"{field} = {json.dumps(value)}")
    return "\n".join(out) + "\n"


def _machine(out: dict[str, object]) -> str:
    """`probe`'s answer as sentences, for a person rather than a pipeline."""
    where = {"darwin": "macOS", "linux": "Linux"}.get(str(out.get("platform")), out.get("platform"))
    if out.get("enforce"):
        head = f"ok  hlyn can confine programs on this machine ({where} {out.get('kernel', '')})".rstrip()
    else:
        why = out.get("why", "unknown reason")
        head = f"NO  hlyn cannot confine programs on this machine ({where}): {why}"
    linux = out.get("platform") == "linux"
    rows = [
        ("files and programs", out.get("enforce"), ""),
        ("network ports", out.get("ports"), ""),
        ("host names in net (api.openai.com)", out.get("hosts"),
         f": {out['why']}" if out.get("enforce") and out.get("why") else ""),
        ("isolation between agents on this machine", out.get("scope"), ""),
        ("local sockets only in write-granted folders, checked by the kernel", out.get("sockets"),
         " (Linux 7.1 or newer; until then host mode's gate checks them, and a racing agent "
         "can get past it)" if linux else ""),
        ("listing what was blocked, after hlyn run", out.get("report"), ""),
    ]
    lines = [head, *(f"    {'yes' if yes else 'no':<4}{name}{'' if yes else why}" for name, yes, why in rows)]
    if out.get("reduced"):
        lines.append(f"    note: host names work in reduced mode here: {out['reduced']}.")
    return "\n".join(lines) + "\n"


def _gist(plan: Policy) -> str:
    """What a policy grants, in a few words."""
    here = os.getcwd()

    def which(value: object) -> str:
        if value is True:
            return "everything"
        return ", ".join("this folder" if item == here else str(item) for item in value)  # type: ignore[attr-defined]

    said = []
    if plan.read:
        said.append(f"read {which(plan.read)}")
    if plan.write:
        said.append(f"write {which(plan.write)}")
    if plan.exec:
        said.append("run any program" if plan.exec is True else f"run {which(plan.exec)}")
    if plan.net:
        if plan.net is True:
            said.append("any network")
        elif plan.hosts():
            said.append(f"hosts {which(plan.hosts())}")
        else:
            said.append(f"TCP ports {which(plan.net)}")
    if plan.env:
        said.append("the whole environment" if plan.env is True else f"env {which(plan.env)}")
    if not said:
        said.append("nothing beyond the Python runtime")
    if plan.tmp is False:
        said.append("no scratch folder")
    return "; ".join(said)


def _launch(cmd: list[str], plan: Policy, quiet: bool = False, as_json: bool = False) -> int:
    """Run `cmd` confined in a child, and say what it was refused.

    The child seals itself and becomes `cmd`; this process stays unconfined to
    wait, listen for refusals while the command runs, pass on the exit code,
    and say what to try next. Exec-ing directly would leave nobody to say it
    -- and a bare "Operation not permitted" is the first thing every new user
    meets.

    A pipe that closes on exec tells a failure to start (already reported by
    the child) apart from the command itself failing.
    """
    from . import report

    ear = _listener(quiet)
    # Everything from here on is undone on the way out, however it goes: a
    # Ctrl-C while the macOS listener is starting would otherwise leave its
    # `log stream` running for good, since nothing it filters for will come.
    try:
        ear.start()
        book = report.Report(plan)
        failed, status = _wait(cmd, ear.grant(plan), ear, book, plan)
    finally:
        ear.close()

    if failed:
        return 1
    code = os.waitstatus_to_exitcode(status)
    book.why = ear.why or _deaf(ear, cmd)
    if as_json:
        sys.stderr.write(json.dumps(book.json(code)) + "\n")
    else:
        sys.stderr.write(book.text(code, cmd))
    return code if code >= 0 else 128 - code


def _wait(cmd: list[str], grants: Policy, ear: Any, book: Any, plan: Policy) -> tuple[bool, int]:
    """Fork, seal and start the command, then listen until it exits.

    Returns whether it failed to start, and its wait status.
    """
    import select
    import signal

    # SIGCHLD wakes the wait below the moment the command exits, instead of
    # on the next poll. Set up before the fork so an instant exit is not missed.
    # Host mode (DESIGN-host-allowlisting.md 5.2, 5.8): the proxy starts
    # here, before the fork, and lives as long as the command and what it
    # starts; its denials go to this run's log.
    way = None
    heard = -1  # the helpers' denials, one JSON line each, for the report
    told: tuple[int | None, int | None] = (None, None)  # the gate's log and report pipe
    if plan.hosts():
        from . import gate, route

        heard, said = os.pipe()
        try:
            with jail._denials(plan) as fd:
                way = route.start(plan.hosts(), log=fd, events=said, inherit=True, gate=jail.gated(),
                                  wait=False)
                if jail.gated():
                    told = (os.dup(fd) if fd is not None else None, os.dup(said))
        except BaseException:
            os.close(heard)
            raise
        finally:
            os.close(said)
        os.set_blocking(heard, False)
    proxied = b""

    wake_r, wake_w = os.pipe()
    for fd in (wake_r, wake_w):
        os.set_blocking(fd, False)
    old_wake = signal.set_wakeup_fd(wake_w)
    old_chld = signal.signal(signal.SIGCHLD, lambda *_: None)
    r = -1
    # With one thread, the gate can serve in the forked process rather than
    # start a fresh interpreter (gate.become's `fresh`, as `hlyn.run(fn)`
    # does): no other thread can have held a lock across the fork.
    alone = False
    if way is not None and sys.platform == "linux":
        from .core.landlock import crowd

        alone = len(crowd()) <= 1
        if alone:
            gate.prepare()
    try:
        r, w = os.pipe()  # not inherited, so a successful exec closes `w`
        pid = os.fork()
        if pid == 0:
            signal.set_wakeup_fd(-1)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            for fd in (r, wake_r, wake_w, *([heard] if heard >= 0 else [])):
                os.close(fd)

            def start() -> NoReturn:
                try:
                    if way is None:
                        jail._spawn(cmd, grants, ear.env, ear.tag)
                    else:
                        port = jail._port(way)
                        jail._spawn(cmd, grants, jail._both(ear.env, jail._proxied(port)), ear.tag,
                                    proxy=(port, way.pid))
                except Error as exc:
                    print(f"hlyn: {exc}", file=sys.stderr)
                except BaseException:  # noqa: BLE001 - anything at all, reported, then the child exits
                    import traceback

                    traceback.print_exc()
                os.write(w, b"x")
                os._exit(1)

            if way is None:
                start()
            # This child becomes the gate for the command: CLI -> gate -> agent.
            gate.become(start, forward=True, isolate=True, close=[way.life, w], fresh=not alone,
                        log=told[0], events=told[1])

        os.close(w)
        for fd in told:
            if fd is not None:
                os.close(fd)
        if way is not None:
            way.close()  # the command holds the proxy now
        # Ctrl-C reaches the child through the terminal; this process only
        # waits. A signal sent to this process by pid is passed on, so killing
        # hlyn kills the command it launched.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda num, _: os.kill(pid, num))

        _log(plan)
        failed = False
        status = None
        while status is None:
            watch = [wake_r] + ([r] if r >= 0 else []) + ([heard] if heard >= 0 else [])
            listening = ear.fileno()
            if listening is not None:
                watch.append(listening)
            ready, _, _ = select.select(watch, [], [], 0.5)
            if heard >= 0 and heard in ready:
                proxied = _proxied(heard, proxied, book)
            if wake_r in ready:
                with contextlib.suppress(OSError):
                    os.read(wake_r, 512)
            if r >= 0 and r in ready:
                failed = bool(os.read(r, 1))
                os.close(r)
                r = -1
            _hear(ear, book)
            _starting(way)
            done, found = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
            if done and os.WIFSTOPPED(found):
                # The command was stopped (Ctrl-Z) and its gate with it: stop
                # too, so the shell sees the job stop, then wake the gate,
                # which hands the command back its terminal.
                os.kill(os.getpid(), signal.SIGSTOP)
                os.kill(pid, signal.SIGCONT)
            elif done:
                status = found
        for denial in ear.finish():
            _file(book, denial)
        if heard >= 0:
            _proxied(heard, proxied, book)
        _starting(way, final=True)
        return failed, status
    finally:
        if r >= 0:
            os.close(r)
        if heard >= 0:
            os.close(heard)
        signal.set_wakeup_fd(old_wake)
        signal.signal(signal.SIGCHLD, old_chld)
        for fd in (wake_r, wake_w):
            os.close(fd)


def _starting(way: Any, final: bool = False) -> None:
    """Say, once, if the proxy `hlyn run` started without waiting for
    (`route.start(wait=False)`) stopped before it was ready."""
    if way is None:
        return
    trouble = way.problem(final=final)
    if trouble:
        print(f"hlyn: {trouble}", file=sys.stderr)


def _exposed(plan: Policy) -> bool:
    """Warn, on stderr, when the policy lets secrets out. By default the run
    goes ahead: the user may mean it, and the message says how to say so.

    Raised through `warnings`, so the standard filters apply: a user who has
    accepted it silences it with PYTHONWARNINGS=ignore::hlyn.Exposed, the same
    way as for the library. Printed by us, so it reads as a sentence rather
    than a file-and-line warning.

    Returns False when the filters make it an error
    (PYTHONWARNINGS=error::hlyn.Exposed, or -W error): the run is refused,
    which is how a CI job keeps a leaky policy from shipping.
    """
    import warnings

    from .secret import Exposed, exposed, warning

    found = exposed(plan)
    if not found:
        return True
    text = warning(found, cli=True)
    try:
        with warnings.catch_warnings(record=True) as heard:
            warnings.warn(text, Exposed, stacklevel=1)
    except Exposed:
        refused = text.replace("hlyn: warning:", "hlyn: refused:", 1).rsplit("\n  Meant it?", 1)[0]
        print(refused, file=sys.stderr)
        print("  Refused because warnings are errors here (PYTHONWARNINGS / -W error).", file=sys.stderr)
        return False
    if heard:
        print(text, file=sys.stderr)
    return True


def _reach(plan: Policy) -> bool:
    """Warn, on stderr, for each host entry that names a local service giving
    onward reach (design 6.7). Same filters and exit rule as `_exposed`."""
    import warnings

    from .hosts import Reach
    from .jail import reaches

    for text in reaches(plan):
        try:
            with warnings.catch_warnings(record=True) as heard:
                warnings.warn(text, Reach, stacklevel=1)
        except Reach:
            print(text.replace("hlyn:", "hlyn: refused:", 1), file=sys.stderr)
            print("  Refused because warnings are errors here (PYTHONWARNINGS / -W error).", file=sys.stderr)
            return False
        if heard:
            print(text, file=sys.stderr)
    return True


def _listener(quiet: bool) -> Any:
    """What will hear the command's refusals. Never raises: a run is never
    refused because its report could not be set up."""
    from . import report

    if quiet:
        return report.Quiet("turned off with --no-report")
    try:
        return jail.back().listen()
    except Exception as exc:  # noqa: BLE001 - the report is an aid, never a reason not to run
        return report.Quiet(f"listening failed ({exc})")


def _deaf(ear: Any, cmd: list[str]) -> str | None:
    """Why a listener that worked could still have heard nothing from `cmd`."""
    import shutil

    if ear.source != "program":
        return None
    from .core import preload

    where = shutil.which(cmd[0])
    if where and preload.static(where):
        return f"{os.path.basename(cmd[0])} is statically linked, so hlyn cannot see inside it"
    return None


def _proxied(fd: int, rest: bytes, book: Any) -> bytes:
    """Add the helpers' denials waiting on `fd` to the report; return any
    partial line. Not logged again here: the proxy and the gate log each one
    themselves. Lines that aren't their JSON are dropped.

    The gate's lines (Linux, 5.9) name the program and say how many times;
    its last line counts what it didn't keep. Both helpers sit outside the
    sandbox, but what they report comes from the agent (a host name, a
    path), so the report checks every flag it is handed."""
    from .report import Denial

    data = rest
    with contextlib.suppress(BlockingIOError):
        while chunk := os.read(fd, 65536):
            data += chunk
    *lines, rest = data.split(b"\n")
    for line in lines:
        try:
            event = json.loads(line)
            if event.get("kind") == "more":
                book.more += int(event.get("count") or 0)
                continue
            source = "gate" if event.get("source") == "gate" else "proxy"
            denial = Denial("net", str(event["target"]), op=str(event["why"]), source=source,
                            by=str(event.get("by") or ""), count=int(event.get("count") or 1),
                            allow=str(event.get("allow") or ""))
        except (ValueError, KeyError, TypeError):
            continue
        book.add(denial)
    return rest[-4096:]


def _hear(ear: Any, book: Any) -> None:
    for denial in ear.read():
        _file(book, denial)


def _file(book: Any, denial: Any) -> None:
    """Add a refusal to the report, and to the log as it happens.

    The record is written by this process, which is unconfined: the agent can
    neither erase it nor, on macOS, forge it.
    """
    from . import log

    entry = book.add(denial)
    if entry is not None:
        log.emit(
            "deny", what=entry.kind, target=entry.target, allow=entry.allow,
            credential=entry.credential, by=denial.by, pid=denial.pid,
            op=denial.op, count=denial.count, source=denial.source,
        )


def _log(plan: Policy) -> None:
    """Point this process's log where the policy says, as the child does."""
    from . import log

    if plan.log is False:
        log.off()
    elif isinstance(plan.log, str):
        log.sink(plan.log)
    else:
        log.sink(True)


def main(argv: Sequence[str] | None = None) -> int:
    """The entry point. Every policy error reaches the user as a sentence.

    A malformed policy is the most likely thing to go wrong here -- a typo in a
    file, a host name in `net`, two starting points at once -- and a traceback
    is a poor way to report a document someone can fix in five seconds.
    """
    try:
        return _run(argv)
    except Error as exc:
        print(f"hlyn: {exc}", file=sys.stderr)
        return 2


def _run(argv: Sequence[str] | None = None) -> int:
    args = build().parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.verb == "probe":
        out = jail.probe()
        sys.stdout.write(json.dumps(out, indent=2) + "\n" if args.json else _machine(out))
        # Non-zero when the machine cannot enforce, so this is usable as a
        # preflight check in a pipeline rather than something to eyeball.
        return 0 if out.get("enforce") else 1

    if args.verb == "presets":
        if args.json:
            print(json.dumps({name: spec.shape(preset(name)) for name in sorted(presets)}, indent=2))
            return 0
        width = max(map(len, presets))
        for name in sorted(presets):
            print(f"{name:<{width}}  {_gist(preset(name))}")
        return 0

    if args.verb == "show":
        p = _policy(args)
        if not _exposed(p) or not _reach(p):
            return 2
        if args.intent:
            # What was asked for, not what it becomes: this is the form a file
            # holds, so `hlyn show --intent > policy.toml` is how a set of
            # flags that works becomes a document someone can review.
            sys.stdout.write(spec.dumps(p) if args.json else _toml(spec.shape(p)))
            return 0
        # Resolved once each: `reads` walks the interpreter's own installation
        # to work out what the runtime needs, which is not something to do
        # twice per field just to render it.
        reads, writes, runs = p.reads(), p.writes(), p.runs()
        resolved: dict[str, object] = {
            "read": reads if isinstance(reads, bool) else list(reads),
            "write": writes if isinstance(writes, bool) else list(writes),
            "exec": runs if isinstance(runs, bool) else list(runs),
            "net": plain(p.net),
            "env": "all" if p.env is True else sorted(p.keep().keys()),
            "tmp": p.tmp,
        }
        if p.hosts():
            # 4.7: where the agent's traffic goes, and what points it there.
            from . import route

            resolved["proxy"] = "127.0.0.1, a port chosen for each run"
            added = sorted(route.env(0))
            if isinstance(resolved["env"], list):
                resolved["env"] = sorted({*resolved["env"], *added})
        sys.stdout.write(json.dumps(resolved, indent=2) + "\n" if args.json else _toml(resolved))
        return 0

    # Only the separator argparse left at the front. Stripping every `--` would
    # rewrite the command being run -- `hlyn run -- git log -- src` would launch
    # `git log src`, which is a different command, silently.
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if args.verb == "watch":
        if not cmd:
            print(
                "hlyn watch: give a command after --, e.g. hlyn watch -- python agent.py",
                file=sys.stderr,
            )
            return 2
        return _watch(cmd, args.json)

    if not cmd:
        print("hlyn run: give a command after --, e.g. hlyn run -- python agent.py", file=sys.stderr)
        return 2

    # Built here, before the fork, so a malformed policy is reported once, as
    # a sentence, with exit code 2 -- like every other command.
    plan = _policy(args)
    if not _exposed(plan) or not _reach(plan):
        return 2
    jail.unbuilt(plan)
    jail._ready(plan)
    return _launch(cmd, plan, args.no_report, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
