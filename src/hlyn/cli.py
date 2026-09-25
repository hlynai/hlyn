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
import json
import os
import sys
from collections.abc import Sequence

from . import __version__, jail, spec
from .error import Error
from .policy import Policy, preset, presets

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
        # No `type=int`: argparse would reject a host name with "invalid int
        # value" before the policy can explain why host names are refused.
        p.add_argument("--net", action="append", metavar="PORT", default=[],
                       help="reachable TCP port, repeatable (TCP only: UDP stays open)")
        p.add_argument("--net-any", action="store_true", help="allow all network access")
        p.add_argument("--env", action="append", metavar="NAME", default=[],
                       help="environment variable to keep (repeatable)")
        p.add_argument("--env-any", action="store_true", help="keep the whole environment, secrets included")
        p.add_argument("--no-tmp", action="store_true", help="do not provide a private scratch directory")
        p.add_argument("--log", metavar="PATH", help="write the record here instead of stderr")
        p.add_argument("--no-log", action="store_true", help="record nothing")

    go = sub.add_parser("run", help="confine this shell's child, then run a command")
    grants(go)
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
    """
    if args.preset and args.policy:
        raise Error("give either --preset or --policy, not both: each is a whole policy.")
    if args.policy:
        base = spec.load(args.policy)
    elif args.preset:
        base = jail._plan(args.preset, {})
    else:
        base = Policy()
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
        edits["net"] = _add(base.net, args.net)
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


def _add(base: object, extra: list[str]) -> object:
    """A field widened by flags. A field already granting everything stays so."""
    if base is True:
        return True
    return [*(base or ()), *extra]


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

    print("hlyn watch: running unconfined, recording what it touches", file=sys.stderr)
    # The command's own output goes to stderr, not stdout. Our stdout carries
    # exactly one thing -- the policy -- so `hlyn watch -- ... > policy.toml`
    # produces a file that parses. Mixing the agent's prints into it produces
    # one that does not, and the error arrives a step later where it makes no
    # sense. The user still sees everything; only the stream differs.
    done = subprocess.run(cmd, env=where, stdout=2, check=False)  # noqa: S603

    watch._load(seen)
    if not watch.seen():
        print(
            "hlyn watch: nothing was recorded. The command may not be Python, or may "
            "have exited before importing anything.",
            file=sys.stderr,
        )
        return done.returncode or 1

    plan = watch.suggest()
    print(f"\n# observed over one run of: {' '.join(cmd)}", file=sys.stderr)
    print("# a draft to cut down, not a policy to trust\n", file=sys.stderr)
    sys.stdout.write(spec.dumps(plan) if as_json else _toml(spec.shape(plan)))
    return done.returncode


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
        else:
            items = ",\n".join(f"  {json.dumps(item)}" for item in value)
            out.append(f"{field} = [\n{items},\n]")
    return "\n".join(out) + "\n"


def _machine(out: dict[str, object]) -> str:
    """`probe`'s answer as sentences, for a person rather than a pipeline."""
    where = {"darwin": "macOS", "linux": "Linux"}.get(str(out.get("platform")), out.get("platform"))
    if out.get("enforce"):
        head = f"ok  hlyn can confine programs on this machine ({where} {out.get('kernel', '')})".rstrip()
    else:
        head = f"NO  hlyn cannot confine programs on this machine ({where}): {out.get('why', 'unknown reason')}"
    rows = [
        ("files and programs", out.get("enforce")),
        ("network ports", out.get("ports")),
        ("isolation between agents on this machine", out.get("scope")),
    ]
    return "\n".join([head, *(f"    {'yes' if yes else 'no':<4}{name}" for name, yes in rows)]) + "\n"


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
        said.append("any network" if plan.net is True else f"TCP ports {which(plan.net)}")
    if plan.env:
        said.append("the whole environment" if plan.env is True else f"env {which(plan.env)}")
    if not said:
        said.append("nothing beyond the Python runtime")
    if plan.tmp is False:
        said.append("no scratch folder")
    return "; ".join(said)


def _launch(cmd: list[str], plan: Policy) -> int:
    """Run `cmd` confined in a child, and explain a failure when it has one.

    The child seals itself and becomes `cmd`; this process stays unconfined
    only to wait, pass on the exit code, and say what to try next. Exec-ing
    directly would leave nobody to say it -- and a bare "Operation not
    permitted" is the first thing every new user meets.

    A pipe that closes on exec tells a failure to start (already reported by
    the child) apart from the command itself failing.
    """
    import signal

    r, w = os.pipe()  # not inherited, so a successful exec closes `w`
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            jail.spawn(cmd, plan)
        except Error as exc:
            print(f"hlyn: {exc}", file=sys.stderr)
        except BaseException:
            import traceback

            traceback.print_exc()
        os.write(w, b"x")
        os._exit(1)

    os.close(w)
    # Ctrl-C reaches the child through the terminal; this process only waits.
    # A signal sent to this process by pid is passed on, so killing hlyn kills
    # the command it launched.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda num, _: os.kill(pid, num))
    failed = os.read(r, 1)
    os.close(r)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if failed:
        return 1
    if code:
        _hint(cmd, code)
    return code if code >= 0 else 128 - code


def _hint(cmd: list[str], code: int) -> None:
    import signal

    if code == -signal.SIGSYS:
        print(
            "hlyn: the kernel stopped the command: it made a system call hlyn never allows "
            "(e.g. ptrace, io_uring, mount, loading kernel modules).",
            file=sys.stderr,
        )
        return
    said = f"signal {-code}" if code < 0 else f"code {code}"
    print(
        f"hlyn: the command exited with {said}. If it was blocked, the error above names the "
        f"path, program or port.\n      Allow it with --read, --write, --exec or --net.",
        file=sys.stderr,
    )
    if os.path.basename(cmd[0]).startswith("python"):
        import shlex

        print(f"      Or draft the policy it needs with: hlyn watch -- {shlex.join(cmd)}", file=sys.stderr)


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
            "net": p.net if isinstance(p.net, bool) else list(p.net),
            "env": "all" if p.env is True else sorted(p.keep().keys()),
            "tmp": p.tmp,
        }
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
    return _launch(cmd, _policy(args))


if __name__ == "__main__":
    raise SystemExit(main())
