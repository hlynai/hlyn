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

from . import attest, jail, spec
from .error import Error
from .policy import Policy, presets

__all__ = ["build", "main"]


def build() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="hlyn",
        description="Runtime containment for AI agents. Denies everything not granted.",
    )
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
        p.add_argument("--net", action="append", metavar="PORT", type=int, default=[],
                       help="reachable TCP port, repeatable (TCP only: UDP stays open)")
        p.add_argument("--net-any", action="store_true", help="allow all network access")
        p.add_argument("--env", action="append", metavar="NAME", default=[],
                       help="environment variable to keep (repeatable)")
        p.add_argument("--env-any", action="store_true", help="keep the whole environment, secrets included")
        p.add_argument("--no-tmp", action="store_true", help="do not provide a private scratch directory")
        p.add_argument("--log", metavar="PATH", help="write the record here instead of stderr")
        p.add_argument("--no-log", action="store_true", help="record nothing")
        p.add_argument("--attest", metavar="PATH", help="write a signed record of what was enforced")

    go = sub.add_parser("run", help="confine this shell's child, then run a command")
    grants(go)
    go.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run")

    sub.add_parser("probe", help="report what this machine can enforce")
    sub.add_parser("presets", help="list the built-in presets")

    look = sub.add_parser("watch", help="run a command unconfined and print the policy it would need")
    look.add_argument("--json", action="store_true", help="print as JSON rather than TOML")
    look.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run")

    hunt = sub.add_parser("audit", help="report the dangerous grants in a policy")
    grants(hunt)
    hunt.add_argument("-a", "--accepted", metavar="FILE",
                      help="risks already accepted, with a reason and an owner")
    hunt.add_argument("--json", action="store_true", help="machine-readable output")
    hunt.add_argument("--ocsf", action="store_true", help="output as OCSF Compliance Findings")
    hunt.add_argument("--severity", metavar="LEVEL", default="low",
                      help="fail only at this severity or worse (default: low)")

    seen = sub.add_parser("verify", help="check an attestation record against itself")
    seen.add_argument("file", help="the record written by --attest")
    seen.add_argument("--key", metavar="FILE", help=f"key file (default: ${attest.CHANNEL})")

    show = sub.add_parser("show", help="print the policy a set of flags produces")
    grants(show)
    show.add_argument("--intent", action="store_true",
                      help="print what was asked for, as a policy file, instead of what it resolves to")
    return top


def _policy(args: argparse.Namespace) -> Policy:
    """Turn flags into a policy, without applying anything.

    A file and a preset are both starting points, and flags edit whichever was
    given. They are mutually exclusive on purpose: silently layering a file on
    top of a preset would make the effective policy something neither document
    states.
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
        edits["read"] = list(base.read or ()) + args.read if isinstance(base.read, tuple) else args.read
    if args.write:
        edits["write"] = list(base.write or ()) + args.write if isinstance(base.write, tuple) else args.write
    if args.exec_any:
        edits["exec"] = True
    elif args.exec:
        edits["exec"] = args.exec
    if args.net_any:
        edits["net"] = True
    elif args.net:
        edits["net"] = args.net
    if args.env_any:
        edits["env"] = True
    elif args.env:
        edits["env"] = args.env
    if args.no_tmp:
        edits["tmp"] = False
    if args.no_log:
        edits["log"] = False
    elif args.log:
        edits["log"] = args.log
    if args.attest:
        edits["attest"] = args.attest
    return base.with_(**edits) if edits else base


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
    sys.stdout.write(spec.dumps(plan) if as_json else _toml(plan))
    return done.returncode


def _toml(plan: Policy) -> str:
    """Render a policy as TOML, without taking on a dependency to write it.

    Only the shapes a policy actually holds -- lists of strings, lists of
    integers, and booleans -- so this is a rendering, not a TOML writer, and it
    is not exported as one.
    """
    out = []
    for field, value in spec.shape(plan).items():
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


MARK = {"critical": "!!", "high": " !", "medium": " ~", "low": " -", "note": " ."}


def _audit(args: argparse.Namespace) -> int:
    """Report the dangerous grants in a policy, and fail the build on them.

    Exits non-zero when something is outstanding, so this is a CI gate rather
    than a report someone means to read. What counts as outstanding is the
    point: a finding with a recorded, unexpired acceptance is not.
    """
    from . import accept, audit, ocsf

    plan = _policy(args)
    # The document as written, when there is one. Some findings are about the
    # gap between what a file says and what it resolves to, which cannot be
    # seen from the resolved policy.
    asked = spec.raw(args.policy) if args.policy else None
    found = audit.check(plan, asked)

    taken = accept.load(args.accepted) if args.accepted else ()
    verdict = accept.apply(found, taken)

    if args.ocsf:
        excused = {item.id: seat.reason for item, seat in verdict.waived}
        print(json.dumps(ocsf.findings(found, excused), indent=2))
        return 0 if verdict.clean else 1

    if args.json:
        print(json.dumps({
            "findings": [item.shape() for item in found],
            "live": [item.id for item in verdict.live],
            "waived": [{"finding": i.id, **s.shape()} for i, s in verdict.waived],
            "expired": [{"finding": i.id, **s.shape()} for i, s in verdict.expired],
            "stale": [s.shape() for s in verdict.stale],
            "clean": verdict.clean,
        }, indent=2))
        return 0 if verdict.clean else 1

    for item in verdict.live:
        print(f"{MARK.get(item.severity, '  ')} {item.severity:<8} {item.says}")
        print(f"                {item.why}")
        print(f"      fix:      {item.fix}")
        print(f"      waive as: {item.id}\n")

    for item, seat in verdict.expired:
        print(f"{MARK.get(item.severity, '  ')} EXPIRED  {item.says}")
        print(f"                accepted by {seat.by} until {seat.until}, which has passed\n")

    for item, seat in verdict.waived:
        print(f" ok  accepted  {item.says}")
        print(f"                {seat.reason} -- {seat.by}, until {seat.until}\n")

    for seat in verdict.stale:
        print(f" ??  stale     {seat.finding} is accepted but no longer occurs")
        print("                the policy changed; remove the entry\n")

    if not found:
        print("no findings.")
    counted = f"{len(verdict.live)} outstanding, {len(verdict.waived)} accepted"
    if verdict.expired:
        counted += f", {len(verdict.expired)} expired"
    print(counted)
    return 0 if verdict.clean else 1


def _verify(args: argparse.Namespace) -> int:
    """Check an attestation record against itself, and its key if it has one."""
    try:
        with open(args.file, encoding="utf-8") as fh:
            body = json.load(fh)
    except OSError as exc:
        print(f"hlyn: {args.file}: {exc.strerror}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"hlyn: {args.file}: not a record ({exc})", file=sys.stderr)
        return 2

    held, said = attest.verify(body, args.key)
    print(f"{'ok ' if held else 'NO '} {said}")
    if held:
        print(f"    policy enforced {body.get('enforced')} by {body.get('backend')} "
              f"on {body.get('host')} at {body.get('at')}")
    return 0 if held else 1


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
        print(json.dumps(out, indent=2))
        # Non-zero when the machine cannot enforce, so this is usable as a
        # preflight check in a pipeline rather than something to eyeball.
        return 0 if out.get("enforce") else 1

    if args.verb == "presets":
        for name in sorted(presets):
            print(name)
        return 0

    if args.verb == "audit":
        return _audit(args)

    if args.verb == "verify":
        return _verify(args)

    if args.verb == "show":
        p = _policy(args)
        if args.intent:
            # What was asked for, not what it becomes: this is the form a file
            # holds, so `hlyn show --intent > policy.json` is how a set of
            # flags that works becomes a document someone can review.
            sys.stdout.write(spec.dumps(p))
            return 0
        # Resolved once each: `reads` walks the interpreter's own installation
        # to work out what the runtime needs, which is not something to do
        # twice per field just to render it.
        reads, writes, runs = p.reads(), p.writes(), p.runs()
        print(
            json.dumps(
                {
                    "read": reads if isinstance(reads, bool) else list(reads),
                    "write": writes if isinstance(writes, bool) else list(writes),
                    "exec": runs if isinstance(runs, bool) else list(runs),
                    "net": p.net if isinstance(p.net, bool) else list(p.net),
                    "env": "all" if p.env is True else sorted(p.keep().keys()),
                    "tmp": p.tmp,
                },
                indent=2,
            )
        )
        return 0

    cmd = [item for item in args.cmd if item != "--"]

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

    try:
        jail.spawn(cmd, _policy(args))
    except Error as exc:
        print(f"hlyn: {exc}", file=sys.stderr)
        return 1
    return 0  # unreachable: spawn replaces this process


if __name__ == "__main__":
    raise SystemExit(main())
