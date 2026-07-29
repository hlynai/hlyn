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
import sys
from typing import Sequence

from . import jail
from .error import Error
from .policy import Policy, presets

__all__ = ["main", "build"]


def build() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="hlyn",
        description="Runtime containment for AI agents. Denies everything not granted.",
    )
    sub = top.add_subparsers(dest="verb", required=True)

    def grants(p: argparse.ArgumentParser) -> None:
        p.add_argument("-p", "--preset", metavar="NAME", help=f"one of: {', '.join(sorted(presets))}")
        p.add_argument("--read", action="append", metavar="PATH", default=[], help="readable path (repeatable)")
        p.add_argument("--write", action="append", metavar="PATH", default=[], help="writable path (repeatable)")
        p.add_argument("--exec", action="append", metavar="PATH", default=[], help="runnable program (repeatable)")
        p.add_argument("--exec-any", action="store_true", help="allow running any program")
        p.add_argument("--net", action="append", metavar="PORT", type=int, default=[], help="reachable TCP port (repeatable)")
        p.add_argument("--net-any", action="store_true", help="allow all network access")
        p.add_argument("--env", action="append", metavar="NAME", default=[], help="environment variable to keep (repeatable)")
        p.add_argument("--env-any", action="store_true", help="keep the whole environment, secrets included")
        p.add_argument("--no-tmp", action="store_true", help="do not provide a private scratch directory")
        p.add_argument("--log", metavar="PATH", help="write the record here instead of stderr")
        p.add_argument("--no-log", action="store_true", help="record nothing")

    go = sub.add_parser("run", help="confine this shell's child, then run a command")
    grants(go)
    go.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command to run")

    sub.add_parser("probe", help="report what this machine can enforce")
    sub.add_parser("presets", help="list the built-in presets")

    show = sub.add_parser("show", help="print the policy a set of flags produces")
    grants(show)
    return top


def _policy(args: argparse.Namespace) -> Policy:
    """Turn flags into a policy, without applying anything."""
    base = jail._plan(args.preset, {}) if args.preset else Policy()
    edits: dict = {}
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
    return base.with_(**edits) if edits else base


def main(argv: Sequence[str] | None = None) -> int:
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

    if args.verb == "show":
        p = _policy(args)
        print(
            json.dumps(
                {
                    "read": p.reads() if p.reads() is True else list(p.reads()),
                    "write": p.writes() if p.writes() is True else list(p.writes()),
                    "exec": p.runs() if isinstance(p.runs(), bool) else list(p.runs()),
                    "net": p.net if isinstance(p.net, bool) else list(p.net),
                    "env": "all" if p.env is True else sorted(p.keep().keys()),
                    "tmp": p.tmp,
                },
                indent=2,
            )
        )
        return 0

    cmd = [item for item in args.cmd if item != "--"]
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
