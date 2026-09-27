# SPDX-License-Identifier: Apache-2.0
"""Confirm that the suite actually catches a specific set of mistakes.

mutmut generates mutation candidates well, but its report cannot be taken at
face value here: it listed changes as surviving that the suite demonstrably
catches -- breaking `ports(443)` was reported as a survivor while
`test_net_accepts_bools_and_ports` fails on it immediately. Its output is a
list of leads, not a verdict.

This confirms the leads. Each case below is a change that would widen or break
a boundary, applied to the real source, checked against the real suite. Every
one of them survived at some point; each has a test now.

    python tools/confirm.py

Only the pure-logic tests are used. Everything below the policy layer is
judged by whether a real kernel refuses a real syscall, which is not something
a source-level mutation measures.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "hlyn" / "policy.py"
TESTS = ["tests/test_policy.py", "tests/test_policy_properties.py"]

# (what the mistake would be, function, text to replace, replacement)
CASES = [
    (
        "net=None grants the whole network instead of none",
        "ports",
        "    if value is None:\n        return False",
        "    if value is None:\n        return True",
    ),
    (
        "env=None passes the entire environment through, secrets included",
        "names",
        "    if value is None:\n        return False",
        "    if value is None:\n        return True",
    ),
    (
        "read=None grants the whole filesystem instead of none",
        "paths",
        "    if value is None:\n        return False",
        "    if value is None:\n        return True",
    ),
    (
        "a bare port number stops working",
        "ports",
        "    if isinstance(value, int):\n        value = (value,)",
        "    if isinstance(value, int):\n        value = None",
    ),
    (
        "a bare environment variable name stops working",
        "names",
        "    if isinstance(value, str):\n        value = (value,)",
        "    if isinstance(value, str):\n        value = None",
    ),
    (
        "an empty environment variable name is accepted",
        "names",
        "if not isinstance(item, str) or not item:",
        "if not isinstance(item, str) and not item:",
    ),
    (
        "a non-path inside a list escapes the check",
        "_one",
        "if isinstance(item, bool) or not isinstance(item, (str, os.PathLike)):",
        "if isinstance(item, bool) and not isinstance(item, (str, os.PathLike)):",
    ),
    (
        "a fractional port is rounded to a port nobody named",
        "ports",
        "            if port != item:",
        "            if False:",
    ),
    (
        "port 0 becomes a legal port",
        "ports",
        "        if not 0 < port < 65536:",
        "        if not 0 <= port < 65536:",
    ),
]


def body(text: str, name: str) -> tuple[int, int]:
    """Where `name`'s definition starts and ends, so edits stay inside it."""
    start = re.search(rf"^def {re.escape(name)}\(", text, re.MULTILINE)
    if not start:
        raise SystemExit(f"{SRC}: no function named {name}")
    after = re.search(r"^(def |class |# ---)", text[start.end() :], re.MULTILINE)
    end = start.end() + (after.start() if after else len(text) - start.end())
    return start.start(), end


def suite_passes() -> bool:
    done = subprocess.run(
        [sys.executable, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode == 0


def main() -> int:
    original = SRC.read_text()
    missed = []
    try:
        if not suite_passes():
            print("the suite is red before any change was made", file=sys.stderr)
            return 2
        for label, fn, find, repl in CASES:
            start, end = body(original, fn)
            scope = original[start:end]
            if find not in scope:
                print(f"stale  {label}\n       (pattern no longer in {fn}; update this case)")
                missed.append(label)
                continue
            SRC.write_text(original[:start] + scope.replace(find, repl, 1) + original[end:])
            if suite_passes():
                print(f"MISSED {label}")
                missed.append(label)
            else:
                print(f"caught {label}")
    finally:
        SRC.write_text(original)

    print(f"\n{len(CASES) - len(missed)}/{len(CASES)} caught")
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
