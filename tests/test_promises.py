# SPDX-License-Identifier: Apache-2.0
"""Every promise in SECURITY.md has a test that tries to break it, and a test of
its allowed twin, or says why not (`promises.py`).

This fails when a promise is added to SECURITY.md with no entry, when an entry
no longer matches a promise, when a named test has been renamed or deleted,
and when an entry has neither a check nor a stated gap.
"""

from __future__ import annotations

import ast
import os
import re

from promises import EXEMPT, PROMISES

HERE = os.path.dirname(os.path.abspath(__file__))
SECURITY = os.path.join(os.path.dirname(HERE), "SECURITY.md")


def bullets() -> list[str]:
    """The promises in SECURITY.md: the bullets under 'What counts as a
    vulnerability' and under '**It stops**', each as one line of text."""
    out: list[str] = []
    mode = ""
    current: list[str] | None = None

    def done() -> None:
        nonlocal current
        if current is not None:
            out.append(re.sub(r"\s+", " ", " ".join(current)).strip())
            current = None

    with open(SECURITY, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if line.startswith("## "):
                done()
                mode = "vuln" if line.startswith("## What counts as a vulnerability") else ""
            if line.startswith("**It stops**"):
                done()
                mode = "stops"
            elif line.startswith("**It does not stop"):
                done()
                mode = ""
            if not mode:
                continue
            if line.startswith("- "):
                done()
                current = [line[2:]]
            elif current is not None and line.startswith("  ") and line.strip():
                current.append(line.strip())
            elif current is not None:
                done()
    done()
    return out


def functions(file: str) -> set[str]:
    path = os.path.join(HERE, file)
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_the_promises_were_read():
    found = bullets()
    print(f"{len(found)} promises in SECURITY.md")
    assert len(found) >= 15, found  # a changed heading must not make this pass with none


def test_every_promise_has_an_entry_and_every_entry_has_a_promise():
    found = bullets()
    says = [str(entry["says"]) for entry in PROMISES]
    unmapped = [b for b in found if not any(b.startswith(s) for s in [*says, *EXEMPT])]
    stale = [s for s in says if not any(b.startswith(s) for b in found)]
    twice = [b for b in found if sum(b.startswith(s) for s in says) > 1]
    assert not unmapped, "promises with no entry in tests/promises.py:\n  " + "\n  ".join(unmapped)
    assert not stale, "entries that match no promise in SECURITY.md:\n  " + "\n  ".join(stale)
    assert not twice, "promises matched by more than one entry:\n  " + "\n  ".join(twice)


def test_every_named_test_exists():
    missing = []
    for entry in PROMISES:
        for ref in [*entry.get("tests", []), *entry.get("control", [])]:  # type: ignore[misc]
            file, _, name = str(ref).partition("::")
            if not os.path.isfile(os.path.join(HERE, file)) or name not in functions(file):
                missing.append(f"{ref} (for: {entry['says']})")
    assert not missing, "tests that do not exist:\n  " + "\n  ".join(missing)


def test_every_promise_has_a_check_and_an_allowed_twin_or_says_why_not():
    problems = []
    for entry in PROMISES:
        name = str(entry["says"])
        if not entry.get("tests"):
            problems.append(f"{name}: no test tries to break it")
        if not entry.get("control") and len(str(entry.get("no_control", ""))) < 30:
            problems.append(f"{name}: no allowed-twin test, and no reason of at least 30 characters")
        if entry.get("gap") is not None and len(str(entry["gap"])) < 20:
            problems.append(f"{name}: a gap must say what is not covered")
    assert not problems, "\n  ".join(problems)


def test_the_table():
    """Print what is covered and what is known not to be, for the person reading the log."""
    rows = []
    for entry in PROMISES:
        rows.append((len(entry["tests"]), len(entry.get("control", [])),  # type: ignore[arg-type]
                     "GAP" if entry.get("gap") else "", str(entry["says"])[:70]))
    print(f"{'tests':>5} {'twin':>4}  promise")
    for tests, twins, mark, says in rows:
        print(f"{tests:>5} {twins:>4}  {says} {mark}")
    gaps = [str(e["gap"]) for e in PROMISES if e.get("gap")]
    print(f"\n{len(gaps)} promises with a stated gap:")
    for gap in gaps:
        print(f"  - {gap}")
    assert rows
