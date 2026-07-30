"""Risks somebody decided to take, with their name against them.

A finding that cannot be waived gets the whole check turned off, so the ability
to accept one is not a weakness in the control -- it is what keeps the control
switched on. What matters is that accepting is *recorded*: which finding, why,
who decided, and until when.

    [[accepted]]
    finding = "credential-reach:/root/.aws"
    reason  = "deploy bot; it pushes images and needs the credentials"
    by      = "karan@hlyn.dev"
    until   = "2026-12-31"

That is a risk register. It is the artifact SOC 2 CC3/CC7 and ISO 27001 A.5.
ask for, and it is far easier to produce as a side effect of a check that runs
in CI than as a spreadsheet somebody remembers to update.

Three rules, each of which exists because the alternative rots quietly:

**An acceptance expires.** `until` is required. A waiver with no end date is
how a temporary exception becomes permanent without anyone deciding it should,
and an expired one stops waiving and becomes a finding of its own.

**An acceptance that matches nothing is reported.** The policy it was written
for has changed; the waiver is now a note about a risk that no longer exists,
and leaving it in place means the next real occurrence is waived silently.

**Every field is required and unknown fields are refused.** A register with an
empty `reason` is not a record of a decision, it is a record that someone
wanted the build to pass.
"""

from __future__ import annotations

import datetime as dt
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from .audit import Finding
from .error import Invalid

__all__ = ["Accepted", "Verdict", "apply", "load", "loads"]

NEEDED: tuple[str, ...] = ("finding", "reason", "by", "until")
ALLOWED: tuple[str, ...] = (*NEEDED, "note")


@dataclass(frozen=True, slots=True)
class Accepted:
    """One risk, consciously taken."""

    finding: str
    reason: str
    by: str
    until: dt.date
    note: str = ""

    def expired(self, today: dt.date | None = None) -> bool:
        return self.until < (today or dt.date.today())

    def shape(self) -> dict[str, str]:
        out = {
            "finding": self.finding,
            "reason": self.reason,
            "by": self.by,
            "until": self.until.isoformat(),
        }
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True, slots=True)
class Verdict:
    """What the register did to a set of findings.

    `live` is what is still outstanding and what a build should fail on.
    `waived` is what was accepted, kept rather than discarded because a report
    that omits accepted risk is not a report of the risk. `stale` and `expired`
    are problems with the register itself.
    """

    live: tuple[Finding, ...]
    waived: tuple[tuple[Finding, Accepted], ...]
    expired: tuple[tuple[Finding, Accepted], ...]
    stale: tuple[Accepted, ...]

    @property
    def clean(self) -> bool:
        """Whether anything is outstanding, counting the register's own problems.

        An expired waiver counts as outstanding: the decision it recorded has
        run out, and the risk is back.
        """
        return not (self.live or self.expired)


def _date(value: object, where: str) -> dt.date:
    """Read a date, however the parser handed it over.

    TOML has a real date type and gives a `date`; JSON and YAML give a string.
    Both arrive here, and a register must not mean different things in
    different formats.
    """
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value.strip())
        except ValueError:
            raise Invalid(
                f"{where}: `until` should be a date like 2026-12-31, got {value!r}."
            ) from None
    raise Invalid(f"{where}: `until` should be a date like 2026-12-31, got {value!r}.")


def _one(item: object, where: str) -> Accepted:
    """Turn one entry into an `Accepted`, or say exactly what is missing."""
    if not isinstance(item, Mapping):
        raise Invalid(f"{where}: each accepted risk should be a table, got {type(item).__name__}.")

    strange = [key for key in item if key not in ALLOWED]
    if strange:
        raise Invalid(
            f"{where}: unknown field(s) {', '.join(sorted(strange))}. "
            f"Known fields: {', '.join(ALLOWED)}."
        )
    missing = [key for key in NEEDED if not str(item.get(key, "")).strip()]
    if missing:
        raise Invalid(
            f"{where}: every accepted risk needs {', '.join(NEEDED)}; "
            f"missing or empty: {', '.join(missing)}. An acceptance without a reason "
            f"and an owner is not a decision anyone can be asked about later."
        )

    return Accepted(
        finding=str(item["finding"]).strip(),
        reason=str(item["reason"]).strip(),
        by=str(item["by"]).strip(),
        until=_date(item["until"], where),
        note=str(item.get("note", "")).strip(),
    )


def build(data: Mapping[str, object]) -> tuple[Accepted, ...]:
    """Turn a parsed register document into entries."""
    if not isinstance(data, Mapping):
        raise Invalid("a register should be a document with an `accepted` list in it.")
    strange = [key for key in data if key != "accepted"]
    if strange:
        raise Invalid(
            f"unknown top-level field(s): {', '.join(sorted(strange))}. "
            f"A register holds one thing: a list of `accepted` entries."
        )
    entries = data.get("accepted")
    if entries is None:
        raise Invalid("this register has no `accepted` entries.")
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise Invalid("`accepted` should be a list of entries.")
    return tuple(_one(item, f"accepted[{n}]") for n, item in enumerate(entries))


def loads(text: str, kind: str = "toml") -> tuple[Accepted, ...]:
    """Parse a register held in a string."""
    from .spec import KINDS

    parse = KINDS.get(kind.lower().lstrip("."))
    if parse is None:
        raise Invalid(f"unknown register format {kind!r}. Known formats: toml, json, yaml.")
    got = parse(text)
    if got is None or (isinstance(got, Mapping) and not got):
        raise Invalid("this register is empty.")
    return build(got)


def load(path: str | os.PathLike[str]) -> tuple[Accepted, ...]:
    """Read a register from a file, choosing the format by extension."""
    where = os.path.abspath(os.fspath(path))
    kind = os.path.splitext(where)[1].lstrip(".").lower() or "toml"
    try:
        with open(where, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise Invalid(f"{where}: {exc.strerror or 'could not be read'}.") from None
    return loads(text, kind)


def apply(
    found: Iterable[Finding],
    accepted: Iterable[Accepted] = (),
    today: dt.date | None = None,
) -> Verdict:
    """Match findings against the register and report what is left.

    Nothing is discarded. An accepted risk is still a risk, and a report that
    hides it is a report that cannot be used to review the decision later.
    """
    found = list(found)
    accepted = list(accepted)
    today = today or dt.date.today()

    by_id: dict[str, Accepted] = {item.finding: item for item in accepted}
    used: set[str] = set()

    live: list[Finding] = []
    waived: list[tuple[Finding, Accepted]] = []
    expired: list[tuple[Finding, Accepted]] = []

    for item in found:
        match = by_id.get(item.id) or by_id.get(item.rule)
        if match is None:
            live.append(item)
            continue
        used.add(match.finding)
        if match.expired(today):
            expired.append((item, match))
        else:
            waived.append((item, match))

    stale = tuple(item for item in accepted if item.finding not in used)
    return Verdict(tuple(live), tuple(waived), tuple(expired), stale)
