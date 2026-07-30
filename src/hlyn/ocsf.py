"""Records in the Open Cybersecurity Schema Framework, rather than our own shape.

A SIEM that already understands OCSF needs no parser written for us, no field
mapping maintained by hand, and no reason to treat this tool's output as a
special case. That is the whole argument for it: a bespoke JSON log is a
integration project for whoever receives it, and the receiving team is never
the team that chose the tool.

    hlyn audit -f policy.toml --ocsf         findings, as Compliance Findings
    hlyn run --log-format ocsf ...           the run's records, as OCSF events

Two things worth being straight about.

**The mappings are a reading of the schema, not a certification.** OCSF is
large, and hlyn's events are narrow: a boundary applied, and a refusal. Where a
class fits cleanly it is used; where the fit is a judgement call, the call is
written down beside it in the code below rather than left for someone to infer
from field names. Anything with no honest home goes in `unmapped`, which is
what OCSF provides it for -- inventing a field would be worse.

**Severity is ours.** OCSF's scale is fixed; the mapping from our severities
onto it is a decision, and it is one table in one place so it can be argued
with.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from .audit import Finding

__all__ = ["event", "finding", "findings"]

SCHEMA = "1.7.0"

# OCSF severity_id. Ours is a five-point scale, OCSF's runs Informational(1),
# Low(2), Medium(3), High(4), Critical(5).
SEVERITY: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "note": 1,
}

# Class 2003, Compliance Finding, in the Findings category (2). This is the
# clean fit: a policy checked against a rule set, producing findings that are
# tracked, waived with a recorded reason, and re-checked -- which is what the
# class is for. `type_uid` is class_uid * 100 + activity_id, per the schema.
COMPLIANCE = 2003
FINDINGS = 2

# Class 1001, File System Activity, in the System Activity category (1). Used
# for a refused path, where the interesting fields are the file and the fact
# that the attempt failed.
FILESYSTEM = 1001
SYSTEM = 1

CREATE, UPDATE = 1, 3  # activity_id: a finding is created, or updated
SUCCESS, FAILURE = 1, 2  # status_id


def _product() -> dict[str, Any]:
    from . import __version__

    return {"name": "hlyn", "vendor_name": "hlyn", "version": __version__}


def _metadata() -> dict[str, Any]:
    return {"version": SCHEMA, "product": _product()}


def _now() -> int:
    """OCSF timestamps are milliseconds since the epoch."""
    return int(time.time() * 1000)


def finding(item: Finding, waived: str | None = None) -> dict[str, Any]:
    """One audit finding as an OCSF Compliance Finding.

    `waived` carries the reason a risk was accepted, when it was. An accepted
    finding is still reported -- suppressing it would hide the decision along
    with the risk -- and is marked `Suppressed` so a dashboard can count it
    separately rather than treating it as outstanding.
    """
    body: dict[str, Any] = {
        "activity_id": CREATE,
        "category_uid": FINDINGS,
        "class_uid": COMPLIANCE,
        "type_uid": COMPLIANCE * 100 + CREATE,
        "severity_id": SEVERITY.get(item.severity, 1),
        "severity": item.severity.capitalize(),
        "time": _now(),
        "message": item.says,
        "metadata": _metadata(),
        "finding_info": {
            "uid": item.id,
            "title": item.says,
            "desc": item.why,
            # OCSF wants the rule as its own object so findings from different
            # tools can be grouped by what was checked rather than by wording.
            "types": [item.rule],
        },
        "remediation": {"desc": item.fix},
        "resources": [{"name": item.subject, "type": "policy-grant"}],
        "status_id": 99 if waived else 1,
        "status": "Suppressed" if waived else "New",
        "unmapped": {"rule": item.rule, "subject": item.subject},
    }
    if waived:
        body["comment"] = waived
    return body


def findings(found: Iterable[Finding], waived: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """A whole report, one OCSF object per finding."""
    waived = waived or {}
    return [finding(item, waived.get(item.id)) for item in found]


def event(row: dict[str, Any]) -> dict[str, Any]:
    """One of our log records as the nearest honest OCSF event.

    A `seal` becomes a Compliance Finding with a passing status: the policy was
    checked against the kernel's ability to apply it, and the kernel applied all
    of it. That is a control that was evaluated and held, which is what the
    class describes -- and it is a better fit than any System Activity class,
    none of which have a notion of "a boundary now exists".

    A `deny` becomes File System Activity that failed. A `deny` that names no
    path is a tool refusal rather than a file one, and stays a finding.
    """
    kind = row.get("kind")
    if kind == "seal":
        return _seal(row)
    if kind == "deny" and row.get("path"):
        return _refused(row)
    return _other(row)


def _seal(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity_id": CREATE,
        "category_uid": FINDINGS,
        "class_uid": COMPLIANCE,
        "type_uid": COMPLIANCE * 100 + CREATE,
        "severity_id": 1,
        "severity": "Informational",
        "time": int(float(row.get("t", time.time())) * 1000),
        "message": f"confinement applied by {row.get('backend')} at level {row.get('level')}",
        "metadata": _metadata(),
        "status_id": SUCCESS,
        "status": "Success",
        "finding_info": {
            "uid": f"seal:{row.get('pid')}",
            "title": "runtime confinement applied in full",
            # Worth stating in the record itself: hlyn raises rather than seal
            # partially, so this is not a best-effort claim.
            "desc": "the kernel accepted every rule in the policy; hlyn refuses to "
            "seal when it would apply less",
        },
        "unmapped": {
            name: row.get(name) for name in ("read", "write", "exec", "net", "env", "tmp")
        },
    }


def _refused(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity_id": UPDATE,
        "category_uid": SYSTEM,
        "class_uid": FILESYSTEM,
        "type_uid": FILESYSTEM * 100 + UPDATE,
        "severity_id": 3,
        "severity": "Medium",
        "time": int(float(row.get("t", time.time())) * 1000),
        "message": str(row.get("why", "refused by policy")),
        "metadata": _metadata(),
        "status_id": FAILURE,
        "status": "Failure",
        "file": {"name": str(row.get("path", "")), "type_id": 1},
        "actor": {"process": {"pid": row.get("pid")}},
        "unmapped": {"seen": row.get("seen")} if row.get("seen") else {},
    }


def _other(row: dict[str, Any]) -> dict[str, Any]:
    """Anything else, kept rather than dropped.

    A record with no good class is still a record. Dropping it would make the
    OCSF stream quietly incomplete, which is worse than one object carrying its
    original fields in `unmapped` where they can be read.
    """
    denied = row.get("kind") == "deny"
    return {
        "activity_id": UPDATE,
        "category_uid": FINDINGS,
        "class_uid": COMPLIANCE,
        "type_uid": COMPLIANCE * 100 + UPDATE,
        "severity_id": 3 if denied else 1,
        "severity": "Medium" if denied else "Informational",
        "time": int(float(row.get("t", time.time())) * 1000),
        "message": str(row.get("why") or row.get("what") or row.get("kind", "")),
        "metadata": _metadata(),
        "status_id": FAILURE if denied else SUCCESS,
        "status": "Failure" if denied else "Success",
        "unmapped": dict(row),
    }
