"""A record that a boundary was applied, and what it was.

hlyn refuses to seal when the kernel would apply less than the whole policy.
That refusal is what makes a record worth keeping: a seal that happened is a
seal that happened *in full*, so "policy X, entirely enforced, on host H, at
time T" is a claim about the kernel rather than about our intentions. Most
tools in this space can only say they asked.

    hlyn run --attest run.json -f policy.toml -- python agent.py
    hlyn verify run.json

**What this is worth, stated exactly, because attestation is a word that gets
oversold.**

The record is tamper-*evident*, not tamper-*proof*. It carries a digest over
its own contents, so a record altered after the fact no longer matches itself.
With a key it also carries an HMAC, which means a collector can tell a record
it issued keys for from one it did not.

It is **not** proof against the confined process itself. A process holding the
signing key can sign whatever it likes, and no amount of cryptography inside a
machine fixes a question about that machine. Real non-repudiation needs a
signer the agent cannot reach -- a control plane that issues per-run keys, or
a TPM. That is a deliberate hole here, not an oversight: this package has no
network component and does not pretend to be its own trust root.

What it does buy, today, and it is not nothing: an artifact per run, produced
automatically, that a collector can verify was not edited in storage, and that
says which policy was enforced rather than which policy was requested.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import socket
import time
from typing import Any

from .policy import Policy

__all__ = ["digest", "make", "sign", "verify"]

# The environment variable naming a file that holds the signing key. A path
# rather than the key itself: an environment variable holding a secret is
# exactly what the `env` control exists to scrub, and it would be scrubbed.
CHANNEL = "HLYN_ATTEST_KEY"

VERSION = 1  # of this record format, so a collector can tell shapes apart


def canon(body: Any) -> bytes:
    """The one byte-for-byte rendering of a record, for hashing.

    Sorted keys, no incidental whitespace, no non-ASCII escapes left to a
    parser's discretion. Two processes that agree on the content have to agree
    on the bytes, or a digest means nothing.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(body: Any) -> str:
    """A SHA-256 over the canonical form."""
    return "sha256:" + hashlib.sha256(canon(body)).hexdigest()


def _grants(plan: Policy) -> dict[str, Any]:
    """What the kernel was actually given, not what the policy said.

    The resolved view is the honest one: a policy naming `/srv` resolves to
    `/srv` plus the interpreter's own files, and an attestation that omitted
    the latter would describe a boundary narrower than the one applied.
    """
    out: dict[str, Any] = {}
    for name, value in (
        ("read", plan.reads()),
        ("write", plan.writes()),
        ("exec", plan.runs()),
    ):
        out[name] = value if isinstance(value, bool) else sorted(value)
    out["net"] = plan.net if isinstance(plan.net, bool) else sorted(plan.net)
    out["env"] = plan.env if isinstance(plan.env, bool) else sorted(plan.env)
    return out


def make(plan: Policy, backend: str, level: object, tmp: str | None = None) -> dict[str, Any]:
    """Build the record for a seal that has just succeeded.

    Called after the kernel has accepted the policy, never before. A record
    written in advance would be a statement of intent wearing the clothes of
    evidence.
    """
    from . import __version__

    body: dict[str, Any] = {
        "version": VERSION,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": socket.gethostname(),
        "pid": os.getpid(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "hlyn": __version__,
        "backend": backend.rsplit(".", 1)[-1],
        "level": level,
        # The whole point. hlyn raises rather than seal partially, so a record
        # existing at all means the kernel took every rule it was given.
        "enforced": "whole",
        "policy": _shape(plan),
        "grants": _grants(plan),
        "tmp": tmp,
    }
    body["digest"] = digest(body)
    return body


def _shape(plan: Policy) -> dict[str, Any]:
    """The policy as written, so a record can be matched to its document."""
    from .spec import shape

    return shape(plan)


def key(source: str | bytes | None = None) -> bytes | None:
    """The signing key, from an argument or the file named in the environment.

    None means unsigned, which is a supported outcome and not an error: a
    digest alone is still tamper-evident, and requiring a key to get any record
    at all would mean most runs produce none.
    """
    # An empty key is no key. Signing with one produces a MAC that verifies
    # against any other empty key, which is worse than being unsigned: it
    # carries the appearance of origin without the substance.
    if isinstance(source, bytes):
        return source or None
    where = source or os.environ.get(CHANNEL)
    if not where:
        return None
    try:
        with open(where, "rb") as fh:
            raw = fh.read().strip()
    except OSError:
        return None
    return raw or None


def sign(body: dict[str, Any], source: str | bytes | None = None) -> dict[str, Any]:
    """Add an HMAC over the record, if a key is available."""
    secret = key(source)
    if secret is None:
        body["signed"] = False
        return body
    naked = {name: value for name, value in body.items() if name not in ("mac", "signed")}
    body["signed"] = True
    body["mac"] = "hmac-sha256:" + hmac.new(secret, canon(naked), hashlib.sha256).hexdigest()
    return body


def verify(body: dict[str, Any], source: str | bytes | None = None) -> tuple[bool, str]:
    """Check a record against itself, and against a key if it claims one.

    Returns whether it holds and a sentence saying why, because "false" on its
    own sends someone to read this file.
    """
    if not isinstance(body, dict):
        return False, "this is not an attestation record"

    said = body.get("digest")
    naked = {name: value for name, value in body.items() if name not in ("digest", "mac", "signed")}
    if not said:
        return False, "this record carries no digest, so nothing can be checked"
    if said != digest(naked):
        return False, "the digest does not match the contents: this record was altered"

    if not body.get("signed"):
        return True, "contents match the digest; unsigned, so origin is not established"

    secret = key(source)
    if secret is None:
        return False, (
            f"this record is signed, but no key was given to check it against "
            f"(set {CHANNEL} to the key file)"
        )
    want = {name: value for name, value in body.items() if name not in ("mac", "signed")}
    got = body.get("mac", "")
    calc = "hmac-sha256:" + hmac.new(secret, canon(want), hashlib.sha256).hexdigest()
    # compare_digest, not ==: a timing-variable comparison on a MAC is the
    # textbook mistake, and cheap to avoid.
    if not hmac.compare_digest(str(got), calc):
        return False, "the signature does not match: wrong key, or an altered record"
    return True, "contents match the digest and the signature checks out"
