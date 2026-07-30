"""Records of what was enforced, and what they are worth.

The claim an attestation makes is narrow and has to stay narrow: the contents
have not been altered since they were written, and -- because hlyn raises
rather than seal partially -- a record existing at all means the kernel took
the whole policy. Everything asserted here is one of those two, or a way the
record could lie and does not.
"""

from __future__ import annotations

import json

from hlyn import attest
from hlyn.policy import Policy

KEY = b"a" * 32
OTHER = b"b" * 32


def record(**edits) -> dict:
    return attest.make(Policy(read=["/srv"], **edits), "hlyn.core.linux", 6, "/tmp/x")


# -- what is in it ----------------------------------------------------------


def test_a_record_states_the_policy_and_what_it_resolved_to():
    """Both, because they differ: a policy naming /srv also grants the runtime."""
    body = record()
    assert body["policy"]["read"] == ["/srv"]
    assert "/srv" in body["grants"]["read"]
    assert len(body["grants"]["read"]) > 1


def test_a_record_says_the_whole_policy_was_applied():
    """The one claim worth making, and it rests on hlyn refusing partial seals."""
    assert record()["enforced"] == "whole"


def test_a_record_names_the_backend_and_the_level():
    body = record()
    assert body["backend"] == "linux"
    assert body["level"] == 6


# -- tamper evidence --------------------------------------------------------


def test_an_untouched_record_verifies():
    held, said = attest.verify(record())
    assert held
    assert "unsigned" in said


def test_an_altered_record_does_not_verify():
    body = record()
    body["enforced"] = "part"
    held, said = attest.verify(body)
    assert not held
    assert "altered" in said


def test_altering_a_grant_is_caught_too():
    body = record()
    body["grants"]["read"].append("/etc/shadow")
    assert not attest.verify(body)[0]


def test_a_record_with_no_digest_proves_nothing():
    body = record()
    del body["digest"]
    held, said = attest.verify(body)
    assert not held
    assert "no digest" in said


# -- signing ----------------------------------------------------------------


def test_a_signed_record_verifies_with_its_key():
    body = attest.sign(record(), KEY)
    held, said = attest.verify(body, KEY)
    assert held
    assert "signature" in said


def test_a_signed_record_fails_with_the_wrong_key():
    body = attest.sign(record(), KEY)
    held, said = attest.verify(body, OTHER)
    assert not held
    assert "wrong key" in said


def test_a_signed_record_cannot_be_checked_without_a_key():
    """Better to refuse than to report success on a signature nobody checked."""
    body = attest.sign(record(), KEY)
    held, _ = attest.verify(body, b"")
    assert not held


def test_signing_survives_a_round_trip_through_json():
    """A record is written to a file and read back; the digest must survive that."""
    body = attest.sign(record(), KEY)
    assert attest.verify(json.loads(json.dumps(body)), KEY)[0]


def test_an_unsigned_record_says_so_rather_than_claiming_origin():
    body = attest.sign(record(), b"")
    assert body["signed"] is False
    assert "mac" not in body


def test_a_forged_signature_flag_does_not_pass():
    """Flipping `signed` to true without a MAC must not read as verified."""
    body = record()
    body["signed"] = True
    held, _ = attest.verify(body, KEY)
    assert not held


# -- canonical form ---------------------------------------------------------


def test_key_order_does_not_change_the_digest():
    """Two processes agreeing on content have to agree on the bytes."""
    first = {"a": 1, "b": [2, 3]}
    second = {"b": [2, 3], "a": 1}
    assert attest.digest(first) == attest.digest(second)


def test_different_content_changes_the_digest():
    assert attest.digest({"a": 1}) != attest.digest({"a": 2})
