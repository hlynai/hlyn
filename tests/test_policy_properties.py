# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the policy layer.

The hand-written tests in test_policy.py check specific, chosen inputs. These
generate hundreds of adversarial ones per run and check invariants that must
hold for *all* of them -- the kind of edge case (a float port, a doubly-nested
symlink-shaped string, a path that is just "/") a human writing examples by
hand tends not to think of, but an injected agent's arguments are not obliged
to be polite.

A failure here means the policy layer computed a boundary wider, narrower, or
differently shaped than its own contract promises -- not that the kernel
enforcement is wrong, since none of this touches the kernel.
"""

from __future__ import annotations

import os

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from hlyn.error import Invalid, Unsupported
from hlyn.policy import Policy, paths, ports, prune, under

# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------

# POSIX path segments: printable, no NUL (which os.fspath rejects for a
# different reason than the one under test), no '/' (that is the separator,
# not a segment).
SEGMENT = st.text(
    alphabet=st.characters(blacklist_characters="/\0", blacklist_categories=("Cs",)),
    min_size=1,
    max_size=12,
).filter(lambda s: s not in (".", ".."))

RELPATH = st.lists(SEGMENT, min_size=0, max_size=5).map(lambda parts: "/".join(parts) or ".")
ABSPATH = RELPATH.map(lambda p: "/" + p.lstrip("/"))
ANYPATH = st.one_of(ABSPATH, RELPATH)

PORT_IN_RANGE = st.integers(min_value=1, max_value=65535)
PORT_OUT_OF_RANGE = st.integers().filter(lambda n: not (1 <= n <= 65535))


# ---------------------------------------------------------------------------
# under() / prune(): the primitives everything else is built from
# ---------------------------------------------------------------------------


@given(ABSPATH)
def test_under_is_reflexive(path):
    assert under(path, path)


@given(ABSPATH, SEGMENT)
def test_under_holds_for_a_true_child(root, child):
    assume(child not in (".", ".."))
    assert under(root.rstrip("/") + "/" + child, root)


@given(ABSPATH, SEGMENT)
def test_under_is_not_fooled_by_a_shared_string_prefix(root, suffix):
    # /usr/lib and /usr/libexec share a string prefix but are unrelated
    # directories. Sibling-with-shared-prefix must never register as "under".
    assume(suffix and not suffix.startswith("/"))
    sibling = root.rstrip("/") + suffix
    assume(sibling != root)
    assume(not sibling.startswith(root.rstrip("/") + "/"))
    assert not under(sibling, root)


@given(st.lists(ABSPATH, min_size=0, max_size=8))
def test_prune_result_is_a_subset_of_the_input(items):
    out = prune(items)
    assert set(out) <= set(items)


@given(st.lists(ABSPATH, min_size=0, max_size=8))
def test_prune_is_idempotent(items):
    once = prune(items)
    twice = prune(once)
    assert once == twice


@given(st.lists(ABSPATH, min_size=0, max_size=8))
def test_prune_leaves_no_redundant_pair(items):
    out = prune(items)
    for item in out:
        others = [other for other in out if other != item]
        assert not any(under(item, other) for other in others), (
            f"{item!r} is still covered by {[o for o in others if under(item, o)]!r}"
        )


@given(st.lists(ABSPATH, min_size=0, max_size=8))
def test_prune_still_covers_everything_the_input_covered(items):
    # Pruning must be a pure simplification: anything the original list would
    # have granted access to must still be granted after pruning.
    out = prune(items)
    for item in items:
        assert any(under(item, kept) for kept in out), f"{item!r} lost coverage after prune"


# ---------------------------------------------------------------------------
# paths(): the read/write/exec normaliser
# ---------------------------------------------------------------------------


@given(ANYPATH)
def test_paths_of_a_single_string_is_always_absolute(text):
    assume(text)
    out = paths(text, "read")
    assert isinstance(out, tuple)
    assert all(os.path.isabs(item) for item in out)


@given(st.lists(ANYPATH.filter(bool), min_size=0, max_size=6))
def test_paths_of_a_list_never_raises_on_well_formed_strings(items):
    out = paths(items, "read")
    assert isinstance(out, tuple)
    assert all(os.path.isabs(item) for item in out)


@given(ANYPATH)
def test_paths_is_idempotent_on_its_own_output(text):
    # Normalising an already-normalised path must be a no-op: the policy
    # layer sometimes feeds its own derived output back through the same
    # normaliser (e.g. Policy.with_), and a non-idempotent normaliser would
    # silently drift the grant on every round trip.
    assume(text)
    once = paths(text, "read")
    twice = paths(list(once), "read")
    assert once == twice


def test_paths_true_and_false_are_not_touched_by_generation():
    assert paths(True, "read") is True
    assert paths(False, "read") is False
    assert paths(None, "read") is False


# ---------------------------------------------------------------------------
# ports(): the network normaliser -- deny by default on anything unenforceable
# ---------------------------------------------------------------------------


@given(st.lists(PORT_IN_RANGE, min_size=0, max_size=8))
def test_ports_in_range_are_preserved_sorted_and_deduped(values):
    out = ports(values)
    assert out == tuple(sorted(set(values)))


@given(PORT_OUT_OF_RANGE)
def test_ports_out_of_range_are_rejected_not_clamped(bad):
    # A port outside 1-65535 must never be silently clamped into range: that
    # would grant a different port than the one asked for.
    try:
        out = ports([bad])
    except Invalid:
        return
    raise AssertionError(f"port {bad} should have raised Invalid, got {out!r}")


@given(st.text(min_size=1).filter(lambda s: not s.isdigit()))
def test_ports_never_turns_a_non_numeric_string_into_a_port(text):
    # A non-numeric string is a host entry (a Rule, refused at seal until host
    # mode is enforced) or refused with Invalid -- never coerced into a port
    # number, and never dropped.
    try:
        out = ports([text])
    except Invalid:
        return
    assert isinstance(out, tuple) and len(out) == 1, f"{text!r} became {out!r}"
    assert not isinstance(out[0], int), f"{text!r} was accepted as port {out[0]}"


@given(st.floats(allow_nan=False, allow_infinity=False))
def test_a_fractional_port_is_never_silently_truncated(value):
    # Found by Hypothesis: `int(1.5)` is 1, so a fractional port used to be
    # accepted as a different port than the one written -- exactly the quiet
    # substitution this module refuses to make anywhere else. A value that
    # converts exactly (443.0) is fine; one that would round is refused.
    try:
        out = ports([value])
    except (Invalid, Unsupported):
        return
    assert out == (int(value),) and int(value) == value, (
        f"port {value!r} was silently truncated to {out!r}"
    )


def test_ports_bools_pass_through_before_generation():
    assert ports(True) is True
    assert ports(False) is False


# ---------------------------------------------------------------------------
# Policy: the composed object
# ---------------------------------------------------------------------------


BOOLISH = st.booleans()
PATHLIST = st.lists(ABSPATH, min_size=0, max_size=4)
PORTLIST = st.lists(PORT_IN_RANGE, min_size=0, max_size=4)
FIELD = st.one_of(BOOLISH, PATHLIST)
NETFIELD = st.one_of(BOOLISH, PORTLIST)


@given(read=FIELD, write=FIELD, exe=FIELD, net=NETFIELD)
@settings(max_examples=200)
def test_policy_never_raises_on_well_formed_combinations(read, write, exe, net):
    Policy(read=read, write=write, exec=exe, net=net)


@given(read=FIELD, write=FIELD, exe=FIELD)
@settings(max_examples=200)
def test_the_runtime_set_always_stays_covered(read, write, exe):
    # Coverage, not set membership: prune() collapses a path into an ancestor
    # that already covers it, so granting "/" legitimately drops every runtime
    # entry from the tuple while still granting access to all of them. The
    # invariant that actually matters is that the interpreter can still reach
    # its own files, which is what `under` checks.
    from hlyn.policy import runtime

    p = Policy(read=read, write=write, exec=exe)
    got = p.reads()
    if got is True:
        return
    for item in runtime():
        assert any(under(item, kept) for kept in got), f"{item!r} became unreadable"


@given(write=BOOLISH, net=NETFIELD)
@settings(max_examples=200)
def test_a_blanket_write_grant_never_widens_read(write, net):
    # policy.py's own comment: "granting write everywhere does not quietly
    # grant read everywhere". This applies to the *bool* form only -- named
    # write paths are documented to cross over deliberately, because someone
    # writing write=["/out"] expects to read back what they wrote.
    from hlyn.policy import network, runtime

    p = Policy(write=write, net=net)
    got = p.reads()
    assert got is not True, "write=True widened read to everything"
    # The only other thing read may gain is what the network itself needs,
    # and only when the network is allowed.
    base = set(runtime()) | (set(network()) if p.net is not False else set())
    assert set(got) == set(prune(base))


@given(write=PATHLIST, net=NETFIELD)
@settings(max_examples=100)
def test_named_write_paths_cross_over_to_read_but_nothing_else_does(write, net):
    # The documented exception, pinned so it stays an exception: a named write
    # path becomes readable, and the read set never grows beyond that plus the
    # runtime.
    from hlyn.policy import network, runtime

    p = Policy(write=write, net=net)
    got = p.reads()
    assert got is not True
    allowed = set(runtime()) | set(paths(write, "write") or ())
    if p.net is not False:
        allowed |= set(network())
    for item in got:
        assert any(under(item, ok) or under(ok, item) for ok in allowed), (
            f"reads() invented {item!r}, which is neither runtime nor a named write path"
        )


@given(read=FIELD, write=FIELD, exe=FIELD)
@settings(max_examples=200)
def test_reads_and_writes_never_raise_for_any_valid_policy(read, write, exe):
    p = Policy(read=read, write=write, exec=exe)
    p.reads()
    p.writes()
    p.runs()


@given(net=NETFIELD)
@settings(max_examples=100)
def test_policy_net_field_matches_normalised_ports(net):
    p = Policy(net=net)
    assert p.net == ports(net)


@given(env=st.one_of(BOOLISH, st.lists(st.sampled_from(["A_KEY", "B_TOKEN", "PATH", "HOME"]))))
@settings(max_examples=100)
def test_keep_never_returns_more_than_the_source_had(env):
    source = {"A_KEY": "1", "B_TOKEN": "2", "PATH": "/bin", "HOME": "/root", "UNLISTED": "3"}
    p = Policy(env=env)
    kept = p.keep(source)
    assert set(kept) <= set(source)
    assert all(kept[k] == source[k] for k in kept)


@given(read=FIELD)
@settings(max_examples=100)
def test_with_never_mutates_the_original(read):
    base = Policy()
    derived = base.with_(read=read)
    assert base.read == ()
    assert derived.read == paths(read, "read")
