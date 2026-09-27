# SPDX-License-Identifier: Apache-2.0
"""The record.

Logging must never be the thing that breaks an agent, so the strongest
assertion here is that a broken sink is survivable.
"""

from __future__ import annotations

import io
import json

import pytest

from hlyn import log
from hlyn.policy import Policy


@pytest.fixture
def sink():
    """Send records to a buffer, and put the sink back afterwards.

    The repeat counter is process-wide, so it is cleared here too: without
    that, one test's records throttle the next test's identical ones and the
    suite passes or fails depending on the order it ran in.
    """
    buf = io.StringIO()
    log._seen.clear()
    log.sink(buf)
    yield buf
    log.sink(True)
    log._seen.clear()


def rows(buf: io.StringIO) -> list[dict]:
    """The records written so far, printed as read so the log shows them."""
    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    print(f"{len(lines)} record(s) in the sink:")
    for line in lines[:10]:
        print("  ", line)
    if len(lines) > 10:
        print(f"   ... and {len(lines) - 10} more")
    return [json.loads(line) for line in lines]


def test_each_record_is_one_json_object(sink):
    log.emit("test", a=1)
    log.emit("test", a=2)
    assert [r["a"] for r in rows(sink)] == [1, 2]


def test_records_carry_time_kind_and_pid(sink):
    log.emit("test")
    row = rows(sink)[0]
    assert {"t", "kind", "pid"} <= set(row)


def test_the_seal_record_states_the_boundary(sink):
    log.seal(Policy(read=["/srv"], net=[443]), "hlyn.core.linux", 6, "/tmp/x")
    row = rows(sink)[0]
    assert row["kind"] == "seal"
    assert row["backend"] == "linux"
    assert row["net"] == [443]
    assert row["tmp"] == "/tmp/x"


def test_a_long_path_list_is_summarised(sink):
    log.seal(Policy(read=[f"/p{i}" for i in range(40)]), "hlyn.core.linux", 6)
    row = rows(sink)[0]
    assert len(row["read"]) == 13
    assert "more" in row["read"][-1]


def test_denials_and_allowances_are_distinguishable(sink):
    log.deny("tool", "PermissionError", tool="search")
    log.allow("tool", tool="search")
    assert [r["kind"] for r in rows(sink)] == ["deny", "allow"]


def test_unserialisable_values_do_not_break_the_record(sink):
    log.emit("test", thing=object())
    assert rows(sink)[0]["kind"] == "test"


def test_a_broken_sink_never_breaks_the_agent():
    class Broken(io.StringIO):
        def write(self, _):
            raise OSError("disk full")

    log.sink(Broken())
    try:
        log.emit("test")  # must not raise
        print("emit into a sink that raises OSError('disk full'): returned normally")
    finally:
        log.sink(True)


def test_the_same_refusal_repeated_does_not_repeat_in_the_log(sink):
    """One startup under a tight policy denies the same thing hundreds of times."""
    for _ in range(100):
        log.deny("path", "EACCES", path="/etc/shadow")
    # Written on the 1st, 2nd, 4th, 8th, 16th, 32nd and 64th.
    assert len(rows(sink)) == 7


def test_a_repeated_record_carries_its_running_total(sink):
    for _ in range(4):
        log.deny("path", "EACCES", path="/etc/shadow")
    assert [r.get("seen") for r in rows(sink)] == [None, 2, 4]


def test_records_that_differ_are_never_collapsed(sink):
    """Throttling must not hide the one denial that is not like the others."""
    log.deny("path", "EACCES", path="/etc/shadow")
    log.deny("path", "EACCES", path="/root/.ssh/id_rsa")
    assert [r["path"] for r in rows(sink)] == ["/etc/shadow", "/root/.ssh/id_rsa"]


def test_a_first_occurrence_is_always_written_immediately(sink):
    """Nothing may wait for process exit: seccomp kills rather than exits."""
    log.deny("path", "EACCES", path="/etc/shadow")
    assert len(rows(sink)) == 1


def test_totals_report_what_was_collapsed(sink):
    for _ in range(5):
        log.deny("path", "EACCES", path="/etc/shadow")
    print("totals:", log.totals())
    assert list(log.totals().values()) == [5]


def test_tracking_stops_rather_than_growing_without_bound(sink):
    """An agent walking a large tree must not make the log module the leak."""
    for n in range(log.LIMIT + 50):
        log.emit("test", n=n)
    print(f"LIMIT {log.LIMIT}; tracked {len(log._seen)} distinct records after {log.LIMIT + 50}")
    assert len(log._seen) == log.LIMIT
    assert len(rows(sink)) == log.LIMIT + 50


def test_logging_can_be_turned_off(sink):
    log.off()
    try:
        log.emit("test")
        print("emitted one record with logging off")
        assert rows(sink) == []
    finally:
        log.sink(sink)


def test_a_host_policy_is_recorded_as_text():
    from hlyn.log import _shape
    from hlyn.policy import Policy

    shaped = _shape(Policy(net=["api.openai.com", "localhost:5432"]).net)
    print(shaped)
    assert shaped == ["api.openai.com:443", "localhost:5432"]
    json.dumps(shaped)  # a log line must serialise
