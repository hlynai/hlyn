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
    """Send records to a buffer, and put the sink back afterwards."""
    buf = io.StringIO()
    log.sink(buf)
    yield buf
    log.sink(True)


def rows(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


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
    finally:
        log.sink(True)


def test_logging_can_be_turned_off(sink):
    log.off()
    try:
        log.emit("test")
        assert rows(sink) == []
    finally:
        log.sink(sink)
