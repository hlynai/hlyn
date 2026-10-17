# SPDX-License-Identifier: Apache-2.0
"""What `hlyn.run(fn)` brings back from the confined child.

The child is the code hlyn exists to confine, so the bytes it writes to the
result pipe are untrusted input to the unconfined parent. They are parsed as
plain data (JSON), never unpickled, capped in size, and a failure is rebuilt
only from a fixed table of exception names and one string.

Each test prints what the parent observed. The forged-bytes tests write
inert data (valid pickles of plain values, text, noise): they show the parent
drops what is not a result, and that `pickle` is never loaded to look at it.
"""

from __future__ import annotations

import os
import pickle
import stat
import sys
import time

import pytest
from conftest import enforces

import hlyn

pytestmark = pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")


def _result_pipe() -> int:
    """The descriptor `run` reads the result from, found the way the code under
    test could find it: an open pipe this process can write."""
    for fd in range(3, 256):
        try:
            if stat.S_ISFIFO(os.fstat(fd).st_mode):
                os.write(fd, b"")
                return fd
        except OSError:
            continue
    raise AssertionError("the child holds no result pipe")


def forge(data: bytes):
    def fn():
        os.write(_result_pipe(), data)
        os._exit(0)
    return fn


def test_plain_data_comes_back_and_a_tuple_becomes_a_list():
    value = {"a": [1, 2.5, None, True, "text", ("x", 1)], "b": {"c": "d"}}
    got = hlyn.run(lambda: value)
    print("returned:", got)
    assert got == {"a": [1, 2.5, None, True, "text", ["x", 1]], "b": {"c": "d"}}


@pytest.mark.parametrize("make", [
    lambda: {1, 2},
    lambda: b"bytes",
    object,
    lambda: float("nan"),
    lambda: float("inf"),
    lambda: {1: "int key"},
    lambda: print,
    lambda: __import__("pathlib").Path("/"),
], ids=["set", "bytes", "object", "nan", "inf", "int key", "function", "path"])
def test_what_is_not_plain_data_is_refused_in_words(make):
    with pytest.raises(hlyn.Failed) as seen:
        hlyn.run(make)
    print("raised:", seen.value)
    assert "could not be returned" in str(seen.value) and "dict with str keys" in str(seen.value)


def test_nesting_deeper_than_the_limit_is_refused():
    def deep():
        value = []
        for _ in range(500):
            value = [value]
        return value
    with pytest.raises(hlyn.Failed) as seen:
        hlyn.run(deep)
    print("raised:", seen.value)
    assert "nested too deeply" in str(seen.value)


@pytest.mark.parametrize("data", [
    pickle.dumps(("ok", 42)),  # a valid pickle of what the old channel carried
    b'{"ok": 42} trailing',
    b'{"ok": 1, "no": {"type": "ValueError", "message": "x"}}',
    b'{"ok": NaN}',
    b'["ok", 42]',
    b"\xff\xfe\x00\x01 not text",
    b"[" * 100000,
    b"",
], ids=["pickle", "trailing", "two keys", "NaN", "list", "noise", "deep", "empty"])
def test_forged_bytes_are_dropped_not_evaluated(data):
    with pytest.raises(hlyn.Failed) as seen:
        hlyn.run(forge(data))
    print("raised:", seen.value)
    assert "not a result" in str(seen.value) or "returned nothing" in str(seen.value)


def test_the_parent_never_loads_pickle_to_look_at_forged_bytes():
    import subprocess

    from conftest import SRC

    code = (
        "import os, stat, sys, hlyn\n"
        "def fn():\n"
        "    for fd in range(3, 256):\n"
        "        try:\n"
        "            if stat.S_ISFIFO(os.fstat(fd).st_mode):\n"
        "                os.write(fd, b'\\x80\\x04N.'); os._exit(0)\n"
        "        except OSError:\n"
        "            pass\n"
        "try:\n"
        "    hlyn.run(fn)\n"
        "except hlyn.Failed as e:\n"
        "    print('dropped:', e)\n"
        "print('pickle loaded:', 'pickle' in sys.modules)\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False,
                          env={**os.environ, "PYTHONPATH": SRC})
    print(done.stdout, done.stderr)
    assert "dropped:" in done.stdout and "pickle loaded: False" in done.stdout


def test_a_result_over_the_cap_is_refused_and_the_child_ended():
    big = 20 << 20
    start = time.monotonic()
    with pytest.raises(hlyn.Failed) as seen:
        hlyn.run(lambda: "x" * big)
    took = time.monotonic() - start
    print(f"raised after {took:.2f} s:", seen.value)
    assert "size limit" in str(seen.value)


FLOOD = """
import json, os, resource, stat, sys, time
import hlyn

def pipe():
    for fd in range(3, 256):
        try:
            if stat.S_ISFIFO(os.fstat(fd).st_mode):
                return fd
        except OSError:
            pass

def writes(total):
    def fn():
        fd, chunk, sent = pipe(), b"x" * 65536, 0
        while total is None or sent < total:
            os.write(fd, chunk)
            sent += len(chunk)
        os._exit(0)
    return fn

def rss():  # peak resident size in bytes (macOS reports bytes, Linux KiB)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024

def fds():
    return len(os.listdir("/dev/fd"))

hlyn.run(lambda: 1)  # imports and first-use costs happen before the baseline
before_rss, before_fds, start = rss(), fds(), time.monotonic()
try:
    hlyn.run(writes(TOTAL))
    said = "RETURNED"
except hlyn.Failed as exc:
    said = str(exc)
try:
    os.waitpid(-1, os.WNOHANG)
    children = "a child is left"
except ChildProcessError:
    children = "none left"
print(json.dumps({"said": said, "grew_mib": (rss() - before_rss) >> 20, "fds_before": before_fds,
                  "fds_after": fds(), "children": children, "seconds": round(time.monotonic() - start, 2)}))
"""


def flood(total: int | None) -> dict:
    """Run a child that writes `total` bytes (None: for ever) at the result pipe,
    in a fresh interpreter with a hard time limit, and report what the parent
    saw: its message, how much its memory grew, whether any child or descriptor
    was left behind."""
    import json
    import subprocess

    from conftest import SRC

    done = subprocess.run([sys.executable, "-c", FLOOD.replace("TOTAL", repr(total))], capture_output=True,
                          text=True, check=False, timeout=60, env={**os.environ, "PYTHONPATH": SRC})
    print(done.stdout, done.stderr)
    return json.loads(done.stdout.splitlines()[-1])


def test_a_child_that_never_stops_writing_is_stopped_and_cleaned_up():
    seen = flood(None)
    assert "size limit" in seen["said"] and seen["seconds"] < 20
    assert seen["children"] == "none left" and seen["fds_after"] == seen["fds_before"]


def test_the_parent_never_holds_more_than_the_cap_while_it_reads():
    # 300 MiB are sent, nearly 20 times the cap. A parent that read it all
    # and checked afterwards would grow by hundreds of MiB.
    seen = flood(300 << 20)
    assert "size limit" in seen["said"]
    assert seen["grew_mib"] < 64, seen
    assert seen["children"] == "none left" and seen["fds_after"] == seen["fds_before"]


def test_a_result_just_under_the_cap_comes_back_whole():
    size = 15 << 20
    got = hlyn.run(lambda: "y" * size)
    print("returned", len(got), "characters")
    assert got == "y" * size


def test_an_ordinary_exception_comes_back_as_its_own_class():
    def boom():
        raise ValueError("from the confined child")
    with pytest.raises(ValueError, match="from the confined child"):
        hlyn.run(boom)


def test_an_os_error_keeps_its_class_and_errno(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("x")

    def denied():
        open(secret)  # noqa: SIM115
    with pytest.raises(PermissionError) as seen:
        hlyn.run(denied, read=[])
    print("raised:", repr(seen.value), seen.value.errno)
    assert seen.value.errno in (13, 1)  # EACCES on Linux, EPERM on macOS
    assert str(seen.value).count("Errno") == 1 and "secret.txt" in str(seen.value)


def test_hlyn_errors_come_back_as_themselves():
    def fn():
        raise hlyn.Invalid("a policy problem")
    with pytest.raises(hlyn.Invalid, match="a policy problem"):
        hlyn.run(fn)


def test_a_custom_exception_comes_back_as_a_failure_naming_it_never_as_an_object():
    class Mine(Exception):
        def __reduce__(self):  # would run in an unpickling parent; nothing here ever unpickles
            return (print, ("RAN IN THE PARENT",))

    def fn():
        raise Mine("custom")
    with pytest.raises(hlyn.Failed, match="Mine: custom") as seen:
        hlyn.run(fn)
    print("raised:", repr(seen.value))
    assert not isinstance(seen.value, Mine)


def test_a_forged_exception_naming_something_outside_the_table_is_a_failure():
    forged = b'{"no": {"type": "os.system", "message": "x", "errno": null}}'
    with pytest.raises(hlyn.Failed, match=r"os\.system: x"):
        hlyn.run(forge(forged))
    forged = b'{"no": {"type": "UnicodeDecodeError", "message": "x", "errno": null}}'
    with pytest.raises(hlyn.Failed, match="UnicodeDecodeError: x"):
        hlyn.run(forge(forged))
