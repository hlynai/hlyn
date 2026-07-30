"""Watching an agent to find out what it needs.

Watching confines nothing, so nothing here is an escape test. What matters is
that the draft it produces is *honest*: that it records what was touched, that
it does not invent grants, and that the things it deliberately leaves out --
the interpreter's own files, a file descriptor mistaken for a path -- stay out.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from hlyn import watch
from hlyn.policy import Policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")


@pytest.fixture
def clean():
    """Watching is one-way inside a process, so tests drive the parts directly."""
    watch._seen.clear()
    yield watch._seen
    watch._seen.clear()


def observed(pairs):
    watch._seen.update(pairs)


# -- reading the events -----------------------------------------------------


def test_a_write_mode_is_recorded_as_a_write(clean):
    watch._hook("open", ("/tmp/out.txt", "w", None))
    assert ("write", "/tmp/out.txt") in clean


def test_a_read_mode_is_recorded_as_a_read(clean):
    watch._hook("open", ("/tmp/in.txt", "r", None))
    assert ("read", "/tmp/in.txt") in clean


def test_append_and_update_modes_count_as_writes(clean):
    watch._hook("open", ("/tmp/a", "a", None))
    watch._hook("open", ("/tmp/b", "r+", None))
    assert {("write", "/tmp/a"), ("write", "/tmp/b")} <= clean


def test_open_flags_are_read_when_there_is_no_mode_string(clean):
    """os.open reports flags and no mode; io.open the reverse."""
    watch._hook("open", ("/tmp/c", None, os.O_WRONLY | os.O_CREAT))
    watch._hook("open", ("/tmp/d", None, os.O_RDONLY))
    assert ("write", "/tmp/c") in clean
    assert ("read", "/tmp/d") in clean


def test_a_file_descriptor_is_not_mistaken_for_a_path(clean):
    """`open` reports an int when the caller opened a descriptor.

    Recorded as a path it becomes a relative grant for a file named "3", whose
    directory is the empty string -- which Policy refuses several steps later,
    far from the cause.
    """
    watch._hook("open", (3, "r", None))
    assert clean == set()


def test_a_connection_records_its_port(clean):
    watch._hook("socket.connect", (object(), ("10.0.0.1", 443)))
    assert ("net", "443") in clean


def test_a_unix_socket_has_no_port_to_record(clean):
    watch._hook("socket.connect", (object(), "/run/thing.sock"))
    assert clean == set()


def test_a_subprocess_records_the_program(clean):
    watch._hook("subprocess.Popen", ("/bin/echo", ["echo", "hi"], None, None))
    assert ("exec", "/bin/echo") in clean


def test_a_shell_command_records_the_shell_not_the_line(clean):
    """The line is not a path, and granting it would be unenforceable."""
    watch._hook("os.system", (b"rm -rf /tmp/x",))
    assert ("exec", "/bin/sh") in clean


def test_the_hook_never_raises_on_a_malformed_event(clean):
    """An exception here would propagate into whatever the agent was doing."""
    watch._hook("open", ())
    watch._hook("socket.connect", ())
    watch._hook("subprocess.Popen", ())


# -- turning observations into a draft --------------------------------------


def test_two_files_in_one_directory_become_the_directory(clean):
    observed({("read", "/data/a.json"), ("read", "/data/b.json")})
    assert watch.suggest().read == ("/data",)


def test_a_lone_file_stays_a_file(clean):
    observed({("read", "/data/only.json")})
    assert watch.suggest().read == ("/data/only.json",)


def test_the_interpreters_own_files_are_left_out(clean):
    """Every policy grants them anyway; listing them buries the real decisions."""
    observed({("read", os.path.join(sys.prefix, "lib", "thing.py")), ("read", "/data/mine.json")})
    assert watch.suggest().read == ("/data/mine.json",)


def test_a_written_path_is_not_repeated_as_a_read(clean):
    """Granting write already grants read, so saying both is noise."""
    observed({("write", "/out/a"), ("write", "/out/b"), ("read", "/out/a")})
    plan = watch.suggest()
    assert plan.write == ("/out",)
    assert plan.read == ()


def test_ports_are_collected_as_numbers(clean):
    observed({("net", "443"), ("net", "8080")})
    assert watch.suggest().net == (443, 8080)


def test_nothing_observed_means_nothing_granted(clean):
    plan = watch.suggest()
    assert plan.read == ()
    assert plan.net is False
    assert plan.exec is False


def test_the_draft_is_a_real_policy(clean):
    """It has to survive Policy's own validation, not just look like one."""
    observed({("read", "/data/a"), ("net", "443"), ("exec", "/bin/echo")})
    assert isinstance(watch.suggest(), Policy)


# -- end to end -------------------------------------------------------------


def test_watching_a_child_records_what_it_touched(tmp_path):
    """The command is not modified and does not cooperate; PYTHONPATH does the work."""
    box = tmp_path / "work"
    box.mkdir()
    agent = tmp_path / "agent.py"
    agent.write_text(
        "import os\n"
        f"open({str(box / 'one.txt')!r}, 'w').write('x')\n"
        f"open({str(box / 'two.txt')!r}, 'w').write('x')\n"
    )

    seen = tmp_path / "seen.json"
    boot = tmp_path / "sitecustomize.py"
    boot.write_text("import hlyn.watch; hlyn.watch.start()")

    env = dict(os.environ)
    env["HLYN_WATCH"] = str(seen)
    env["PYTHONPATH"] = os.pathsep.join([str(tmp_path), SRC])
    done = subprocess.run(
        [sys.executable, str(agent)], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr

    pairs = json.loads(seen.read_text())
    got = {tuple(item) for item in pairs}
    assert ("write", str(box / "one.txt")) in got
    assert ("write", str(box / "two.txt")) in got
