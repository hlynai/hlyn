# SPDX-License-Identifier: Apache-2.0
"""Watching an agent to find out what it needs.

Watching confines nothing, so nothing here is an escape test. What matters is
that the draft it produces is *honest*: that it records what was touched, that
it does not invent grants, and that the things it deliberately leaves out --
the interpreter's own files, a file descriptor mistaken for a path -- stay out.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
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


def files(root, *names: str) -> list[str]:
    """Real files under `root` (the draft leaves out paths that don't exist)."""
    out = []
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
        out.append(str(path))
    return out


@pytest.fixture
def data(tmp_path, monkeypatch):
    """A project folder outside the temp folder, which the draft skips."""
    home = tmp_path.parent / f"{tmp_path.name}-home"
    home.mkdir()
    monkeypatch.setattr(watch.tempfile, "gettempdir", lambda: str(tmp_path / "not-here"))
    return home


def test_two_files_in_one_directory_become_the_directory(clean, data):
    a, b = files(data / "data", "a.json", "b.json")
    observed({("read", a), ("read", b)})
    assert watch.suggest().read == (str(data / "data"),)


def test_a_lone_file_stays_a_file(clean, data):
    (only,) = files(data / "data", "only.json")
    observed({("read", only)})
    assert watch.suggest().read == (only,)


def test_the_interpreters_own_files_are_left_out(clean, data):
    """Every policy grants them anyway; listing them buries the real decisions."""
    (mine,) = files(data / "data", "mine.json")
    observed({("read", os.path.join(sys.prefix, "lib", "os.py")), ("read", mine)})
    assert watch.suggest().read == (mine,)


def test_a_written_path_is_not_repeated_as_a_read(clean, data):
    """Granting write already grants read, so saying both is noise."""
    a, b = files(data / "out", "a", "b")
    observed({("write", a), ("write", b), ("read", a)})
    plan = watch.suggest()
    assert plan.write == (str(data / "out"),)
    assert plan.read == ()


def test_a_path_that_does_not_exist_is_left_out(clean, data):
    """Found in real runs: a program started by name is looked for along PATH,
    and each miss was drafted as a program to allow; `hlyn run` then refused
    the draft, since a path that doesn't exist can't be granted. A read of a
    file that isn't there is the same kind of probe."""
    (tool,) = files(data / "bin", "tool")
    observed({("exec", "/usr/local/sbin/no-such-tool"), ("exec", tool),
              ("read", str(data / "missing.cfg"))})
    plan = watch.suggest()
    print(plan)
    assert plan.exec == (tool,) and plan.read == ()


def test_a_file_the_run_created_is_granted_by_its_folder(clean, data):
    """Creating a file needs its folder: a grant on the file alone refuses the
    next run, which starts before it exists (found: an agent writing
    out/report.json)."""
    (data / "out").mkdir()
    observed({("write", str(data / "out" / "report.json"))})
    assert watch.suggest().write == (str(data / "out"),)


def test_a_written_path_is_granted_by_its_folder_unless_that_is_too_wide(clean, data, monkeypatch):
    """Writing is granted by folder: a tool that saves by writing a temporary
    file and renaming it, or that creates what it writes (git clone's new
    folder, found in tools/hostlab/watchlab.sh), needs the folder, which the
    next run starts without. Not the home folder, though: a file written
    there stays a file."""
    monkeypatch.setenv("HOME", str(data))
    (notes,) = files(data / "notes", "today.md")
    (rc,) = files(data, ".toolrc")
    observed({("write", notes), ("write", rc), ("write", str(data / "clone")),
              ("write", str(data / "clone" / "README"))})
    plan = watch.suggest()
    print(plan.write)
    assert str(data / "notes") in plan.write and rc in plan.write
    assert str(data) not in plan.write
    # A folder the run made in the home folder is named itself: its parent is
    # too wide to grant on a guess.
    assert str(data / "clone") in plan.write


def test_a_wide_folder_read_whole_is_left_out(clean, data):
    """pip lists /etc (its `distro` check), which recorded `/etc` as a read and
    drafted all of it, /etc/shadow included. Measured: pip installs with the
    listing refused, since the files it wants are granted by every policy.
    So a folder too wide to grant on a guess is left out when read whole;
    files read in it stay."""
    observed({("read", "/etc"), ("read", "/etc/hosts")})
    plan = watch.suggest()
    print(plan.read)
    assert "/etc" not in plan.read and "/etc/hosts" in plan.read


def test_never_collapsed_into_a_top_folder_proc_or_a_folder_holding_credentials(clean, data):
    """Two files in /etc became `/etc` (hlyn then warned /etc/shadow was
    exposed), and npm's /proc reads became `/proc`, every process's
    environment. The draft keeps the files instead."""
    keyed = data / "config"
    a, b = files(keyed, "app.toml", "db.toml")
    (keyed / ".env").write_text("API_KEY=sk-live-not-real")
    observed({("read", "/etc/hosts"), ("read", "/etc/passwd"), ("read", a), ("read", b),
              *(("read", f"/proc/{os.getpid()}/{name}") for name in ("stat", "status")
                if sys.platform == "linux")})
    plan = watch.suggest()
    print(plan.read)
    assert "/etc" not in plan.read and "/etc/hosts" in plan.read and "/etc/passwd" in plan.read
    assert str(keyed) not in plan.read and a in plan.read and b in plan.read
    assert not any(item in ("/proc", f"/proc/{os.getpid()}") for item in plan.read)


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


# -- host names (DESIGN-host-allowlisting.md 4.7) ----------------------------


def test_a_name_looked_up_is_recorded_with_its_port(clean):
    watch._hook("socket.getaddrinfo", ("API.OpenAI.com.", 443, 0, 1, 0, 0))
    watch._hook("socket.getaddrinfo", (b"pypi.org", "https", 0, 1, 0, 0))
    print(sorted(clean))
    assert ("host", "api.openai.com 443") in clean
    assert ("host", "pypi.org 0") in clean  # a service name, not a number: port unknown


def test_a_request_through_a_proxy_records_the_host_it_tunnels_to(clean):
    class Tunnel:
        _tunnel_host = "pypi.org"
        _tunnel_port = 443

    watch._hook("http.client.connect", (Tunnel(), "127.0.0.1", 3128))
    print(sorted(clean))
    assert clean == {("host", "pypi.org 443")}


def test_hosts_seen_make_the_draft_name_hosts(clean, monkeypatch):
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    observed({
        ("host", "api.openai.com 443"), ("host", "pypi.org 0"),
        ("addr", "151.101.0.223 443"),  # pypi.org's address: a name explains it
        ("addr", "127.0.0.1 5432"),  # a local database: localhost:5432
        ("addr", "10.0.0.5 6379"),  # an internal service, by address
        ("host", "127.0.0.1 0"),  # an address looked up: not a name
        ("host", "b\u00fccher.de 443"),  # the grammar refuses it: left out
        ("net", "443"), ("net", "5432"), ("net", "6379"),
    })
    got = [str(rule) for rule in watch.suggest().net]
    print(got)
    assert got == ["10.0.0.5:6379", "api.openai.com:443", "localhost:5432", "pypi.org:443"]


def test_the_environments_own_proxy_is_not_drafted(clean, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:46467")
    observed({("host", "pypi.org 443"), ("addr", "127.0.0.1 46467"), ("net", "46467")})
    got = [str(rule) for rule in watch.suggest().net]
    print(got)
    assert got == ["pypi.org:443"]


def test_without_names_the_draft_names_ports_as_before(clean):
    observed({("addr", "10.0.0.1 443"), ("net", "443")})
    assert watch.suggest().net == (443,)


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="needs a backend that seals")
def test_watch_once_then_enforce_the_draft(tmp_path):
    """The workflow 4.7 recommends: watch, read the draft, run under it. The
    agent here only looks a name up (offline), so the draft must list that
    host, and the enforced run must refuse a host the watch never saw."""
    agent = tmp_path / "agent.py"
    agent.write_text(
        "import socket, sys, urllib.request\n"
        "try:\n    socket.getaddrinfo('api.example.com', 443)\nexcept OSError:\n    pass\n"
        "if len(sys.argv) > 1:\n"
        "    try:\n        urllib.request.urlopen('https://evil.example.net/', timeout=10)\n"
        "    except Exception as e:\n        print('evil:', e)\n"
    )
    env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
    env["PYTHONPATH"] = SRC
    drafted = subprocess.run([sys.executable, "-m", "hlyn.cli", "watch", "--", sys.executable, str(agent)],
                             capture_output=True, text=True, env=env, cwd=str(tmp_path), check=False)
    print(drafted.stdout)
    assert 'net = [\n  "api.example.com:443",\n]' in drafted.stdout
    policy = tmp_path / "policy.toml"
    policy.write_text(drafted.stdout)
    enforced = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "-f", str(policy), "--read", str(tmp_path),
         "--", sys.executable, str(agent), "evil"],
        capture_output=True, text=True, env=env, cwd=str(tmp_path), check=False)
    print(enforced.stdout, enforced.stderr[-800:])
    assert "403 hlyn: evil.example.net:443 is not in --net" in enforced.stdout
    assert "allow with --net evil.example.net" in enforced.stderr


def drafted(program: str, draft: str) -> bool:
    """Whether `draft` grants running `program`, where PATH finds it."""
    found = shutil.which(program) or program
    return f'"{found}"' in draft or f'"{os.path.realpath(found)}"' in draft


@pytest.mark.skipif(not shutil.which("curl"), reason="needs curl")
def test_watch_sees_where_a_non_python_client_went_through_its_proxy(tmp_path):
    """curl in a child process is invisible to Python's audit hooks; it
    names its destination only to the proxy it goes through. hlyn watch
    sends it through its own, in record mode, and drafts that host -- and
    not the recording proxy it only reached because it was told to.

    The server is on loopback, which NO_PROXY exempts; curl's `--noproxy ''`
    clears that list, so it still takes the proxy it was given. (127.0.0.2,
    which NO_PROXY doesn't name, isn't configured on macOS.)"""
    import http.server
    import threading

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    script = tmp_path / "agent.py"
    script.write_text(f"import subprocess; subprocess.run(['curl', '-s', '--noproxy', '', '-o', '/dev/null', "
                      f"'http://127.0.0.1:{port}/'], check=True)\n")
    env = {k: v for k, v in os.environ.items() if k.lower() not in (
        "https_proxy", "http_proxy", "all_proxy", "no_proxy")}
    env["PYTHONPATH"] = SRC
    done = subprocess.run([sys.executable, "-m", "hlyn.cli", "watch", "--", sys.executable, str(script)],
                          capture_output=True, text=True, env=env, check=False, timeout=60)
    server.shutdown()
    print(done.stdout, done.stderr[-600:])
    assert done.returncode == 0
    assert f'"localhost:{port}"' in done.stdout
    assert done.stdout.count("localhost:") == 1  # the recording proxy isn't drafted
    # A program started by bare name is granted where PATH found it.
    assert drafted("curl", done.stdout)


def test_a_program_started_by_name_is_found_on_path_not_in_the_working_folder(clean, tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    tool = bin_ / "mytool"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    watch._program("mytool", {"PATH": str(bin_)})
    watch._program("no-such-tool-anywhere", {"PATH": str(bin_)})
    watch._program("./relative/tool")
    print(watch.seen())
    assert ("exec", str(tool)) in watch.seen()
    assert not [value for kind, value in watch.seen() if "no-such-tool" in value]
    assert ("exec", os.path.abspath("./relative/tool")) in watch.seen()


@pytest.mark.skipif(sys.platform != "linux", reason="the preloaded library is Linux-only")
def test_watch_sees_what_a_program_that_isnt_python_uses(tmp_path):
    """No Python in the workload at all: a shell pipeline. The library
    `hlyn run` preloads to hear refusals reports what was allowed instead,
    so the draft names the programs it ran and the file it wrote."""
    from hlyn.core import preload

    if preload.find() is None:
        pytest.skip("the reporting library isn't built (cargo build --release in native/report)")
    out = os.path.join(os.environ.get("HOME", "/root"), f".hlyn-watch-test-{os.getpid()}.txt")
    try:
        done = subprocess.run(
            [sys.executable, "-m", "hlyn.cli", "watch", "--", "sh", "-c", f"echo hi | tr a-z A-Z > {out}"],
            capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC), check=False, timeout=60)
    finally:
        with contextlib.suppress(OSError):
            os.remove(out)
    print(done.stdout, done.stderr[-400:])
    assert done.returncode == 0
    assert drafted("tr", done.stdout)
    assert f'"{out}"' in done.stdout
