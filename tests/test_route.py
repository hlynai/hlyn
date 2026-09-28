# SPDX-License-Identifier: Apache-2.0
"""The unconfined side of host mode (DESIGN-host-allowlisting.md 5.1, 5.2, 5.7, 5.8).

`route.start` launches the proxy helper and refuses unless it says it is
sealed; `route.Shared` hands out a port per run; `route.env` points clients
at the proxy; `route.sockets`/`neutralise` deal with connections opened
before a seal. Each test prints what it observed.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import SRC, enforces

from hlyn import helpers, hosts, route
from hlyn.error import Invalid, Unsupported

needs = pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
RULES = (hosts.parse("api.example.com"), hosts.parse("localhost:9"))


def ask(port: int, target: str) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        conn.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
        return conn.recv(200)


def gone(way: route.Route, timeout: float = 10) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end and way.alive():
        time.sleep(0.05)
    return not way.alive()


# ---------------------------------------------------------------------------
# starting a helper
# ---------------------------------------------------------------------------


def test_the_helper_command_is_an_isolated_interpreter_with_hlyn_on_its_path():
    argv = helpers.command("proxy", "--net", "a.example")
    print(argv)
    assert argv[0] == helpers.interpreter() and argv[1:3] == ["-I", "-S"]
    assert os.path.dirname(os.path.dirname(os.path.abspath(helpers.__file__))) in argv[4]
    assert argv[-3:] == ["proxy", "--net", "a.example"]
    with pytest.raises(ValueError):
        helpers.command("nothing")


def test_a_frozen_app_is_rerun_as_itself_with_the_marker(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", "/Applications/Agent.app/Contents/MacOS/agent")
    argv = helpers.command("gate", "--child", "7")
    print(argv)
    assert argv == ["/Applications/Agent.app/Contents/MacOS/agent", helpers.MARKER, "gate", "--child", "7"]


def test_hlyn_helper_becomes_the_helper_only_when_started_as_one():
    code = f"""
import sys
sys.path.insert(0, {SRC!r})
import hlyn
hlyn.helper()
print("the app's own main ran", sys.argv[1:])
"""
    plain = subprocess.run([sys.executable, "-c", code, "--app-flag"], capture_output=True, text=True,
                           timeout=30, check=False)
    marked = subprocess.run([sys.executable, "-c", code, helpers.MARKER, "proxy"], capture_output=True,
                            text=True, timeout=30, check=False)
    print("plain:", plain.returncode, plain.stdout, plain.stderr)
    print("marked:", marked.returncode, marked.stdout, marked.stderr)
    assert "the app's own main ran ['--app-flag']" in plain.stdout
    # Started as the proxy helper with no --net: the helper's own refusal, and
    # the app's main never runs.
    assert marked.returncode == 2 and "name at least one host" in marked.stderr and marked.stdout == ""


@needs
def test_start_returns_a_sealed_listening_proxy_and_stops_it_when_the_last_holder_goes():
    began = time.monotonic()
    way = route.start(RULES)
    took = time.monotonic() - began
    try:
        answer = ask(way.port, "evil.example.net:443")
        print(f"{way} started in {took * 1000:.0f} ms; CONNECT to an unlisted host -> {answer[:70]!r}")
        assert answer.startswith(b"HTTP/1.1 403 hlyn: evil.example.net:443 is not in --net")
    finally:
        way.close()
    parent = subprocess.run(["ps", "-o", "ppid=", "-p", str(way.pid)], capture_output=True, text=True,
                            check=False).stdout.strip()
    ended = gone(way)
    print(f"proxy {way.pid}'s parent while running: {parent} (this test is {os.getpid()}); "
          f"gone after the lifetime pipe closed: {ended}")
    assert parent == "1" and ended


@needs
def test_a_proxy_that_does_not_start_is_refused_with_the_fix():
    old = multiprocessing.spawn.get_executable()
    multiprocessing.set_executable("/usr/bin/true")
    try:
        with pytest.raises(Unsupported) as caught:
            route.start(RULES)
    finally:
        multiprocessing.set_executable(os.fsdecode(old))
    print(caught.value)
    text = str(caught.value)
    assert text.startswith("can't start the network helper:")
    assert 'sys.executable is /usr/bin/true, not Python. Call multiprocessing.set_executable' in text
    assert text.endswith("Nothing was sealed.")


@needs
def test_the_users_own_proxy_is_passed_on_and_a_bad_one_refused():
    way = route.start(RULES, source={"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "internal"})
    try:
        # -ww: procps cuts the line at 80 columns when stdout is not a terminal.
        line = subprocess.run(["ps", "-ww", "-o", "command=", "-p", str(way.pid)], capture_output=True,
                              text=True, check=False).stdout
        print(line)
        assert "--upstream http://proxy.corp:3128 --skip internal" in line
    finally:
        way.close()
    with pytest.raises(Invalid) as caught:
        route.start(RULES, source={"HTTPS_PROXY": "socks5://proxy.corp:1080"})
    print(caught.value)
    assert "only http:// proxies" in str(caught.value)


@needs
def test_deny_records_go_to_the_log_descriptor_with_the_run_port():
    read, write = os.pipe()
    way = route.start(RULES, log=write)
    os.close(write)
    try:
        ask(way.port, "evil.example.net:443")
        time.sleep(0.3)
        os.set_blocking(read, False)
        record = json.loads(os.read(read, 65536).splitlines()[0])
    finally:
        way.close()
        os.close(read)
    print(record)
    assert record["kind"] == "deny" and record["what"] == "net" and record["why"] == "not-listed"
    assert record["target"] == "evil.example.net:443" and record["allow"] == "--net evil.example.net"
    assert record["port"] == way.port and record["pid"] == way.pid and record["by"] == "hlyn-proxy"


# ---------------------------------------------------------------------------
# one proxy per allowlist, a port per run (5.8)
# ---------------------------------------------------------------------------


@needs
def test_shared_hands_out_a_port_per_run_and_closes_it_after():
    share = route.shared(RULES)
    try:
        read, write = os.pipe()
        one = share.lease(write)
        os.close(write)
        two = share.lease()
        print(f"shared proxy pid {share.route.pid}; run ports {one} and {two}")
        assert one != two
        assert ask(one, "evil.example.net:443").startswith(b"HTTP/1.1 403")
        time.sleep(0.3)
        os.set_blocking(read, False)
        record = json.loads(os.read(read, 65536).splitlines()[0])
        print("run one's log got:", record)
        assert record["port"] == one
        share.release(one)
        with pytest.raises(OSError) as caught:
            socket.create_connection(("127.0.0.1", one), timeout=2)
        print(f"after release, port {one}: {caught.value}")
        assert ask(two, "evil.example.net:443").startswith(b"HTTP/1.1 403")
        share.release(two)
        assert route.shared(RULES) is share
        os.close(read)
    finally:
        share.close()


@needs
def test_a_forked_child_does_not_reuse_its_parents_shared_proxy():
    # In a fresh interpreter: forking pytest's own multi-threaded process is
    # exactly the hazard hlyn avoids.
    code = f"""
import os, sys
sys.path.insert(0, {SRC!r})
from hlyn import hosts, route
rules = (hosts.parse("api.example.com"),)
share = route.shared(rules)
read, write = os.pipe()
kid = os.fork()
if kid == 0:
    os.close(read)
    mine = route.shared(rules)
    os.write(write, f"{{mine is share}} {{mine.route.pid}} {{share.route.control}}".encode())
    mine.close()
    os._exit(0)
os.close(write)
said = os.read(read, 400).decode()
os.waitpid(kid, 0)
print("parent's proxy", share.route.pid, "| child said:", said)
print("parent can still lease:", share.lease() > 0)
share.close()
"""
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                          check=False)
    print(done.stdout, done.stderr)
    parent = done.stdout.split("parent's proxy ")[1].split()[0]
    same, pid, control = done.stdout.split("child said: ")[1].split("\n")[0].split(" ", 2)
    assert same == "False" and pid != parent and control == "None"
    assert "parent can still lease: True" in done.stdout


# ---------------------------------------------------------------------------
# the agent's environment (5.7)
# ---------------------------------------------------------------------------


def test_env_points_every_common_client_at_the_proxy():
    got = route.env(40000, {"JAVA_TOOL_OPTIONS": "-Xmx1g"})
    for key, value in sorted(got.items()):
        print(f"{key}={value}")
    url = "http://127.0.0.1:40000"
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
                "npm_config_proxy", "npm_config_https_proxy"):
        assert got[key] == url
    assert got["NO_PROXY"] == got["no_proxy"] == "localhost,127.0.0.1,::1"
    assert got["NODE_USE_ENV_PROXY"] == "1"
    assert got["JAVA_TOOL_OPTIONS"].startswith("-Xmx1g -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=40000")


# ---------------------------------------------------------------------------
# sockets open before a seal (5.2, row 27)
# ---------------------------------------------------------------------------


def test_sockets_finds_every_ip_socket_and_nothing_else():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    tcp = socket.create_connection(server.getsockname())
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    unix = socket.socket(socket.AF_UNIX)
    try:
        found = route.sockets()
        print(route.describe(found))
        fds = {item.fd: item for item in found}
        assert fds[tcp.fileno()].peer == f"127.0.0.1:{server.getsockname()[1]}"
        assert fds[udp.fileno()].kind == "UDP" and fds[server.fileno()].kind == "TCP"
        assert unix.fileno() not in fds
    finally:
        for item in (server, tcp, udp, unix):
            item.close()


def test_neutralise_leaves_the_numbers_taken_and_every_use_failing():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    tcp = socket.create_connection(server.getsockname())
    number = tcp.fileno()
    count = route.neutralise([item for item in route.sockets() if item.fd == number])
    try:
        tcp.sendall(b"x")
        said = "sent"
    except OSError as exc:
        said = f"{type(exc).__name__}: {exc}"
    opened = os.open(os.devnull, os.O_RDONLY)
    print(f"neutralised {count}; send -> {said}; a new file got fd {opened}, the old number was {number}")
    assert count == 1 and said.startswith("OSError: [Errno") and "non-socket" in said
    assert opened != number
    os.close(opened)
    tcp.close()  # closes the /dev/null copy, harmlessly
    server.close()


# ---------------------------------------------------------------------------
# started without waiting: socket activation (hlyn run)
# ---------------------------------------------------------------------------


def settled(way: route.Route, timeout: float = 10) -> str | None:
    """Poll `problem()` until the proxy has said it's ready or failed."""
    end = time.monotonic() + timeout
    while way.pending is not None and time.monotonic() < end:
        said = way.problem()
        if said:
            return said
        time.sleep(0.02)
    assert way.pending is None, "the proxy neither became ready nor failed"
    return None


@needs
def test_an_early_proxy_has_its_port_and_pid_at_once_and_serves_a_connection_made_before_it_was_ready():
    rules = (hosts.parse("localhost:1"),)
    began = time.perf_counter()
    way = route.start(rules, wait=False)
    took = (time.perf_counter() - began) * 1000
    try:
        # Connected at once, before the proxy can have finished starting:
        # the kernel holds it in the backlog until the sealed proxy accepts.
        early = socket.create_connection(("127.0.0.1", way.port), timeout=10)
        early.sendall(b"CONNECT evil.example.net:443 HTTP/1.1\r\nHost: evil.example.net:443\r\n\r\n")
        answer = early.recv(200)
        early.close()
        said = settled(way)
        print(f"start returned in {took:.1f} ms; port {way.port}, pid {way.pid}; answer {answer[:60]!r}; "
              f"problem: {said!r}")
        assert said is None
        assert answer.startswith(b"HTTP/1.1 403")
    finally:
        way.close()
    assert gone(way)


@needs
def test_an_early_proxy_that_dies_before_it_is_ready_refuses_connections_and_says_why():
    rules = (hosts.parse("localhost:1"),)
    way = route.start(rules, wait=False)
    try:
        os.kill(way.pid, 9)  # before it could have sealed: a few ms in
        deadline = time.monotonic() + 10
        refused = None
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", way.port), timeout=2).close()
            except ConnectionRefusedError:
                refused = True
                break
            except ConnectionResetError:
                pass  # queued on the listener as the dying proxy closed it: try again
            time.sleep(0.05)
        said = settled(way)
        print(f"after SIGKILL: connection refused: {refused}; problem: {said!r}")
        assert refused, "nobody else may hold the listening socket: a dead proxy must refuse, not hang"
        assert said and said.startswith("the proxy stopped before it was ready")
    finally:
        way.close()


def reached(start: str) -> set[str]:
    """hlyn's modules reachable from `start` by import statements anywhere in
    each file, functions included: what a freezer's bytecode scan bundles."""
    import ast

    root = os.path.join(SRC, "hlyn")

    def path(name: str) -> str | None:
        parts = name.split(".")[1:]
        base = os.path.join(root, *parts)
        for candidate in (base + ".py", os.path.join(base, "__init__.py")):
            if os.path.isfile(candidate):
                return candidate
        return None

    seen: set[str] = set()
    todo = [start]
    while todo:
        name = todo.pop()
        if name in seen or path(name) is None:
            continue
        seen.add(name)
        package = name if path(name).endswith("__init__.py") else name.rpartition(".")[0]
        for node in ast.walk(ast.parse(Path(path(name)).read_text())):
            if isinstance(node, ast.Import):
                todo += [alias.name for alias in node.names if alias.name.startswith("hlyn")]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                    module = f"{base}.{node.module}" if node.module else base
                else:
                    module = node.module or ""
                if module.startswith("hlyn"):
                    todo.append(module)
                    todo += [f"{module}.{alias.name}" for alias in node.names]
    return seen


def test_a_freezer_finds_the_helpers_from_hlyn_helper():
    """Freezers (PyInstaller, Nuitka, cx_Freeze) bundle what a program's
    import statements reach. A frozen app starts its helpers through
    `hlyn.helper()`, so the proxy and the gate, and what they import, must be
    reachable by import statements from there, not only by a module name
    computed at run time (which is what failed: `No module named hlyn.proxy`)."""
    found = reached("hlyn.helpers")
    print(sorted(found))
    for name in ("hlyn.proxy", "hlyn.gate", "hlyn.listen", "hlyn.wire", "hlyn.chain", "hlyn.core.guard"):
        assert name in found, name


def test_pyinstaller_finds_hlyns_hook_and_the_hook_bundles_the_native_libraries():
    """The hook is found through the `pyinstaller40` entry point, and names
    the libraries hlyn opens by path (checked on the source, since PyInstaller
    itself needn't be installed to run this suite)."""
    import tomllib

    with open(os.path.join(os.path.dirname(SRC), "pyproject.toml"), "rb") as fh:
        points = tomllib.load(fh)["project"]["entry-points"]["pyinstaller40"]
    from hlyn.__pyinstaller import get_hook_dirs

    hooks = get_hook_dirs()
    hook = Path(hooks[0], "hook-hlyn.py").read_text()
    print(points, hooks, hook, sep="\n")
    assert points == {"hook-dirs": "hlyn.__pyinstaller:get_hook_dirs"}
    assert 'binaries = collect_dynamic_libs("hlyn")' in hook
