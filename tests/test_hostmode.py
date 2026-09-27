"""Host mode through every entry point, on macOS (DESIGN-host-allowlisting.md 5.2-5.8).

`hlyn.on`, `hlyn.run(fn)`, `hlyn.spawn` and `hlyn run` with `net` naming
hosts: each starts the proxy, seals with a profile that allows only its
port, points the program at it, and keeps it alive exactly as long as the
program. Matrix rows 15 (clients that ignore the proxy), 16 (attacking the
helpers), 17 (a helper killed mid-run) and 27 (sockets open before the seal),
plus the report, the log, exit statuses and signals.

Offline wherever possible: a listed `localhost:PORT` entry stands in for an
allowed service, and an unlisted name is refused before any lookup. The one
test that needs the internet says so and skips without it. Every test prints
what the sealed program saw.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time

import pytest
from conftest import SRC, boot, enforces

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or not enforces(), reason="host mode is enforced on macOS (Linux: phase 4)"
)

HLYN = [sys.executable, "-m", "hlyn.cli"]
ENV = {**os.environ, "PYTHONPATH": SRC}


class Server:
    """A local service that answers every connection with `b"hi "` and what it got."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.got: list[bytes] = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(30)
            try:
                data = conn.recv(200)
            except OSError:
                data = b""
            self.got.append(data)
            with contextlib.suppress(OSError):
                conn.sendall(b"hi " + data)

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def service():
    server = Server()
    yield server
    server.close()


PROBE = """
import os, socket, urllib.request
def direct(host, port):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    s.settimeout(5)
    try:
        s.connect((host, port)); s.sendall(b"ping"); return "CONNECTED " + s.recv(20).decode()
    except OSError as e:
        return f"REFUSED errno {e.errno}"
def proxied(url):
    try:
        return "OK " + str(urllib.request.urlopen(url, timeout=10).status)
    except Exception as e:
        return f"FAILED {e}"
"""


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def gone(pid: int, timeout: float = 10) -> bool:
    end = time.monotonic() + timeout
    while alive(pid) and time.monotonic() < end:
        time.sleep(0.05)
    return not alive(pid)


def records(path: str) -> list[dict]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# hlyn.on()
# ---------------------------------------------------------------------------


def test_on_allows_listed_entries_only_and_records_the_proxy(service, tmp_path):
    log = str(tmp_path / "log.jsonl")
    done = boot(PROBE + f"""
import hlyn, json
got = hlyn.on(net=["api.example.com", "localhost:{service.port}"], log={log!r})
print("proxy", got["proxy"], "helpers", got["helpers"])
print("HTTPS_PROXY", os.environ.get("HTTPS_PROXY"), "NO_PROXY", os.environ.get("NO_PROXY"))
print("listed localhost:", direct("127.0.0.1", {service.port}))
print("unlisted local port:", direct("127.0.0.1", 9))
print("unlisted address:", direct("1.1.1.1", 443))
print("unlisted name, through the proxy:", proxied("https://evil.example.net/"))
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    out = done.stdout
    assert "listed localhost: CONNECTED hi ping" in out
    assert "unlisted local port: REFUSED errno 1" in out
    assert "unlisted address: REFUSED errno 1" in out
    assert "unlisted name, through the proxy: FAILED <urlopen error Tunnel connection failed: 403 hlyn: " \
           "evil.example.net:443 is not in --net (allow with --net evil.example.net)>" in out
    port = out.split("proxy 127.0.0.1:")[1].split()[0]
    assert f"HTTPS_PROXY http://127.0.0.1:{port} NO_PROXY localhost,127.0.0.1,::1" in out
    seal, deny = records(log)[0], records(log)[1]
    print("log:", seal, deny, sep="\n")
    assert seal["kind"] == "seal" and seal["proxy"] == f"127.0.0.1:{port}"
    assert deny["kind"] == "deny" and deny["target"] == "evil.example.net:443" and deny["port"] == int(port)
    helper = int(out.split("helpers [")[1].split("]")[0])
    assert gone(helper), "the proxy outlived the process that sealed itself with it"


def test_row_27_on_refuses_while_a_connection_is_open(service):
    done = boot(f"""
import socket, hlyn
held = socket.create_connection(("127.0.0.1", {service.port}))
try:
    hlyn.on(net=["api.example.com"])
except hlyn.Unsupported as e:
    print("REFUSED:", e)
print("sealed:", hlyn.sealed())
held.sendall(b"still mine"); print("caller's connection:", held.recv(20))
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "REFUSED: 1 network connection is already open (fd " in done.stdout
    assert f"to 127.0.0.1:{service.port}). It would keep working after the seal" in done.stdout
    assert "sealed: False" in done.stdout and "caller's connection: b'hi still mine'" in done.stdout


# ---------------------------------------------------------------------------
# hlyn.run(fn)
# ---------------------------------------------------------------------------


def test_run_gives_each_call_its_own_port_and_log_records(service, tmp_path):
    log = str(tmp_path / "log.jsonl")
    done = boot(PROBE + f"""
import hlyn, socket
held = socket.create_connection(("127.0.0.1", {service.port}))
def work():
    return (os.environ["HTTPS_PROXY"], direct("127.0.0.1", {service.port}),
            proxied("https://evil.example.net/"), held.fileno(), _use(held))
def _use(sock):
    try:
        sock.sendall(b"x"); return "inherited socket WORKS"
    except OSError as e:
        return f"inherited socket unusable: {{e}}"
policy = dict(net=["api.example.com", "localhost:{service.port}"], log={log!r})
for call in range(3):
    print("call", call, hlyn.run(work, **policy))
held.sendall(b"after"); print("caller's socket after:", held.recv(20))
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    calls = [line for line in done.stdout.splitlines() if line.startswith("call ")]
    assert len(calls) == 3
    ports = {line.split("http://127.0.0.1:")[1].split("'")[0] for line in calls}
    assert len(ports) == 3, "each run(fn) call should get its own port"
    for line in calls:
        assert "'CONNECTED hi ping'" in line and "403 hlyn: evil.example.net:443" in line
        assert "inherited socket unusable: [Errno 38] Socket operation on non-socket" in line
    assert "caller's socket after: b'hi after'" in done.stdout
    denies = [r for r in records(log) if r["kind"] == "deny"]
    print("deny records:", denies)
    assert {str(r["port"]) for r in denies} == ports
    seals = [r for r in records(log) if r["kind"] == "seal"]
    assert [r["closed"] for r in seals] == [1, 1, 1]


def test_run_refuses_a_host_policy_it_cannot_start_the_proxy_for():
    done = boot("""
import multiprocessing, hlyn
multiprocessing.set_executable("/usr/bin/false")
try:
    hlyn.run(lambda: "ran", net=["api.example.com"])
except hlyn.Unsupported as e:
    print("REFUSED:", e)
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "REFUSED: can't start the network helper:" in done.stdout and "Nothing was sealed." in done.stdout


# ---------------------------------------------------------------------------
# hlyn.spawn()
# ---------------------------------------------------------------------------


def test_spawn_keeps_the_pid_passes_the_status_and_ends_the_proxy(service):
    done = boot(f"""
import os, socket, hlyn
held = socket.create_connection(("127.0.0.1", {service.port}))
held.set_inheritable(True)  # one that would survive exec into the command
print("caller", os.getpid(), "held fd", held.fileno(), flush=True)
hlyn.spawn([{sys.executable!r}, "-c", '''
import os, socket, sys
print("command pid", os.getpid(), "parent", os.getppid(), flush=True)
print("proxy", os.environ.get("HTTPS_PROXY"), flush=True)
try:
    socket.socket(fileno={{held}}).sendall(b"x"); print("inherited socket WORKS")
except OSError as e:
    print("inherited socket unusable:", e)
sys.exit(5)
'''.replace("{{held}}", str(held.fileno()))], net=["api.example.com"], log=False)
""")
    print(done.stdout, done.stderr[-1500:], sep="\n")
    out = done.stdout
    caller = out.split("caller ")[1].split()[0]
    assert f"parent {caller}" in out and done.returncode == 5
    assert "inherited socket unusable: [Errno 38] Socket operation on non-socket" in out
    port = int(out.split("proxy http://127.0.0.1:")[1].split()[0])
    time.sleep(0.5)
    with pytest.raises(OSError) as caught:
        socket.create_connection(("127.0.0.1", port), timeout=2)
    print(f"proxy port {port} after the command exited: {caught.value}")


def test_spawn_passes_a_signal_to_the_command_and_dies_of_it_too():
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {SRC!r})
        import hlyn
        hlyn.spawn(["/bin/sleep", "30"], net=["api.example.com"], log=False)
    """)
    process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    end = time.monotonic() + 15
    kid = None
    while kid is None and time.monotonic() < end:
        found = subprocess.run(["pgrep", "-P", str(process.pid), "sleep"], capture_output=True, text=True,
                               check=False).stdout.split()
        kid = int(found[0]) if found else None
        time.sleep(0.05)
    assert kid is not None, "sleep never started"
    os.kill(process.pid, signal.SIGTERM)
    _, err = process.communicate(timeout=15)
    print(f"sent SIGTERM to {process.pid} (the original pid); status {process.returncode}; "
          f"sleep {kid} gone: {gone(kid)}\n{err[-800:]}")
    assert process.returncode == -signal.SIGTERM and gone(kid)


# ---------------------------------------------------------------------------
# hlyn run
# ---------------------------------------------------------------------------


def test_cli_reports_the_blocked_host_with_its_flag_and_passes_the_exit_code(service):
    done = subprocess.run(
        [*HLYN, "run", "--no-log", "--net", "api.example.com", "--net", f"localhost:{service.port}", "--",
         sys.executable, "-c", PROBE + f"""
print("listed:", direct("127.0.0.1", {service.port}))
print("blocked:", proxied("https://evil.example.net/")[:80])
raise SystemExit(3)
"""],
        capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/tmp",
    )
    print(done.stdout, done.stderr, sep="\n")
    assert done.returncode == 3
    assert "listed: CONNECTED hi ping" in done.stdout
    assert "net    evil.example.net:443" in done.stderr and "allow with --net evil.example.net" in done.stderr
    assert "Only allow hosts you recognise: an injected agent chooses where it tries to go." in done.stderr


def test_cli_explains_a_direct_connect_without_a_wrong_flag():
    done = subprocess.run(
        [*HLYN, "run", "--no-log", "--net", "api.example.com", "--", sys.executable, "-c",
         PROBE + 'print(direct("1.1.1.1", 443)); raise SystemExit(1)'],
        capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/tmp",
    )
    print(done.stdout, done.stderr, sep="\n")
    assert "REFUSED errno 1" in done.stdout
    assert "connected directly instead of through HTTPS_PROXY" in done.stderr
    assert "--net 443" not in done.stderr


# ---------------------------------------------------------------------------
# rows 15-17
# ---------------------------------------------------------------------------


def test_row_15_clients_that_ignore_the_proxy_fail_closed():
    body = PROBE + """
import asyncio
try:
    import urllib3
    urllib3.PoolManager(retries=False, timeout=5).request("GET", "http://1.1.1.1/"); print("urllib3: REACHED")
except Exception as e:
    print("urllib3:", type(e).__name__, str(e)[:90])
try:
    import aiohttp
    async def go():
        async with aiohttp.ClientSession() as s:  # trust_env=False: ignores HTTPS_PROXY
            async with s.get("http://1.1.1.1/", timeout=aiohttp.ClientTimeout(total=5)) as r:
                return r.status
    print("aiohttp: REACHED", asyncio.run(go()))
except Exception as e:
    print("aiohttp:", type(e).__name__, str(e)[:90])
"""
    done = boot("import hlyn\nhlyn.on(net=['api.example.com'], log=False)\n" + body)
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "REACHED" not in done.stdout
    assert "urllib3:" in done.stdout and "aiohttp:" in done.stdout


def test_row_16_the_agent_cannot_touch_the_helpers_or_another_runs_proxy():
    other = subprocess.Popen(
        [sys.executable, "-m", "hlyn.proxy", "--json", "--quiet", "--net", "example.com"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ENV)
    try:
        theirs = json.loads(other.stdout.readline())
        done = boot(PROBE + f"""
import hlyn
got = hlyn.on(net=["api.example.com"], log=False)
proxy = got["helpers"][0]
for what, call in (("kill the proxy", lambda: os.kill(proxy, 15)),
                   ("kill the proxy's group", lambda: os.killpg(os.getpgid(proxy), 15)),
                   ("signal 0 to it", lambda: os.kill(proxy, 0))):
    try:
        call(); print(what + ": ALLOWED")
    except OSError as e:
        print(what + ":", e.errno, e.strerror)
print("another run's proxy:", direct("127.0.0.1", {theirs["port"]}))
print("own proxy still up:", proxied("https://evil.example.net/")[:60])
""")
    finally:
        other.kill()
        other.wait()
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "kill the proxy: 1 Operation not permitted" in done.stdout
    assert "ALLOWED" not in done.stdout
    assert "another run's proxy: REFUSED errno 1" in done.stdout
    assert "own proxy still up: FAILED <urlopen error Tunnel connection failed: 403" in done.stdout


def test_row_17_a_proxy_killed_mid_run_closes_the_network_and_opens_nothing():
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {SRC!r})
    """) + PROBE + textwrap.dedent("""
        import hlyn, time
        got = hlyn.on(net=["api.example.com"], log=False)
        port = int(got["proxy"].split(":")[1])
        print("before:", proxied("https://evil.example.net/")[:70], flush=True)
        print("PROXY", got["helpers"][0], flush=True)
        sys.stdin.readline()
        print("after, through the proxy:", proxied("https://evil.example.net/")[:60])
        print("after, straight to its port:", direct("127.0.0.1", port))
        print("after, direct elsewhere:", direct("1.1.1.1", 443))
    """)
    process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    lines = []
    for line in process.stdout:
        lines.append(line)
        if line.startswith("PROXY"):
            break
    proxy = int(lines[-1].split()[1])
    os.kill(proxy, signal.SIGKILL)
    assert gone(proxy)
    out, err = process.communicate("go\n", timeout=60)
    out = "".join(lines) + out
    print(out, err[-800:], sep="\n")
    assert "before: FAILED <urlopen error Tunnel connection failed: 403" in out
    assert "after, through the proxy: FAILED" in out and "403" not in out.split("after, through")[1]
    assert "after, straight to its port: REFUSED errno 61" in out
    assert "after, direct elsewhere: REFUSED errno 1" in out


# ---------------------------------------------------------------------------
# the real internet, once, if there is one
# ---------------------------------------------------------------------------


def online() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not online(), reason="needs the internet")
def test_every_entry_point_reaches_a_listed_host_and_only_it():
    fetch = """
import urllib.request
def fetch(url):
    try:
        return urllib.request.urlopen(url, timeout=20).status
    except Exception as e:
        return str(e)[:70]
"""
    results = {}
    results["on"] = boot(fetch + """
import hlyn
hlyn.on(net=["example.com"], log=False)
print(fetch("https://example.com/"), "|", fetch("https://www.iana.org/"))
""").stdout.strip()
    results["run"] = boot(fetch + """
import hlyn
print(hlyn.run(lambda: f'{fetch("https://example.com/")} | {fetch("https://www.iana.org/")}',
               net=["example.com"], log=False))
""").stdout.strip()
    results["spawn"] = boot("""
import hlyn, sys
hlyn.spawn([sys.executable, "-c", '''
import urllib.request
def fetch(url):
    try:
        return urllib.request.urlopen(url, timeout=20).status
    except Exception as e:
        return str(e)[:70]
print(fetch("https://example.com/"), "|", fetch("https://www.iana.org/"))
'''], net=["example.com"], log=False)
""").stdout.strip()
    cli = subprocess.run([*HLYN, "run", "--no-log", "--no-report", "--net", "example.com", "--",
                          "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"],
                         capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/tmp")
    results["hlyn run (curl)"] = cli.stdout
    for name, said in results.items():
        print(f"{name}: {said}")
    for name in ("on", "run", "spawn"):
        assert results[name].startswith("200 | <urlopen error Tunnel connection failed: 403 hlyn: "
                                        "www.iana.org:443"), name
    assert results["hlyn run (curl)"] == "200"
