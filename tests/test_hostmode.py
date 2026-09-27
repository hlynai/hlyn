"""Host mode through every entry point (DESIGN-host-allowlisting.md 5.2-5.8).

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
import errno
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
    sys.platform not in ("darwin", "linux") or not enforces(), reason="host mode needs a backend that seals"
)

HLYN = [sys.executable, "-m", "hlyn.cli"]
ENV = {**os.environ, "PYTHONPATH": SRC}

# What a refused direct connection returns: Seatbelt says EPERM, the Linux
# gate (and Landlock) EACCES. Compared as whole values, never as prefixes:
# "errno 1" is a prefix of "errno 13".
DENIED = errno.EPERM if sys.platform == "darwin" else errno.EACCES
NOTSOCK = f"[Errno {errno.ENOTSOCK}] {os.strerror(errno.ENOTSOCK)}"


def said(out: str, label: str) -> str:
    """The rest of the line in `out` that starts with `label: `."""
    for line in out.splitlines():
        if line.startswith(label + ": "):
            return line[len(label) + 2:]
    return f"(no line {label!r})"


class Server:
    """A local service that answers every connection with `b"hi "` and what it got."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.got: list[bytes] = []
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

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
        # On Linux, close() alone doesn't wake a thread blocked in accept();
        # a leftover thread would make later in-process seals refuse (Landlock
        # confines one thread). shutdown() does wake it.
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.thread.join(5)


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
    assert said(out, "listed localhost") == "CONNECTED hi ping"
    assert said(out, "unlisted local port") == f"REFUSED errno {DENIED}"
    assert said(out, "unlisted address") == f"REFUSED errno {DENIED}"
    assert "unlisted name, through the proxy: FAILED <urlopen error Tunnel connection failed: 403 hlyn: " \
           "evil.example.net:443 is not in --net (allow with --net evil.example.net)>" in out
    port = out.split("proxy 127.0.0.1:")[1].split()[0]
    assert f"HTTPS_PROXY http://127.0.0.1:{port} NO_PROXY localhost,127.0.0.1,::1" in out
    rows = records(log)
    print("log:", *rows, sep="\n")
    seal = rows[0]
    deny = next(row for row in rows if row["kind"] == "deny" and row["source"] == "proxy")
    assert seal["kind"] == "seal" and seal["proxy"] == f"127.0.0.1:{port}"
    assert deny["target"] == "evil.example.net:443" and deny["port"] == int(port)
    if sys.platform == "linux":
        # The direct connects were refused by the gate, which logs them too.
        gate = {row["target"]: row["allow"] for row in rows
                if row["kind"] == "deny" and row["source"] == "gate"}
        assert gate == {"127.0.0.1:9": "--net localhost:9", "1.1.1.1:443": "--net 1.1.1.1"}
    helpers = [int(pid) for pid in out.split("helpers [")[1].split("]")[0].split(",")]
    # macOS: [proxy]. Linux: [gate, proxy]; the gate exits with the process too.
    assert len(helpers) == (1 if sys.platform == "darwin" else 2)
    for helper in helpers:
        assert gone(helper), f"helper {helper} outlived the process that sealed itself with it"


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
        assert f"inherited socket unusable: {NOTSOCK}" in line
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
    assert f"inherited socket unusable: {NOTSOCK}" in out
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
    assert done.stdout.strip() == f"REFUSED errno {DENIED}"
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
for name, pid in zip(("gate", "proxy") if len(got["helpers"]) == 2 else ("proxy",), got["helpers"]):
    for what, call in ((f"kill the {{name}}", lambda: os.kill(pid, 15)),
                       (f"kill the {{name}}'s group", lambda: os.killpg(os.getpgid(pid), 15)),
                       (f"signal 0 to the {{name}}", lambda: os.kill(pid, 0))):
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
    assert said(done.stdout, "kill the proxy") == "1 Operation not permitted"
    if sys.platform == "linux":
        assert said(done.stdout, "kill the gate") == "1 Operation not permitted"
    assert "ALLOWED" not in done.stdout
    assert said(done.stdout, "another run's proxy") == f"REFUSED errno {DENIED}"
    assert "own proxy still up: FAILED <urlopen error Tunnel connection failed: 403" in done.stdout


HELPERS = ["proxy"] + (["gate"] if sys.platform == "linux" else [])


@pytest.mark.parametrize("which", HELPERS)
def test_row_17_a_helper_killed_mid_run_closes_the_network_and_opens_nothing(which):
    """Killing the proxy: connections through it are refused. Killing the
    gate (Linux): the kernel answers every trapped connect with ENOSYS,
    because no one holds the notification descriptor. Neither opens a
    single connection."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {SRC!r})
    """) + PROBE + textwrap.dedent("""
        import hlyn, time
        got = hlyn.on(net=["api.example.com"], log=False)
        port = int(got["proxy"].split(":")[1])
        print("before:", proxied("https://evil.example.net/")[:70], flush=True)
        print("HELPERS", *got["helpers"], flush=True)
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
        if line.startswith("HELPERS"):
            break
    pids = [int(pid) for pid in lines[-1].split()[1:]]
    victim = pids[-1] if which == "proxy" else pids[0]
    os.kill(victim, signal.SIGKILL)
    assert gone(victim)
    out, err = process.communicate("go\n", timeout=60)
    out = "".join(lines) + out
    print(f"killed the {which} ({victim})", out, err[-800:], sep="\n")
    assert "before: FAILED <urlopen error Tunnel connection failed: 403" in out
    assert said(out, "after, through the proxy").startswith("FAILED")
    assert "403" not in out.split("after, through")[1]
    if which == "proxy":
        assert said(out, "after, straight to its port") == f"REFUSED errno {errno.ECONNREFUSED}"
        assert said(out, "after, direct elsewhere") == f"REFUSED errno {DENIED}"
    else:
        assert said(out, "after, straight to its port") == f"REFUSED errno {errno.ENOSYS}"
        assert said(out, "after, direct elsewhere") == f"REFUSED errno {errno.ENOSYS}"


# ---------------------------------------------------------------------------
# the real internet, once, if there is one
# ---------------------------------------------------------------------------


def reachable() -> str | None:
    """A host this machine can fetch over HTTPS unconfined, the way the test
    will (through the environment's own proxy, if it has one), or None."""
    import urllib.request

    for host in ("example.com", "pypi.org"):
        try:
            urllib.request.urlopen(f"https://{host}/", timeout=10).close()
            return host
        except Exception:  # noqa: BLE001, S112 - any failure: try the next host
            continue
    return None


HOST = reachable()


def online() -> bool:
    return HOST is not None


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
    assert HOST is not None
    fetch = fetch.replace("HOST", HOST)
    results["on"] = boot(fetch + """
import hlyn
hlyn.on(net=["HOST"], log=False)
print(fetch("https://HOST/"), "|", fetch("https://www.iana.org/"))
""".replace("HOST", HOST)).stdout.strip()
    results["run"] = boot(fetch + """
import hlyn
print(hlyn.run(lambda: f'{fetch("https://HOST/")} | {fetch("https://www.iana.org/")}',
               net=["HOST"], log=False))
""".replace("HOST", HOST)).stdout.strip()
    results["spawn"] = boot("""
import hlyn, sys
hlyn.spawn([sys.executable, "-c", '''
import urllib.request
def fetch(url):
    try:
        return urllib.request.urlopen(url, timeout=20).status
    except Exception as e:
        return str(e)[:70]
print(fetch("https://HOST/"), "|", fetch("https://www.iana.org/"))
'''], net=["HOST"], log=False)
""".replace("HOST", HOST)).stdout.strip()
    cli = subprocess.run([*HLYN, "run", "--no-log", "--no-report", "--net", HOST, "--",
                          "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"https://{HOST}"],
                         capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/tmp")
    results["hlyn run (curl)"] = cli.stdout
    for name, text in results.items():
        print(f"{name}: {text}")
    for name in ("on", "run", "spawn"):
        assert results[name].startswith("200 | <urlopen error Tunnel connection failed: 403 hlyn: "
                                        "www.iana.org:443"), name
    assert results["hlyn run (curl)"] == "200"


# ---------------------------------------------------------------------------
# Linux: the gate (5.2, 5.3)
# ---------------------------------------------------------------------------

linux = pytest.mark.skipif(sys.platform != "linux", reason="the gate answers connection checks on Linux only")

HUNT = """
import fcntl, os, struct
# SECCOMP_IOCTL_NOTIF_RECV: _IOWR('!', 0, struct seccomp_notif), 80 bytes.
RECV = (3 << 30) | (80 << 16) | (ord("!") << 8)
held, answered = [], []
for fd in range(4096):
    try:
        fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError:
        continue
    held.append(fd)
    try:
        fcntl.ioctl(fd, RECV, bytearray(80), True)
        answered.append(fd)
    except OSError:
        pass
print("descriptors held:", held)
print("descriptors that answer NOTIF_RECV:", answered)
"""


@linux
@pytest.mark.parametrize("entry", ["on", "run", "spawn"])
def test_row_19_the_agent_holds_no_notification_descriptor(entry):
    """The sealed process closes its copy of the notification descriptor
    before any agent code runs (5.2, step 5): no descriptor it holds answers
    SECCOMP_IOCTL_NOTIF_RECV, so it can't answer its own connection checks."""
    if entry == "on":
        code = "import hlyn\nhlyn.on(net=['api.example.com'], log=False)\n" + HUNT
    elif entry == "run":
        code = ("import hlyn\ndef hunt():\n    exec(" + repr(HUNT) + ", {})\n"
                "hlyn.run(hunt, net=['api.example.com'], log=False)\n")
    else:
        code = (f"import hlyn, sys\nhlyn.spawn([sys.executable, '-c', {HUNT!r}], "
                "net=['api.example.com'], log=False)\n")
    done = boot(code)
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "descriptors held: [" in done.stdout
    assert said(done.stdout, "descriptors that answer NOTIF_RECV") == "[]"


@linux
def test_a_program_left_running_keeps_its_network_after_the_command_exits(service, tmp_path):
    """The command exits while a process it started still runs: the gate
    hands the connection checks to a successor and exits with the command's
    status, so `hlyn run` returns at once; the background process's listed
    connection still works, and the successor exits after it."""
    out = tmp_path / "background.txt"
    started = time.monotonic()
    done = subprocess.run(
        [*HLYN, "run", "--no-log", "--no-report", "--net", f"localhost:{service.port}",
         "--write", str(tmp_path),
         "--", sys.executable, "-c", textwrap.dedent(f"""
            import os, socket, time
            if os.fork() == 0:
                # Let go of hlyn run's output, as a daemon would, so only
                # hlyn itself can keep the caller waiting.
                null = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(null, fd)
                time.sleep(1.5)
                try:
                    s = socket.create_connection(("127.0.0.1", {service.port}), timeout=5)
                    s.sendall(b"late"); got = s.recv(20).decode()
                except OSError as e:
                    got = f"REFUSED {{e}}"
                open({str(out)!r}, "w").write(got)
                os._exit(0)
            raise SystemExit(4)
         """)],
        capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/tmp",
    )
    took = time.monotonic() - started
    print(f"hlyn run returned {done.returncode} after {took:.2f} s", done.stderr[-500:])
    assert done.returncode == 4 and took < 1.5, "hlyn run waited for the background process"
    end = time.monotonic() + 15
    while not out.exists() and time.monotonic() < end:
        time.sleep(0.1)
    time.sleep(0.2)
    got = out.read_text() if out.exists() else "(nothing written)"
    print("background process, after the command had exited:", got)
    assert got == "hi late"
    time.sleep(1)
    left = subprocess.run(["ps", "-ww", "-eo", "pid,args"], capture_output=True, text=True,
                          check=False).stdout
    gates = [line for line in left.splitlines() if "main() gate" in line and "--child" in line]
    print("gates still running:", gates)
    assert gates == []


@linux
def test_row_21_host_mode_inside_host_mode_is_refused_with_the_reason():
    done = boot(f"""
import hlyn, subprocess, sys
inner = '''
import sys; sys.path.insert(0, {SRC!r})
import hlyn
try:
    hlyn.on(net=["api.example.com"], log=False)
    print("inner: SEALED")
except hlyn.Unsupported as e:
    print("inner refused:", e)
'''
def nested():
    return subprocess.run([sys.executable, "-c", inner], capture_output=True, text=True).stdout
print(hlyn.run(nested, net=["api.example.com"], exec=[sys.executable], read=[{SRC!r}], log=False))
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert "inner refused: can't restrict hosts here: this process is already inside a sandbox" in done.stdout
    assert ("Use ports (--net 443) or net=False here, or run hlyn outside it. "
            "Nothing was sealed.") in done.stdout


@linux
def test_a_bad_pointer_gets_the_kernels_answer_not_a_connection():
    done = boot("""
import ctypes, errno, socket, hlyn
hlyn.on(net=["api.example.com"], log=False)
libc = ctypes.CDLL(None, use_errno=True)
s = socket.socket()
rc = libc.connect(s.fileno(), ctypes.c_void_p(8), 16)
print("connect(fd, (void *)8, 16):", rc, errno.errorcode.get(ctypes.get_errno()))
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert said(done.stdout, "connect(fd, (void *)8, 16)") == "-1 EFAULT"


@linux
def test_probe_says_when_only_reduced_mode_is_possible(monkeypatch):
    from hlyn.cli import _machine
    from hlyn.core import linux as backend

    for scope in (None, 0, 1, 2, 3):
        monkeypatch.setattr(backend, "ptrace", lambda scope=scope: scope)
        got = backend.probe()
        text = _machine(got)
        print(f"ptrace_scope {scope}: hosts {got['hosts']}, reduced {got.get('reduced')!r}")
        if scope is not None and scope >= 2:
            assert got["reduced"].startswith(f"kernel.yama.ptrace_scope is {scope}")
            assert "note: host names work in reduced mode here" in text
        else:
            assert "reduced" not in got and "note:" not in text


@linux
def test_run_fn_with_hosts_costs_a_gate_start_per_call_and_nothing_more(service):
    """5.8: the proxy is shared; each call starts one small gate. Target:
    under 50 ms added per call after the first (section 9). Printed with the
    ports-only cost beside it; asserted against a loose bound."""
    done = boot(f"""
import time, hlyn
def timed(**policy):
    hlyn.run(lambda: 1, log=False, **policy)  # the first call starts the shared proxy
    began = time.perf_counter()
    for _ in range(20):
        hlyn.run(lambda: 1, log=False, **policy)
    return (time.perf_counter() - began) / 20 * 1000
ports = timed(net=[{service.port}])
named = timed(net=["localhost:{service.port}"])
print(f"per call: ports {{ports:.1f}} ms, hosts {{named:.1f}} ms, added {{named - ports:.1f}} ms")
import threading
stop = threading.Event()
# A caller with threads: its gate is a fresh interpreter.
threading.Thread(target=stop.wait, daemon=True).start()
ports = timed(net=[{service.port}])
named = timed(net=["localhost:{service.port}"])
print(f"per call, caller with threads: ports {{ports:.1f}} ms, hosts {{named:.1f}} ms, "
      f"added {{named - ports:.1f}} ms")
stop.set()
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    for label in ("per call", "per call, caller with threads"):
        line = said(done.stdout, label)
        added = float(line.split("added ")[1].split()[0])
        assert added < 250, line


@linux
def test_a_handoff_the_gate_cant_read_closes_the_descriptor_so_nothing_waits_forever():
    """If the config that comes with the notification descriptor can't be
    read, the gate must close the descriptor (the agent's connects then fail
    with ENOSYS) rather than hold it unanswered (they would wait forever)."""
    from hlyn import gate

    ours, theirs = socket.socketpair()
    read, write = os.pipe()
    socket.send_fds(ours, [b"not json"], [write])
    os.close(write)
    got = gate._take(theirs.detach())
    os.set_blocking(read, False)
    try:
        tail = os.read(read, 1)
    except BlockingIOError:
        tail = None
    print("guard:", got, "| the pipe's read end after _take:", tail, "| acknowledged:", ours.recv(1))
    assert got is None and tail == b""  # EOF: no copy of the write end is left


@linux
def test_a_failed_seal_after_the_gate_started_leaves_no_gate_behind():
    done = boot("""
import os, subprocess, time, hlyn
def gates():
    out = subprocess.run(["ps", "-ww", "-o", "pid=,args=", "--ppid", "1"],
                         capture_output=True, text=True).stdout
    return [line.split()[0] for line in out.splitlines() if "main() gate --child 0 --detach" in line]
before = gates()
try:
    hlyn.on(net=["api.example.com"], read=["/no/such/path"], log=False)
except hlyn.Invalid as e:
    print("refused:", str(e)[:60])
time.sleep(0.5)
print("sealed:", hlyn.sealed())
print("new gates left:", [pid for pid in gates() if pid not in before])
""")
    print(done.stdout, done.stderr[-800:], sep="\n")
    assert said(done.stdout, "refused").startswith("these paths could not be opened")
    assert said(done.stdout, "sealed") == "False"
    assert said(done.stdout, "new gates left") == "[]"


# ---------------------------------------------------------------------------
# Linux: what the gate refused, in the report and the log (5.9)
# ---------------------------------------------------------------------------

REFUSALS = """
import socket
for _ in range(5):
    try: socket.create_connection(("140.82.112.5", 443), timeout=3)
    except OSError: pass
try: socket.create_connection(("1.1.1.1", 53), timeout=3)
except OSError: pass
for path in ("/run/hlyn-test-private/app.sock", "DOCKER"):
    try: socket.socket(socket.AF_UNIX).connect(path)
    except OSError: pass
"""


@linux
@pytest.mark.parametrize("form", ["text", "json"])
def test_hlyn_run_lists_each_refusal_by_the_gate_once_with_its_flag(tmp_path, form):
    docker = str(tmp_path / "docker.sock")
    listening = socket.socket(socket.AF_UNIX)  # one that exists: a missing one is ENOENT, not a refusal
    listening.bind(docker)
    listening.listen(1)
    done = subprocess.run(
        [*HLYN, "run", "--no-log", *(["--json"] if form == "json" else []), "--net", "pypi.org",
         "--write", str(tmp_path), "--", sys.executable, "-c",
         REFUSALS.replace("DOCKER", docker) + "raise SystemExit(2)"],
        capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd=str(tmp_path),
    )
    print(done.stderr)
    assert done.returncode == 2
    if form == "json":
        report = json.loads(next(line for line in done.stderr.splitlines() if line.startswith('{"exit"')))
        gate = {row["target"]: row for row in report["blocked"] if row.get("source") == "gate"}
        print(json.dumps(gate, indent=1))
        assert gate["140.82.112.5:443"]["allow"] == "--net 140.82.112.5"
        assert gate["140.82.112.5:443"]["count"] == 5
        assert gate["1.1.1.1:53"]["allow"] is None
        private = gate["local socket /run/hlyn-test-private/app.sock"]
        assert private["allow"] == "--write /run/hlyn-test-private"
        assert gate[f"local socket {docker}"]["allow"] is None
        return
    lines = done.stderr.splitlines()
    assert sum("140.82.112.5" in line and "allow with" in line for line in lines) == 1
    assert any("140.82.112.5:443" in line and "allow with --net 140.82.112.5" in line
               and "[5 times]" in line for line in lines)
    assert any("1.1.1.1:53" in line and "DNS: the proxy looks up names" in line for line in lines)
    assert any("local socket /run/hlyn-test-private/app.sock" in line
               and "allow with --write /run/hlyn-test-private" in line for line in lines)
    assert any(f"local socket {docker}" in line and "never allowed with --net hosts" in line
               for line in lines)
    assert "  to allow all of these: --net 140.82.112.5 --write /run/hlyn-test-private" in lines


@linux
@pytest.mark.parametrize("entry", ["on", "run", "spawn"])
def test_the_gates_refusals_reach_the_log_from_every_entry_point(tmp_path, entry):
    log = str(tmp_path / "log.jsonl")
    docker = socket.socket(socket.AF_UNIX)  # one that exists: a missing one is ENOENT, not a refusal
    docker.bind(str(tmp_path / "docker.sock"))
    docker.listen(1)
    body = REFUSALS.replace("DOCKER", str(tmp_path / "docker.sock"))
    if entry == "on":
        code = f"import hlyn\nhlyn.on(net=['pypi.org'], log={log!r})\n" + body
    elif entry == "run":
        code = f"import hlyn\nhlyn.run(lambda: exec({body!r}, {{}}), net=['pypi.org'], log={log!r})\n"
    else:
        code = (f"import hlyn, sys\nhlyn.spawn([sys.executable, '-c', {body!r}], net=['pypi.org'], "
                f"log={log!r})\n")
    done = boot(code)
    time.sleep(0.5)
    rows = [row for row in records(log) if row["kind"] == "deny" and row.get("source") == "gate"]
    print(done.stderr[-500:], *rows, sep="\n")
    got = {(row["why"], row["target"]): row for row in rows}
    assert got[("direct", "140.82.112.5:443")]["allow"] == "--net 140.82.112.5"
    assert got[("direct", "140.82.112.5:443")]["by"].startswith("python")
    assert got[("dns", "1.1.1.1:53")]["allow"] is None
    assert got[("unix", "/run/hlyn-test-private/app.sock")]["allow"] == "--write /run/hlyn-test-private"
    assert got[("unix", str(tmp_path / "docker.sock"))]["allow"] == "--net-any"
    docker.close()
    # Five connects to the same address: written on the 1st, 2nd and 4th, the
    # way every hlyn log collapses repeats.
    seen = [row.get("seen", 1) for row in rows if row["target"] == "140.82.112.5:443"]
    assert seen == [1, 2, 4]


@linux
def test_a_program_that_looks_up_names_itself_is_told_how_to_use_the_proxy():
    """5.6, 5.7: with hosts there is no DNS. A client that ignores
    HTTPS_PROXY and resolves the name itself fails at the lookup; the report
    says why and which client setting fixes it. glibc's probe of a missing
    nscd socket on the way is the kernel's own ENOENT, not a refusal."""
    done = subprocess.run(
        [*HLYN, "run", "--no-log", "--net", "pypi.org", "--", sys.executable, "-c",
         "import socket\nsocket.create_connection(('api.github.com', 443), timeout=5)"],
        capture_output=True, text=True, env=ENV, timeout=120, check=False, cwd="/",
    )
    print(done.stderr)
    assert "Temporary failure in name resolution" in done.stderr or "Name or service not known" in done.stderr
    assert "a name lookup or QUIC (UDP)" in done.stderr
    assert "ignoring HTTPS_PROXY" in done.stderr and "aiohttp: trust_env=True" in done.stderr
    assert "nscd" not in done.stderr


FLOOD = """
import os, socket, statistics, sys, time
def timed(n=200):
    port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])
    took = []
    for _ in range(n):
        s = socket.socket()
        began = time.perf_counter()
        s.connect(("127.0.0.1", port))
        took.append(time.perf_counter() - began)
        s.close()
    return statistics.median(took) * 1e6
print("gate", os.getppid(), flush=True)
sys.stdin.readline()
before = timed()
refused = other = 0
for i in range(COUNT):
    s = socket.socket()
    try:
        s.connect(("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255), 443))
        other += 1
    except PermissionError:
        refused += 1
    except OSError:
        other += 1
    s.close()
after = timed()
print(f"flood: {refused} refused, {other} other; connect median {before:.0f} us before, {after:.0f} us after",
      flush=True)
sys.stdin.readline()
raise SystemExit(3)
"""


def rss(pid: int) -> int:
    with open(f"/proc/{pid}/status") as fh:
        return next(int(line.split()[1]) for line in fh if line.startswith("VmRSS:"))


@linux
def test_row_28_a_flood_of_distinct_addresses_is_refused_in_fixed_memory():
    count = int(os.environ.get("HLYN_FLOOD", "20000"))
    process = subprocess.Popen(
        [*HLYN, "run", "--no-log", "--json", "--net", "pypi.org", "--", sys.executable, "-c",
         FLOOD.replace("COUNT", str(count))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV, cwd="/",
    )
    gate = int(process.stdout.readline().split()[1])
    start = rss(gate)
    process.stdin.write("go\n")
    process.stdin.flush()
    line = process.stdout.readline()
    peak = rss(gate)
    _, err = process.communicate("done\n", timeout=600)
    report = json.loads(next(row for row in err.splitlines() if row.startswith('{"exit"')))
    listed = [row for row in report["blocked"] if row.get("source") == "gate"]
    print(line.strip())
    print(f"gate {gate}: {start} kB before the flood, {peak} kB after {count} distinct refusals")
    print(f"report: {len(listed)} listed, {report['more']} more counted, exit {report['exit']}")
    refused = int(line.split()[1])
    before, after = (float(part.split()[0]) for part in line.split("median ")[1].split(" before, "))
    assert refused == count
    assert peak - start < 8 * 1024, "the gate's memory grew with the number of refusals"
    # The report keeps 1000 lines of any kind; the rest are counted, not lost.
    assert len(listed) >= 990 and len(listed) + report["more"] == count
    assert after < max(2000.0, 3 * before), "connects slowed down after the flood"
