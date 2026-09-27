# SPDX-License-Identifier: Apache-2.0
"""Phase 3 groundwork: what a macOS host-mode profile must and must not grant.

A prototype of the host-mode Seatbelt profile (design 5.4): hlyn's base
profile with the blanket `(allow mach-lookup)` removed, no mDNSResponder,
and TCP allowed only to the proxy's port. Each client then runs through a
real proxy (`python -m hlyn.proxy`, unsealed here) with HTTPS_PROXY set, and
the script prints what worked and what the sandbox refused (from `log
stream`, scoped by a tag, as oslog.py does).

    python3 tools/hostlab/hostmode.py            # every probe
    python3 tools/hostlab/hostmode.py curl git   # some

Questions it answers:
  1. Do Python, curl, git and node need any Mach service in host mode?
  2. Does `localhost` resolve with no mDNSResponder (so a direct client can
     use a `localhost:PORT` entry by name)?
  3. Does SBPL accept `(regex ...)` for unix-socket paths, and does a later
     deny win over an earlier subpath allow?
"""
import json, os, re, select, socket, subprocess, sys, tempfile, threading, time, uuid

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src")
sys.path.insert(0, ROOT)
from hlyn.core import mac  # noqa: E402
from hlyn.policy import Policy  # noqa: E402

H = os.path.expanduser("~")
TMP = os.path.realpath(tempfile.mkdtemp(prefix="hostmode-"))


def profile(port, tag, extra=()):
    base = mac.profile(Policy(read=True, write=(TMP, "/dev"), exec=True, net=False, env=True), tag)
    base = base.replace("(allow mach-lookup)\n", "")
    return "\n".join([base, f'(allow network-outbound (remote tcp "localhost:{port}"))', *extra])


def denials(tag, run):
    """Run `run()` while streaming the log; return the Sandbox lines tagged `tag`."""
    stream = subprocess.Popen(["/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
                               'sender == "Sandbox"'], stdout=subprocess.PIPE, text=True)
    time.sleep(1.5)  # crude: oslog.py proves readiness with a marker; enough for a lab
    out = run()
    time.sleep(1.5)
    stream.terminate()
    lines = stream.communicate(timeout=5)[0].splitlines()
    found = []
    for line in lines:
        try:
            message = json.loads(line).get("eventMessage", "")
        except ValueError:
            continue
        if message.endswith("\n" + tag):
            found.append(message.rsplit("\n", 1)[0])
    return out, found


def start_proxy(*entries):
    exe = [sys.executable, "-m", "hlyn.proxy", "--json", "--stay"] + [x for e in entries for x in ("--net", e)]
    # Unsealed on purpose here: the question is the agent's profile, not the proxy's.
    code = ("import sys; sys.path.insert(0, %r); import hlyn.proxy as p; p.seal = lambda: 'lab';"
            "sys.exit(p.main(sys.argv[1:]))" % ROOT)
    proc = subprocess.Popen([sys.executable, "-c", code, "--json", "--stay",
                             *[x for e in entries for x in ("--net", e)]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready = json.loads(proc.stdout.readline())
    return proc, ready["port"]


def run(name, cmd, port, extra=(), env=None):
    tag = "hostmode-" + uuid.uuid4().hex[:8]
    text = profile(port, tag, extra)
    url = f"http://127.0.0.1:{port}"
    where = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": H, "TMPDIR": TMP,
             "HTTPS_PROXY": url, "HTTP_PROXY": url, "https_proxy": url, "http_proxy": url,
             "NO_PROXY": "localhost,127.0.0.1,::1", "NODE_USE_ENV_PROXY": "1", **(env or {})}

    def go():
        return subprocess.run(["/usr/bin/sandbox-exec", "-p", text, *cmd], capture_output=True,
                              text=True, timeout=60, env=where)

    done, seen = denials(tag, go)
    tail = (done.stdout + done.stderr).strip().splitlines()[-2:]
    print(f"== {name}: exit {done.returncode}; output {tail}")
    for line in sorted(set(seen)):
        print(f"   denied: {line}")
    return done.returncode, seen


PY = sys.executable
PROBES = {
    "python-start": [PY, "-c", "print('up')"],
    "python-https": [PY, "-c", "import urllib.request as u; print(u.urlopen('https://example.com', timeout=20).status)"],
    "curl": ["/usr/bin/curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"],
    "git": ["/opt/homebrew/bin/git", "ls-remote", "https://github.com/git/git", "HEAD"],
    "node": ["/opt/homebrew/bin/node", "-e",
             "fetch('https://example.com').then(r=>console.log(r.status)).catch(e=>{console.log(String(e.cause||e));process.exit(1)})"],
    "python-subprocess": [PY, "-c", "import subprocess; print(subprocess.run(['/bin/echo','child'],capture_output=True,text=True).stdout.strip())"],
    # 2: localhost by name, with no resolver socket
    "localhost-lookup": [PY, "-c", "import socket; print(socket.getaddrinfo('localhost', 5432, type=socket.SOCK_STREAM))"],
    "name-lookup": [PY, "-c", "import socket; print(socket.getaddrinfo('example.com', 443))"],
}


def lookup_and_localhost(port):
    # A local "database" on a listed localhost port, reached directly by name.
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen()
    db = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].sendall(b"db-hello"), daemon=True).start()
    run("localhost-direct-by-name", [PY, "-c",
        f"import socket; s=socket.create_connection(('localhost',{db}),timeout=5); print(s.recv(8))"],
        port, extra=[f'(allow network-outbound (remote tcp "localhost:{db}"))'])
    srv.close()


def unix_rules(port):
    # 3: does a regex path filter compile for unix sockets, and does a later deny win?
    folder = os.path.join(TMP, "run")
    os.makedirs(folder, exist_ok=True)
    for name in ("ok.sock", "docker.sock"):
        path = os.path.join(folder, name)
        s = socket.socket(socket.AF_UNIX); s.bind(path); s.listen()
        threading.Thread(target=lambda s=s: [s.accept() for _ in range(4)], daemon=True).start()
    code = ("import socket,sys\nfor n in ('ok.sock','docker.sock'):\n s=socket.socket(socket.AF_UNIX)\n"
            f" try: s.connect('{folder}/'+n); print(n,'connected')\n except OSError as e: print(n,e)")
    run("unix subpath + later regex deny", [PY, "-c", code], port, extra=[
        f'(allow network-outbound (remote unix-socket (subpath "{folder}")))',
        '(deny network-outbound (remote unix-socket (regex #"/docker\\.sock$")))',
    ])
    run("unix path-regex form", [PY, "-c", code], port, extra=[
        f'(allow network-outbound (remote unix-socket (subpath "{folder}")))',
        '(deny network-outbound (remote unix-socket (path-regex #"/docker\\.sock$")))',
    ])


if __name__ == "__main__":
    proxy, port = start_proxy("example.com", "github.com", "localhost:9")
    try:
        only = sys.argv[1:]
        for name, cmd in PROBES.items():
            if not only or name in only:
                run(name, cmd, port)
        if not only or "localhost" in only:
            lookup_and_localhost(port)
        if not only or "unix" in only:
            unix_rules(port)
    finally:
        proxy.terminate()
