# SPDX-License-Identifier: Apache-2.0
"""Which Mach services does each client need? Run it under hlyn's own profile
with the blanket mach-lookup replaced by an allowlist, grow the allowlist from
the Sandbox denials until the client succeeds, and report the minimum."""
import json, os, re, subprocess, sys, time, uuid
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from hlyn.core import mac
from hlyn.policy import Policy

M = os.path.dirname(os.path.abspath(__file__))  # holds fetch (swiftc -O fetch.swift -o fetch) and leaf.pem (certs.sh)
H = os.path.expanduser("~")
POLICY = Policy(read=True, write=("/private/tmp", "/dev"), exec=True, net=(443,), env=True)
CLIENTS = {
    "curl":      ["/usr/bin/curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"],
    "python":    [sys.executable, "-c", "import urllib.request as u; print(u.urlopen('https://example.com').status)"],
    "node":      ["/opt/homebrew/bin/node", "-e", "fetch('https://example.com').then(r=>console.log(r.status)).catch(e=>{console.log(e.cause||e);process.exit(1)})"],
    "git":       ["/opt/homebrew/bin/git", "ls-remote", "https://github.com/git/git", "HEAD"],
    "swift":     [f"{M}/fetch", "https://example.com"],
    "security":  ["/usr/bin/security", "verify-cert", "-c", f"{M}/leaf.pem", "-p", "ssl", "-s", "leak.example"],
}

def run(cmd, allow):
    tag = "machlab-" + uuid.uuid4().hex[:8]
    text = mac.profile(POLICY, tag)
    grants = "".join(f' (global-name "{n}")' for n in sorted(allow))
    if cmd[0].endswith("/fetch"):
        text += "\n(allow file-write* (subpath \"%s/Library/Caches/fetch\"))\n(allow ipc-posix-shm-read-data)\n(allow system-info)\n(allow file-ioctl)" % H
    text = text.replace("(allow mach-lookup)", f"(allow mach-lookup{grants})" if allow else "")
    start = time.strftime("%Y-%m-%d %H:%M:%S")
    p = subprocess.run(["/usr/bin/sandbox-exec", "-p", text, *cmd], capture_output=True, text=True, timeout=60, env={**os.environ, "HOME": H})
    time.sleep(1.5)
    log = subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--start", start, "--predicate",
                          f'sender == "Sandbox" AND eventMessage CONTAINS "{tag}"'], capture_output=True, text=True).stdout
    denied = set(re.findall(r"deny\(\d+\) mach-lookup (\S+)", log))
    return p.returncode, (p.stdout + p.stderr).strip().splitlines()[-1:] , denied

only = sys.argv[1:] or list(CLIENTS)
out = {}
for name in only:
    cmd = CLIENTS[name]
    allow, seen = set(), []
    for rnd in range(12):
        rc, tail, denied = run(cmd, allow)
        seen.append({"round": rnd, "rc": rc, "tail": tail, "denied": sorted(denied)})
        new = denied - allow
        if rc == 0 or not new:
            break
        allow |= new
    # Minimise: drop each grant in turn, keep it only if the client then fails.
    need = set(allow)
    if rc == 0:
        for n in sorted(allow):
            r2, _, _ = run(cmd, need - {n})
            if r2 == 0:
                need.discard(n)
    out[name] = {"ok": rc == 0, "tail": tail, "denied_first_round": seen[0]["denied"], "needed": sorted(need), "rounds": len(seen)}
    print(name, json.dumps(out[name], indent=1), flush=True)
json.dump(out, open(f"{M}/machlab.json", "w"), indent=1)
