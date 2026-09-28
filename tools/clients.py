# SPDX-License-Identifier: Apache-2.0
"""The client matrix (DESIGN-host-allowlisting.md section 9; REMAINING #12).

Runs each HTTP client this machine has under `hlyn run` with host names in
`net`, twice: once against a listed host, which must work, and once against
a host that isn't listed, which must fail and be named in hlyn's report.
Every run's command, exit status, output and report are printed.

    python3 tools/clients.py [--python PY] [--hlyn 'CMD'] [NAME ...]

`--python` is an interpreter with requests, httpx, openai and anthropic
installed (default: this one); clients that aren't installed are skipped.
`--hlyn` is how to run hlyn (default: this tree's source, as `python -m
hlyn.cli`). Needs the internet. Every run starts in a scratch folder it may
read, since on macOS a program can't find its working folder otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
LISTED = "https://pypi.org/simple/six/"
UNLISTED = "https://example.org/"


@dataclass
class Client:
    name: str
    argv: list[str]  # "{url}" is replaced by the address to fetch
    hosts: list[str] = field(default_factory=lambda: ["pypi.org"])
    flags: list[str] = field(default_factory=list)
    ok: str = "200"  # printed on success
    blocked: bool = True  # also run against a host that isn't listed
    env: dict[str, str] = field(default_factory=dict)  # set, and kept with --env
    stderr: bool = False  # the client reports success on stderr (uv)


def which(name: str) -> str | None:
    places = [os.environ.get("PATH", ""), "/opt/homebrew/bin", "/usr/local/bin",
              os.path.expanduser("~/.local/bin")]
    return shutil.which(name, path=os.pathsep.join(places))


def prefix(py: str) -> str:
    """The environment `py` belongs to (a venv's folder holds its pyvenv.cfg)."""
    done = subprocess.run([py, "-c", "import sys; print(sys.prefix)"], capture_output=True, text=True,
                          check=True)
    return done.stdout.strip()


def clients(py: str, work: str) -> list[Client]:
    out: list[Client] = []
    fetch = "import sys, {m}; print({call})"
    for module, call in (
        ("urllib.request", "urllib.request.urlopen(sys.argv[1], timeout=30).status"),
        ("requests", "requests.get(sys.argv[1], timeout=30).status_code"),
        ("httpx", "httpx.get(sys.argv[1], timeout=30).status_code"),
    ):
        if subprocess.run([py, "-c", f"import {module}"], capture_output=True, check=False).returncode == 0:
            out.append(Client(module.split(".")[0], [py, "-c", fetch.format(m=module, call=call), "{url}"]))
    sdk = ("import sys\n{imp}\nclient = {make}\ntry:\n    client.models.list()\n    print('listed')\n"
           "except Exception as exc:\n    print(type(exc).__name__, getattr(exc, 'status_code', ''))\n")
    for module, host, imp, make in (
        ("openai", "api.openai.com", "from openai import OpenAI", "OpenAI(api_key='sk-hlyn-test-not-real')"),
        ("anthropic", "api.anthropic.com", "from anthropic import Anthropic",
         "Anthropic(api_key='sk-ant-hlyn-test-not-real')"),
    ):
        if subprocess.run([py, "-c", f"import {module}"], capture_output=True, check=False).returncode == 0:
            # A made-up key: reaching the API is shown by its 401.
            out.append(Client(f"{module} SDK", [py, "-c", sdk.format(imp=imp, make=make)], hosts=[host],
                              ok="AuthenticationError 401", blocked=False))
    curl = which("curl")
    if curl:
        out.append(Client("curl", [curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}\\n", "{url}"]))
    node = which("node")
    if node:
        script = ("fetch(process.argv[1]).then(r => console.log(r.status))"
                  ".catch(e => { console.log('failed', String(e.cause || e)); process.exit(1) })")
        out.append(Client("node fetch", [node, "-e", script, "{url}"]))
    git = which("git")
    if git:
        core = subprocess.run([git, "--exec-path"], capture_output=True, text=True, check=False).stdout
        # git stops when a configuration file exists and can't be read; this
        # run reads none rather than being granted the user's own.
        out.append(Client("git ls-remote", [git, "ls-remote", "https://github.com/git/git", "HEAD"],
                          hosts=["github.com"], flags=["--exec", core.strip()] if core.strip() else [],
                          ok="HEAD", blocked=False,
                          env={"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}))
    target = os.path.join(work, "pip-target")
    os.makedirs(target, exist_ok=True)
    if subprocess.run([py, "-m", "pip", "--version"], capture_output=True, check=False).returncode == 0:
        out.append(Client("pip download", [py, "-m", "pip", "download", "--no-deps", "--no-cache-dir",
                                           "--disable-pip-version-check", "-d", target, "six==1.16.0"],
                          hosts=["pypi.org", "files.pythonhosted.org"], flags=["--write", target],
                          ok="Saved", blocked=False))
    uv = which("uv")
    if uv:
        into, cache = os.path.join(work, "uv-target"), os.path.join(work, "uv-cache")
        for folder in (into, cache):
            os.makedirs(folder, exist_ok=True)
        out.append(Client("uv pip install",
                          [uv, "pip", "install", "--python", py, "--target", into, "--cache-dir", cache,
                           "six==1.16.0"],
                          hosts=["pypi.org", "files.pythonhosted.org"],
                          # uv runs the interpreter it installs for, to ask about it.
                          flags=["--write", into, "--write", cache, "--exec", os.path.realpath(py),
                                 "--read", prefix(py)],
                          ok="+ six==1.16.0", blocked=False, stderr=True))
    npm = which("npm")
    if npm and node:
        cache = os.path.join(work, "npm-cache")
        os.makedirs(cache, exist_ok=True)
        modules = os.path.dirname(os.path.dirname(os.path.realpath(npm)))  # .../lib/node_modules
        out.append(Client("npm view", [npm, "view", "left-pad", "version", "--cache", cache],
                          hosts=["registry.npmjs.org"],
                          flags=["--read", modules, "--write", cache, "--exec", node],
                          ok="1.3.0", blocked=False))
    return out


def run(hlyn: list[str], client: Client, url: str, work: str) -> tuple[int, str, str]:
    argv = [part.replace("{url}", url) for part in client.argv]
    command = [*hlyn, "run", "--no-log", "--read", work, *client.flags,
               *(item for name in client.env for item in ("--env", name)),
               *(item for host in client.hosts for item in ("--net", host)), "--", *argv]
    print(f"$ {shlex.join(command)}", flush=True)
    try:
        ours = hlyn[:3] == [sys.executable, "-m", "hlyn.cli"]  # this tree's hlyn, from its source
        env = {**os.environ, **({"PYTHONPATH": SRC} if ours else {}), **client.env}
        done = subprocess.run(command, capture_output=True, text=True, timeout=300, cwd=work, check=False,
                              env=env)
    except subprocess.TimeoutExpired as exc:
        return -1, str(exc.stdout or ""), f"timed out after 300 s\n{exc.stderr or ''}"
    return done.returncode, done.stdout, done.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description="Run each HTTP client under hlyn with hosts in net.")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--hlyn", default=None)
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    hlyn = shlex.split(args.hlyn) if args.hlyn else [sys.executable, "-m", "hlyn.cli"]
    work = os.path.realpath(tempfile.mkdtemp(prefix="hlyn-clients-"))
    results = []
    for client in clients(args.python, work):
        if args.names and client.name not in args.names:
            continue
        rc, out, err = run(hlyn, client, LISTED, work)
        worked = rc == 0 and client.ok in (out + err if client.stderr else out)
        print(f"exit {rc}\nstdout:\n{out}stderr:\n{err}", flush=True)
        refused = None
        if client.blocked:
            brc, bout, berr = run(hlyn, client, UNLISTED, work)
            print(f"exit {brc}\nstdout:\n{bout}stderr:\n{berr}", flush=True)
            refused = brc != 0 or "200" not in bout
            refused = refused and "example.org:443" in berr  # named in the report, with its flag
        results.append({"client": client.name, "listed host works": worked, "unlisted host refused": refused})
        said = "refused and reported" if refused else "NOT REFUSED"
        other = "" if refused is None else f"; unlisted host {said}"
        print(f"== {client.name}: listed host {'works' if worked else 'FAILED'}{other}\n", flush=True)
    print(json.dumps(results, indent=1))
    shutil.rmtree(work, ignore_errors=True)
    good = all(item["listed host works"] and item["unlisted host refused"] is not False for item in results)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
