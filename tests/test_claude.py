# SPDX-License-Identifier: Apache-2.0
"""`hlyn claude`, with the real Claude Code, against a scripted model.

No API key and no network: tests/claudemodel.py answers Claude Code's model
requests with a fixed list of tool calls, and records what each one returned.
The home folder is a throwaway one holding a fake SSH key, so nothing here
touches the real `~/.claude` or keychain.

Each session first proves something works (a write in the project lands, git
commits), so a run that refuses everything can't pass; and the same steps run
once without hlyn, where the key is read, so a refusal is hlyn's.
Skipped where Claude Code isn't installed.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys

import pytest
from claudemodel import Model
from conftest import SRC, enforces, skip_if_too_old

CLAUDE = shutil.which("claude")
pytestmark = [
    pytest.mark.skipif(CLAUDE is None, reason="Claude Code (claude) is not installed"),
    pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend"),
]

CANARY = "PRIVATE-KEY-CANARY"


@pytest.fixture
def place(tmp_path):
    """A throwaway home with a key and a git identity, and a project folder."""
    home, work = tmp_path / "home", tmp_path / "work"
    (home / ".ssh").mkdir(parents=True)
    work.mkdir()
    (home / ".ssh" / "id_ed25519").write_text(CANARY + "\n")
    (home / ".gitconfig").write_text("[user]\n\tname = Hlyn Test\n\temail = test@example.com\n")
    (home / ".claude.json").write_text("{}")
    return home, work


def session(steps, home, work, confined=True, *, prompt="go", more=(), flags=(), persist=False,
            output="json", **extra):
    """One `claude -p` session driven by `steps`; returns (process, model).
    `more` is added to Claude Code's arguments and `flags` to hlyn's; the
    session is kept on disk with `persist` (to resume it); `extra` sets
    variables, one set to None being left out."""
    with Model(steps) as model:
        env = {
            "HOME": str(home),
            "PATH": os.pathsep.join([os.path.dirname(CLAUDE), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
            "TERM": "dumb",
            "SHELL": "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh",
            "ANTHROPIC_BASE_URL": model.url,
            "ANTHROPIC_API_KEY": "sk-ant-not-a-real-key",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "PYTHONPATH": SRC,
        }
        env.update(extra)
        env = {k: v for k, v in env.items() if v is not None}
        if os.environ.get("HLYN_SHIM"):
            env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
        if os.geteuid() == 0:
            # Claude Code refuses to skip its permission prompts as root
            # unless told it runs in a container (the Linux test bed does).
            env["IS_SANDBOX"] = "1"
        args = ["-p", prompt, "--setting-sources", "", "--permission-mode", "bypassPermissions",
                "--model", "sonnet", "--output-format", output, *more]
        if output == "stream-json":
            args.append("--verbose")
        if not persist:
            args.append("--no-session-persistence")
        if confined:
            cmd = [sys.executable, "-m", "hlyn.cli", "claude", "--no-log", "--json", *flags, "--", *args]
        else:
            cmd = [CLAUDE, *args]
        done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                              timeout=180, stdin=subprocess.DEVNULL, check=False)
        skip_if_too_old(done)
        return done, model


def show(label, done, model, steps):
    print(f"--- {label}: exit {done.returncode}")
    for (tool, arguments), (error, text) in zip(steps, model.results(), strict=False):
        print(f"  {tool} {json.dumps(arguments)[:90]}\n    -> {'ERROR ' if error else ''}{text[:240]!r}")
    print("  stderr:", done.stderr[-2500:])


def blocked(done):
    """The JSON report's entries."""
    for line in done.stderr.splitlines():
        if line.startswith("{") and '"blocked"' in line:
            return json.loads(line)["blocked"]
    return []


def test_claude_code_works_and_cannot_reach_a_key_or_an_unlisted_host(place):
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    key = str(home / ".ssh" / "id_ed25519")
    steps = [
        ("Write", {"file_path": str(work / "out.txt"), "content": "hello"}),
        ("Bash", {"command": "git init -q && git commit -q --allow-empty -m first "
                             "&& git log --format=%an && echo GIT-OK"}),
        ("Read", {"file_path": key}),
        ("Bash", {"command": f"cat {key}"}),
        ("Bash", {"command": "curl -s -m 5 -o /dev/null -w 'got %{http_code}' https://example.com; echo"}),
    ]
    control, free = session(steps[2:3], home, work, confined=False)
    show("without hlyn", control, free, steps[2:3])
    done, model = session(steps, home, work)
    show("hlyn claude", done, model, steps)

    # Without hlyn the key is read: the refusals below are hlyn's.
    assert CANARY in free.results()[0][1], "the control run didn't read the key"

    assert done.returncode == 0, "Claude Code did not finish under hlyn claude"
    results = model.results()
    assert len(results) == len(steps), f"Claude Code ran {len(results)} of {len(steps)} steps"
    write, git, read, cat, curl = results
    assert not write[0] and (work / "out.txt").read_text() == "hello", "the write in the project didn't land"
    assert not git[0] and "Hlyn Test" in git[1] and "GIT-OK" in git[1], "git didn't work"
    refused = "EACCES" if sys.platform == "linux" else "EPERM"
    assert read[0] and refused in read[1], "the Read tool wasn't refused by the kernel"
    assert cat[0] and ("Permission denied" in cat[1] or "Operation not permitted" in cat[1])
    assert "got 000" in curl[1], "curl reached an unlisted host"
    assert any(e["kind"] == "net" and "example.com" in e["target"] for e in blocked(done)), \
        "the report didn't name the refused host"
    sent = json.dumps(model.requests())
    assert CANARY not in sent and CANARY not in done.stdout, "the key reached the model"


def test_a_setup_token_signs_in_without_the_keychain(place):
    # The way in on macOS, where the keychain stays closed: `claude setup-token`
    # once, then CLAUDE_CODE_OAUTH_TOKEN. The token reaches the model as a
    # bearer token, and hlyn has no sign-in note to print.
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    # The second step is what makes a kept token safer than an API key: Claude
    # Code holds it, but strips it from the programs its Bash tool starts
    # (an ANTHROPIC_API_KEY is passed through to them; measured).
    steps = [("Write", {"file_path": str(work / "out.txt"), "content": "hello"}),
             ("Bash", {"command": "env | grep -c CLAUDE_CODE_OAUTH_TOKEN; echo END"})]
    token = "sk-ant-oat01-not-a-real-token"  # noqa: S105 - a fake, for the scripted model
    done, model = session(steps, home, work, ANTHROPIC_API_KEY=None, CLAUDE_CODE_OAUTH_TOKEN=token)
    show("hlyn claude, signed in with a setup token", done, model, steps)
    print("  headers sent:", [{k: v for k, v in h.items() if k in ("authorization", "x-api-key")}
                              for h in model.headers])
    assert done.returncode == 0 and (work / "out.txt").read_text() == "hello"
    assert model.headers and all(h.get("authorization") == f"Bearer {token}" for h in model.headers)
    assert not any("x-api-key" in h for h in model.headers)
    shell = model.results()[1][1]
    assert shell.split() == ["0", "END"], f"the agent's shell saw the token: {shell!r}"
    # Claude Code still asks the keychain (the report lists it); hlyn's note
    # about signing in is what must not appear.
    assert "keeps its sign-in in the macOS keychain" not in done.stderr


def test_claude_config_dir_moves_its_state_and_saves_there(place):
    # With CLAUDE_CONFIG_DIR, Claude Code keeps .claude.json inside it, where
    # it can save; ~/.claude is never made.
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    state = home / "elsewhere"
    steps = [("Write", {"file_path": str(work / "out.txt"), "content": "hello"})]
    done, model = session(steps, home, work, CLAUDE_CONFIG_DIR=str(state))
    show("hlyn claude, CLAUDE_CONFIG_DIR", done, model, steps)
    saved = (state / ".claude.json").read_text() if (state / ".claude.json").exists() else ""
    print("  state folder:", sorted(p.name for p in state.iterdir()) if state.exists() else None,
          "\n  .claude.json:", saved[:160])
    assert done.returncode == 0 and (work / "out.txt").read_text() == "hello"
    assert len(saved) > 2, "Claude Code saved nothing in its state folder"
    assert not (home / ".claude").exists()


def interactive(steps, home, work, confined=True):
    """Claude Code's interactive screen on a pseudo-terminal, typed at the
    way a person would: dismiss the first question it asks, type `go`, press
    Enter, wait for the steps, then Ctrl-C twice. Returns (model, screen)."""
    import json as _json
    import pty
    import select
    import time

    key = "sk-ant-api03-not-a-real-key-0123456789abcdefghij"
    # Answers to the questions a first start asks, so the session reaches its
    # prompt. Under hlyn they can't be saved (~/.claude.json is read-only).
    (home / ".claude.json").write_text(_json.dumps({
        "hasCompletedOnboarding": True, "bypassPermissionsModeAccepted": True,
        "customApiKeyResponses": {"approved": [key[-20:]], "rejected": []},
        "projects": {os.path.realpath(work): {"hasTrustDialogAccepted": True,
                                              "hasCompletedProjectOnboarding": True}},
    }))
    screen = bytearray()

    def pump(fd, seconds):
        end = time.time() + seconds
        while time.time() < end:
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    screen.extend(os.read(fd, 65536))
                except OSError:
                    return

    def send(fd, data):
        with contextlib.suppress(OSError):
            os.write(fd, data)

    with Model(steps) as model:
        env = {
            "HOME": str(home), "TERM": "xterm-256color", "SHELL": "/bin/sh",
            "PATH": os.pathsep.join([os.path.dirname(CLAUDE), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
            "ANTHROPIC_BASE_URL": model.url, "ANTHROPIC_API_KEY": key, "PYTHONPATH": SRC,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            **({"HLYN_SHIM": os.environ["HLYN_SHIM"]} if os.environ.get("HLYN_SHIM") else {}),
            **({"IS_SANDBOX": "1"} if os.geteuid() == 0 else {}),
        }
        args = ["--permission-mode", "bypassPermissions", "--model", "sonnet"]
        argv = ([sys.executable, "-m", "hlyn.cli", "claude", "--no-log", "-y", "--", *args]
                if confined else [CLAUDE, *args])
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(work)
            os.execve(argv[0], argv, env)  # noqa: S606
        try:
            pump(fd, 6)
            send(fd, b"\x1b")  # Esc: "not now" to whatever it asks first
            pump(fd, 1.5)
            send(fd, b"go")
            pump(fd, 1.5)
            send(fd, b"\r")
            for _ in range(60):
                pump(fd, 0.5)
                if len(model.results()) >= len(steps):
                    break
            pump(fd, 1)
            send(fd, b"\x03")
            pump(fd, 0.5)
            send(fd, b"\x03")
            pump(fd, 3)
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)
            os.waitpid(pid, 0)
            os.close(fd)
        return model, screen.decode("utf-8", "replace")


def test_interactive_claude_code_works_and_cannot_reach_a_key(place):
    # The way people use it: the full-screen session on a terminal. Before
    # macOS allowed terminal control (raw mode), keys were echoed and never
    # read, and the session never sent a request.
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    key = str(home / ".ssh" / "id_ed25519")
    steps = [("Write", {"file_path": str(work / "out.txt"), "content": "hello"}),
             ("Read", {"file_path": key})]
    free, _ = interactive(steps, home, work, confined=False)
    (work / "out.txt").unlink(missing_ok=True)
    model, screen = interactive(steps, home, work)
    for label, m in (("without hlyn", free), ("hlyn claude", model)):
        print(f"--- {label}: {len(m.requests())} requests")
        for (tool, _), (error, text) in zip(steps, m.results(), strict=False):
            print(f"  {tool} -> {'ERROR ' if error else ''}{text[:160]!r}")
    if len(model.results()) < len(steps):
        print("screen:", screen[-3000:])
    assert len(free.results()) == 2 and CANARY in free.results()[1][1], "the control run didn't read the key"
    assert len(model.results()) == 2, "the session under hlyn claude didn't run both steps"
    write, read = model.results()
    assert not write[0] and (work / "out.txt").read_text() == "hello"
    assert read[0] and ("EACCES" if sys.platform == "linux" else "EPERM") in read[1]
    assert CANARY not in json.dumps(model.requests())


# --- what a real Claude Code session does beyond its first prompt -------------
# Measured 2026-10-01 against Claude Code 2.1.269 (macOS) and 2.1.286 (Linux);
# FINDINGS.md, "`hlyn claude` beyond the first prompt".

MARK = "FIRST-PROMPT-MARK"


def test_resume_continues_a_session_that_was_started_under_hlyn(place):
    # The session file goes to the state folder, which is granted, and
    # --resume reads it back: the model is sent the first prompt again.
    if not enforces():
        pytest.skip("this machine can't enforce")
    import uuid

    home, work = place
    sid = str(uuid.uuid4())
    first, one = session([], home, work, prompt=f"{MARK} say hi", more=["--session-id", sid], persist=True)
    show("first session", first, one, [])
    kept = list((home / ".claude" / "projects").rglob(f"{sid}.jsonl"))
    assert first.returncode == 0 and len(kept) == 1, "the session was not kept in the state folder"
    second, two = session([], home, work, prompt="and now more", more=["--resume", sid], persist=True)
    show("resumed session", second, two, [])
    assert second.returncode == 0
    assert MARK in json.dumps(two.requests()), "the resumed session did not carry the first prompt"
    assert json.loads(second.stdout)["session_id"] == sid
    assert len(list((home / ".claude" / "projects").rglob("*.jsonl"))) == 1, "a second session file was made"


STDIO_SERVER = '''
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": "demo", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "ping", "description": "say pong",
                             "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "MCP-PONG"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
'''


def mcp_config(work, servers):
    path = work / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return ["--mcp-config", str(path), "--strict-mcp-config"]


def test_an_mcp_server_that_runs_as_a_program_starts_and_answers(place):
    # A stdio server is a program Claude Code starts: confined like the rest,
    # it needs nothing but to run.
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    (work / "mcp_stdio.py").write_text(STDIO_SERVER)
    use = mcp_config(work, {"demo": {"command": sys.executable, "args": [str(work / "mcp_stdio.py")]}})
    steps = [("ping", {})]
    free, plain = session(steps, home, work, confined=False, more=use)
    show("without hlyn", free, plain, steps)
    done, model = session(steps, home, work, more=use)
    show("hlyn claude", done, model, steps)
    assert plain.results() == [(False, "text\nMCP-PONG")], "the control run didn't reach the server"
    assert done.returncode == 0 and model.results() == [(False, "text\nMCP-PONG")]


def web_mcp_server():
    """A local HTTP MCP server (one JSON reply per POST), on a free port."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if "id" not in msg:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            method = msg["method"]
            if method == "initialize":
                result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                          "serverInfo": {"name": "web", "version": "1"}}
            elif method == "tools/list":
                result = {"tools": [{"name": "ping", "description": "pong",
                                     "inputSchema": {"type": "object", "properties": {}}}]}
            elif method == "tools/call":
                result = {"content": [{"type": "text", "text": "HTTP-MCP-PONG"}]}
            else:
                result = {}
            body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_an_mcp_server_on_this_machine_needs_its_port_and_the_report_says_so(place):
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    server = web_mcp_server()
    try:
        port = server.server_port
        use = mcp_config(work, {"web": {"type": "http", "url": f"http://127.0.0.1:{port}/mcp"}})
        steps = [("ping", {})]
        _free, plain = session(steps, home, work, confined=False, more=use)
        assert plain.results() == [(False, "text\nHTTP-MCP-PONG")], "the control run didn't reach the server"
        shut, none = session(steps, home, work, more=use)
        show("without --net", shut, none, steps)
        assert none.results() == [], "the server answered without being allowed"
        said = [e for e in blocked(shut) if e["kind"] == "net" and str(port) in e["target"]]
        assert said and f"--net localhost:{port}" in (said[0]["allow"] or "") + said[0]["note"], \
            f"the report didn't name the flag: {blocked(shut)}"
        done, model = session(steps, home, work, more=use, flags=["--net", f"localhost:{port}"])
        show(f"--net localhost:{port}", done, model, steps)
        assert done.returncode == 0 and model.results() == [(False, "text\nHTTP-MCP-PONG")]
    finally:
        server.shutdown()
        server.server_close()


def test_a_remote_mcp_server_is_refused_with_the_flag_that_allows_it(place):
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    use = mcp_config(work, {"web": {"type": "http", "url": "https://mcp.example.test/mcp"}})
    done, model = session([("ping", {})], home, work, more=use)
    show("hlyn claude", done, model, [("ping", {})])
    assert model.results() == []
    said = [e for e in blocked(done) if e["kind"] == "net" and e["target"] == "mcp.example.test:443"]
    assert said and said[0]["allow"] == "--net mcp.example.test"


def plugin(root):
    (root / ".claude-plugin").mkdir(parents=True)
    (root / "skills" / "hello").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demoplug", "version": "1.0.0", "description": "a plugin"}))
    (root / "skills" / "hello" / "SKILL.md").write_text(
        "---\nname: hello\ndescription: say hello\n---\nHi.\n")
    return str(root)


def loaded(done):
    """The plugins Claude Code reports at the start of a stream-json session,
    leaving out the ones built into it (newer versions list those too)."""
    for line in done.stdout.splitlines():
        if line.startswith("{") and '"init"' in line:
            event = json.loads(line)
            if event.get("subtype") == "init":
                return [item["name"] for item in event.get("plugins", []) if item.get("path") != "builtin"]
    return None


def test_a_plugin_in_the_project_loads_and_one_elsewhere_needs_read(place, tmp_path):
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    inside, outside = plugin(work / "plug"), plugin(tmp_path / "elsewhere" / "plug")
    done, model = session([], home, work, more=["--plugin-dir", inside], output="stream-json")
    show("plugin in the project", done, model, [])
    assert done.returncode == 0 and loaded(done) == ["demoplug"]
    done, model = session([], home, work, more=["--plugin-dir", outside], output="stream-json")
    show("plugin outside the project", done, model, [])
    assert loaded(done) == [], "a plugin outside every grant was loaded"
    if sys.platform == "darwin":
        # Linux can't see inside Claude Code's static binary (README, "Reports are not complete"),
        # so there the refusal is real but unreported.
        read = [e for e in blocked(done) if e["kind"] == "read" and "elsewhere" in e["target"]]
        assert read and all(e["allow"] and e["allow"].startswith("--read ") for e in read)
    done, model = session([], home, work, more=["--plugin-dir", outside], output="stream-json",
                          flags=["--read", outside])
    show("plugin outside, with --read", done, model, [])
    assert done.returncode == 0 and loaded(done) == ["demoplug"]


PROVIDERS = [
    # (name, variables set, the one to pass with --env, host without it, host with it)
    ("vertex", {"CLAUDE_CODE_USE_VERTEX": "1", "CLOUD_ML_REGION": "europe-west1",
                "ANTHROPIC_VERTEX_PROJECT_ID": "demo-project", "CLAUDE_CODE_SKIP_VERTEX_AUTH": "1"},
     "CLOUD_ML_REGION", "us-east5-aiplatform.googleapis.com", "europe-west1-aiplatform.googleapis.com"),
    ("bedrock", {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "eu-west-1",
                 "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1"},
     "AWS_REGION", "bedrock-runtime.us-east-1.amazonaws.com", "bedrock-runtime.eu-west-1.amazonaws.com"),
    ("foundry", {"CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_RESOURCE": "demo-resource",
                 "CLAUDE_CODE_SKIP_FOUNDRY_AUTH": "1"},
     None, "demo-resource.services.ai.azure.com", "demo-resource.services.ai.azure.com"),
]


@pytest.mark.parametrize(("name", "variables", "passed", "plain", "regional"), PROVIDERS,
                         ids=[p[0] for p in PROVIDERS])
def test_a_cloud_provider_is_refused_naming_its_host_and_the_region_needs_env(
        place, name, variables, passed, plain, regional):
    # Bedrock, Vertex and Foundry send to their own hosts, not api.anthropic.com. hlyn
    # allows only the Anthropic ones, so the report names the host to add; a region
    # set in a variable that isn't ANTHROPIC_* or CLAUDE_* only counts with --env.
    # No credentials are needed: the SKIP_*_AUTH variables stand in for them, and the
    # request never leaves because the proxy refuses it first.
    if not enforces():
        pytest.skip("this machine can't enforce")
    home, work = place
    extra = {**variables, "ANTHROPIC_BASE_URL": None, "ANTHROPIC_API_KEY": None,
             "CLAUDE_CODE_MAX_RETRIES": "0"}
    done, model = session([], home, work, **extra)
    show(f"{name}, no --env", done, model, [])
    hosts = {e["target"].removesuffix(":443"): e["allow"] for e in blocked(done) if e["kind"] == "net"}
    assert plain in hosts and hosts[plain] == f"--net {plain}", f"the host to allow wasn't named: {hosts}"
    assert model.requests() == [], "something reached the Anthropic API stand-in"
    if passed is None:
        return
    done, model = session([], home, work, flags=["--env", passed], **extra)
    show(f"{name}, --env {passed}", done, model, [])
    hosts = {e["target"].removesuffix(":443"): e["allow"] for e in blocked(done) if e["kind"] == "net"}
    assert regional in hosts and hosts[regional] == f"--net {regional}", f"--env didn't reach it: {hosts}"
    assert plain not in hosts or plain == regional
