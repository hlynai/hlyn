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


def session(steps, home, work, confined=True):
    """One `claude -p` session driven by `steps`; returns (process, model)."""
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
        if os.environ.get("HLYN_SHIM"):
            env["HLYN_SHIM"] = os.environ["HLYN_SHIM"]
        if os.geteuid() == 0:
            # Claude Code refuses to skip its permission prompts as root
            # unless told it runs in a container (the Linux test bed does).
            env["IS_SANDBOX"] = "1"
        args = ["-p", "go", "--setting-sources", "", "--permission-mode", "bypassPermissions",
                "--model", "sonnet", "--output-format", "json", "--no-session-persistence"]
        if confined:
            cmd = [sys.executable, "-m", "hlyn.cli", "claude", "--no-log", "--json", "--", *args]
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
