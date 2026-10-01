# SPDX-License-Identifier: Apache-2.0
"""`hlyn claude`: Claude Code, confined, in one command.

    hlyn claude                        Claude Code in this folder
    hlyn claude --read ~/docs          plus one more readable folder
    hlyn claude -- --resume            arguments after -- go to claude

Everything here was measured by running the real Claude Code under hlyn against
a scripted model (tests/claudemodel.py) and reading what was refused. Claude
Code gets:

- this folder, to read and write: the project it works on;
- its own state folder (`CLAUDE_CONFIG_DIR`, or `~/.claude`), to write;
- `~/.claude.json`, to read only. Claude Code saves it through a temporary
  file and a lock beside it, in the home folder, which no grant short of the
  whole home folder allows; and it lists the MCP servers Claude Code starts,
  outside any environment, the next time it runs without hlyn;
- its own installation, to read; any program, to run (file access stays
  confined: running a program never grants reading anything);
- the network: the model API and the sign-in refresh, and nothing else.
  `ANTHROPIC_BASE_URL` replaces the model API when set;
- its variables (`ANTHROPIC_*`, `CLAUDE_*`, `SHELL`, `IS_SANDBOX`), with every
  other secret removed;
- a private temporary folder, named in `CLAUDE_CODE_TMPDIR`: Claude Code
  ignores `TMPDIR` and uses /tmp unless told otherwise.

Each flag adds to this, as for `hlyn run`.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from collections.abc import MutableMapping
from urllib.parse import urlsplit

from .error import Error
from .policy import Policy

__all__ = ["HOSTS", "command", "policy", "prepare", "signin", "state"]

# The model API, and the host that refreshes a signed-in session's token
# (TOKEN_URL in Claude Code 2.1). Nothing else: CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC
# turns off what would otherwise go to telemetry, error reports and updates.
HOSTS: tuple[str, ...] = ("api.anthropic.com", "platform.claude.com")

# System shell start-up files, read by the shell Claude Code's Bash tool
# starts (and, on macOS, the PATH list its path_helper reads). World-readable
# configuration, no secrets; refused, each command reports them.
SHELLS: tuple[str, ...] = (
    "/etc/profile", "/etc/zprofile", "/etc/zshrc", "/etc/zshenv", "/etc/bashrc", "/etc/bash.bashrc",
    "/etc/paths", "/etc/paths.d", "/etc/profile.d",
)

# git's configuration. git stops ("fatal: unable to access") when a config
# file exists and can't be read, so without these every git command fails for
# anyone with a ~/.gitconfig, or with Homebrew's git. `~/.git-credentials`
# stays closed.
GIT: tuple[str, ...] = (
    "/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig",
    "~/.gitconfig", "~/.config/git",
)

# macOS: /usr/bin/git and the other developer tools are stubs that run the
# real ones from here, and git reads iconv's tables. CoreFoundation reads
# ~/.CFUserTextEncoding (the user's text encoding) in every program.
TOOLS: tuple[str, ...] = (
    "/Library/Developer/CommandLineTools", "/Applications/Xcode.app", "/usr/share/i18n",
    "~/.CFUserTextEncoding",
)

# Linux: kernel settings Claude Code's runtime (Bun) reads to size its memory,
# refused on every run otherwise. Single files of numbers, nothing per process.
# (It also needs its own /proc/self: `cli._own`.)
KERNEL: tuple[str, ...] = (
    "/sys/kernel/mm/transparent_hugepage/enabled", "/proc/sys/vm/mmap_min_addr",
    "/proc/sys/vm/overcommit_memory", "/sys/devices/system/cpu/online",
)


def _limits() -> list[str]:
    """Linux: the memory and CPU limits of the cgroup hlyn runs in, which the
    command starts in too, read by Bun the same way."""
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as fh:
            line = next((row for row in fh if row.startswith("0::")), "")
    except OSError:
        return []
    where = os.path.join("/sys/fs/cgroup", line[3:].strip().lstrip("/"))
    return [os.path.join(where, name) for name in ("memory.max", "memory.high", "cpu.max")]


def command(args: list[str]) -> list[str]:
    """`claude` from PATH, with the arguments meant for it."""
    found = shutil.which("claude")
    if not found:
        raise Error(
            "claude is not on PATH. Install Claude Code (https://code.claude.com/docs/en/setup), "
            "or run another build with hlyn run -- /path/to/claude."
        )
    return [found, *args]


def state(env: MutableMapping[str, str]) -> str:
    """Where Claude Code keeps its own settings, sessions and hooks."""
    return env.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")


def _model(env: MutableMapping[str, str]) -> str:
    """The `net` entry for ANTHROPIC_BASE_URL, or the API's own host."""
    url = env.get("ANTHROPIC_BASE_URL")
    if not url:
        return HOSTS[0]
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Error(f"ANTHROPIC_BASE_URL is {url!r}, not an http(s) URL hlyn can allow.")
    host = parts.hostname
    if host in ("127.0.0.1", "::1"):
        host = "localhost"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{host}:{port}"


def policy(binary: str, env: MutableMapping[str, str], tmp: str) -> Policy:
    """What Claude Code needs, measured, as a policy. `tmp` is the folder
    `prepare` made: hlyn's private temporary folder and Claude Code's."""
    cwd = os.getcwd()
    mine = state(env)
    # The installation, by both names: `claude` is usually a link in a bin
    # folder (`~/.local/bin`) pointing at the version it runs, and Claude Code
    # lists both while starting.
    read = [cwd, os.path.dirname(os.path.realpath(binary)), os.path.dirname(binary)]
    if not env.get("CLAUDE_CONFIG_DIR"):
        dotfile = os.path.join(os.path.expanduser("~"), ".claude.json")
        if os.path.exists(dotfile):
            read.append(dotfile)
    # The terminal the person started it on. The shell Claude Code's Bash tool
    # runs opens it for job control and prompts, and reports a refusal on every
    # command without it. Typing into it stays refused by both kernels
    # (`TIOCSTI`; FINDINGS.md, "Terminal control"), which is the dangerous part.
    extra = [*SHELLS, *GIT, "/dev/tty"]
    if sys.platform == "darwin":
        extra += TOOLS
    elif sys.platform == "linux":
        extra += [*KERNEL, *_limits()]
    read += [path for path in map(os.path.expanduser, extra) if os.path.exists(path)]
    keep = sorted(
        name for name in env
        if name.startswith(("ANTHROPIC_", "CLAUDE_"))
        or name in ("DISABLE_TELEMETRY", "IS_SANDBOX", "SHELL", "TMPPREFIX", "xcrun_db")
    )
    return Policy(
        read=tuple(read),
        write=(cwd, mine, *(["/dev/tty"] if os.path.exists("/dev/tty") else [])),
        exec=True,
        net=(_model(env), *HOSTS[1:]),
        env=tuple(keep),
        tmp=tmp,
    )


# Ways to sign in that don't need the keychain.
SIGNINS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
)


def signin(env: MutableMapping[str, str]) -> str | None:
    """macOS: a note when Claude Code's sign-in can only be in the keychain.

    Claude Code reads it with the `security` tool, and the keychain stays
    closed: opening it lets the agent's `security` read every item that tool
    may read (other command-line tools' tokens too), not just Claude Code's.
    """
    if sys.platform != "darwin" or any(env.get(name) for name in SIGNINS):
        return None
    if os.path.exists(os.path.join(state(env), ".credentials.json")):
        return None  # signed in without the keychain
    return (
        "hlyn: Claude Code keeps its sign-in in the macOS keychain, which stays closed to the agent "
        "(opening it could expose other saved passwords too).\n"
        "      Sign in without it: run `claude setup-token` once, outside hlyn, then "
        "export CLAUDE_CODE_OAUTH_TOKEN=<the token>; or set ANTHROPIC_API_KEY."
    )


def prepare(env: MutableMapping[str, str]) -> str:
    """Set up what Claude Code expects before it starts: its state folder
    exists (a grant needs a path that does), its temporary folder is private,
    and traffic that isn't the model is off. Returns the temporary folder."""
    os.makedirs(state(env), mode=0o700, exist_ok=True)
    box = tempfile.mkdtemp(prefix="hlyn-claude-")
    env["CLAUDE_CODE_TMPDIR"] = box
    env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    # zsh, the macOS default shell, makes its here-document files at
    # $TMPPREFIX* (/tmp/zsh by default), not under TMPDIR.
    env.setdefault("TMPPREFIX", os.path.join(box, "zsh"))
    if sys.platform == "darwin":
        # xcrun (behind /usr/bin/git) caches in the per-user temporary folder
        # every app shares, and prints an error on each call when refused.
        env.setdefault("xcrun_db", os.path.join(box, "xcrun_db"))
    return box
