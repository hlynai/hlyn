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

import glob
import os
import re
import shutil
import sys
import tempfile
import textwrap
from collections.abc import MutableMapping
from typing import TextIO
from urllib.parse import urlsplit

from .error import Error
from .policy import Policy

__all__ = ["HOSTS", "command", "forget", "login", "policy", "prepare", "save", "saved", "signin", "state"]

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


# Where Claude Code keeps its own housekeeping, outside its state folder:
# version locks (native installs) and its cache, which holds its MCP servers'
# logs. Refused, a real session's report listed them every time. Nothing here
# runs later. Made by `prepare` where their parent exists.
KEEPING: tuple[str, ...] = (
    "~/.local/state/claude/locks",
    "~/Library/Caches/claude-cli-nodejs" if sys.platform == "darwin" else "~/.cache/claude-cli-nodejs",
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


def hinted(full: list[str], path: str) -> list[str]:
    """`full` (from `command`) with one short line added to Claude Code's
    system prompt: where hlyn lists what it refused and the flag that would
    allow it (`report.Blocked`). Nothing is written into the person's project.
    A system prompt the person appended themselves is left as it is."""
    if any(arg.startswith("--append-system-prompt") for arg in full[1:]):
        return full
    text = (
        f"This session runs in an hlyn environment that refuses what it wasn't given. When a file, "
        f"command or network access is refused, read {path} (also $HLYN_BLOCKED): it says why and "
        f"which hlyn flag would allow it. You can't change it from inside; tell the user the flag."
    )
    return [full[0], "--append-system-prompt", text, *full[1:]]


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
        write=(cwd, mine, *(["/dev/tty"] if os.path.exists("/dev/tty") else []),
               *(path for path in map(os.path.expanduser, KEEPING) if os.path.isdir(path))),
        exec=True,
        net=(_model(env), *HOSTS[1:]),
        env=tuple(keep),
        tmp=tmp,
    )


# -- signing in on macOS ------------------------------------------------------
#
# Claude Code keeps its sign-in in the macOS keychain and reads it with the
# `security` tool. That stays closed to the agent: opening it would let the
# agent's `security` read every item that tool may read, other command-line
# tools' tokens included. So hlyn keeps a sign-in of its own there instead:
# a long-lived token from `claude setup-token`, read by hlyn *outside* the
# environment and handed to Claude Code alone as CLAUDE_CODE_OAUTH_TOKEN.
# Measured (FINDINGS.md, "hlyn claude"): Claude Code strips that variable from
# the programs its Bash tool starts, so the agent's commands never see it.
#
# The rules are OpenAPPA's for its own credential store
# (`appa-runtime/src/credentials.rs`): the store is outside the agent, a
# variable the person set always wins over it, and only the one variable goes
# to the one program. Where OpenAPPA keeps a 0600 SQLite file, this uses the
# keychain, written the way Claude Code writes its own item: `security -i`
# reading the command on stdin, the secret hex-encoded (`-X`), so it is never
# in the process list.

SECURITY = "/usr/bin/security"  # by full path: never a `security` found on PATH
SERVICE = "hlyn: Claude Code sign-in"
TOKEN = "CLAUDE_CODE_OAUTH_TOKEN"  # noqa: S105 - a variable name, not a value


def _keychain(env: MutableMapping[str, str]) -> list[str]:
    """The keychain file to use, if not the default one (HLYN_KEYCHAIN)."""
    where = env.get("HLYN_KEYCHAIN")
    return [os.path.abspath(os.path.expanduser(where))] if where else []


def _account() -> str:
    import getpass

    name = getpass.getuser()
    if not name or '"' in name or "\\" in name or "\n" in name:
        raise Error(f"can't keep a sign-in for the user name {name!r}.")
    return name


def saved(env: MutableMapping[str, str]) -> str | None:
    """The token `hlyn claude --login` kept, or None. Read by hlyn itself,
    unconfined, before anything is sealed."""
    import subprocess

    if sys.platform != "darwin" or not os.path.exists(SECURITY):
        return None
    done = subprocess.run(  # noqa: S603 - Apple's tool by full path, fixed arguments
        [SECURITY, "find-generic-password", "-a", _account(), "-s", SERVICE, "-w", *_keychain(env)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    token = done.stdout.strip()
    return token if done.returncode == 0 and token else None


def save(token: str, env: MutableMapping[str, str]) -> None:
    """Keep `token` in the keychain, replacing any kept before."""
    import subprocess

    paths = _keychain(env)
    if any('"' in path or "\n" in path for path in paths):
        raise Error("HLYN_KEYCHAIN can't contain a quotation mark or a line break.")
    keychain = "".join(f' "{path}"' for path in paths)
    command = (f'add-generic-password -U -a "{_account()}" -s "{SERVICE}" '
               f'-X "{token.encode().hex()}"{keychain}\n')
    done = subprocess.run(  # noqa: S603 - Apple's tool by full path; the secret goes on stdin
        [SECURITY, "-i"], input=command, capture_output=True, text=True, timeout=30, check=False,
    )
    # `security -i` answers 0 even when a command in it fails; check by reading.
    if done.returncode != 0 or saved(env) != token:
        raise Error(f"couldn't save the sign-in in the keychain: {(done.stderr or done.stdout).strip()}")


def forget(env: MutableMapping[str, str]) -> bool:
    """Remove the kept token. Returns whether there was one."""
    import subprocess

    if sys.platform != "darwin":
        return False
    done = subprocess.run(  # noqa: S603 - Apple's tool by full path, fixed arguments
        [SECURITY, "delete-generic-password", "-a", _account(), "-s", SERVICE, *_keychain(env)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    return done.returncode == 0


def looks(token: str) -> bool:
    """A plausible token: one word of printable characters, not a sentence
    pasted by mistake. Its real check is Claude Code's first request."""
    return 20 <= len(token) <= 4096 and token.isascii() and token.isprintable() and " " not in token


# What `claude setup-token` draws around the token (Claude Code 2.1.269):
# "Your OAuth token (valid for 1 year):", the token, wrapped to the terminal's
# width, then "Store this token securely. You won't be able to see it again."
# It has no option to print the token anywhere else, so it is read off the
# screen, strictly: anything that doesn't fit falls back to pasting it.
HEADING = "Your OAuth token"
AFTER = "Store this token"
# Terminal control sequences: OSC (titles, links), CSI (colours, cursor
# movement, erasing), and the two-byte ones.
ESCAPES = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
SHAPE = re.compile(r"sk-ant-[a-z]{2,8}[0-9]{0,3}-[A-Za-z0-9_-]{40,400}")
KEEP = 256 * 1024  # bytes of screen kept: the token is in the last frame


def scrape(seen: bytes) -> str | None:
    """The token in what `setup-token` drew, or None.

    The last frame between the heading and the line after the token, with
    control sequences and every bit of white space removed: wrapping only ever
    adds line breaks and indentation, never characters, and a token has no
    white space in it. Then it must be exactly one token, or nothing.
    """
    text = ESCAPES.sub("", seen.decode("utf-8", "replace"))
    start = text.rfind(HEADING)
    end = text.find(AFTER, start) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    compact = "".join(text[start:end].split())
    found = compact.find("sk-ant-")
    if found < 0 or compact.count("sk-ant-") != 1:
        return None
    token = compact[found:]
    return token if SHAPE.fullmatch(token) else None


def _draw(binary: str) -> bytes:
    """Run `claude setup-token` on a pseudo-terminal the size of this one,
    keystrokes and screen relayed both ways (the standard library's
    `pty.spawn`), and keep what it drew.

    `pty.spawn` gives the new terminal no size, and a full-screen program then
    lays itself out for 80 columns. So the child sets the size on its own
    terminal, then becomes `claude`.
    """
    import pty

    seen = bytearray()

    def read(fd: int) -> bytes:
        data = os.read(fd, 4096)
        seen.extend(data)
        if len(seen) > KEEP:
            del seen[: len(seen) - KEEP]
        return data

    size = shutil.get_terminal_size()
    sizer = (
        "import fcntl, os, struct, sys, termios\n"
        "try:\n"
        "    size = struct.pack('HHHH', int(sys.argv[1]), int(sys.argv[2]), 0, 0)\n"
        "    fcntl.ioctl(0, termios.TIOCSWINSZ, size)\n"
        "except OSError:\n"
        "    pass\n"
        "os.execv(sys.argv[3], sys.argv[3:])\n"
    )
    pty.spawn([sys.executable, "-c", sizer, str(size.lines), str(size.columns), binary, "setup-token"], read)
    return bytes(seen)


def login(binary: str, env: MutableMapping[str, str]) -> str:
    """`hlyn claude --login`: run `claude setup-token` (unconfined: it opens a
    browser to sign in), read the token it shows, and keep it."""
    import getpass

    if sys.platform != "darwin":
        return ("hlyn claude: nothing to do on this system. Sign in with `claude` as usual: "
                "its sign-in file is in ~/.claude, which hlyn claude lets it use.")
    print("hlyn: running `claude setup-token`: sign in in the browser it opens.", file=sys.stderr)
    seen = _draw(binary)
    token = scrape(seen)
    if token:
        print(f"hlyn: read the token from the screen ({token[:16]}...{token[-4:]}).", file=sys.stderr)
    elif HEADING not in ESCAPES.sub("", seen.decode("utf-8", "replace")):
        raise Error("claude setup-token ended without making a token. Nothing was saved.")
    else:
        token = getpass.getpass(
            "hlyn: couldn't read the token from the screen. Paste it here (it won't be shown): "
        ).strip()
    if not looks(token):
        raise Error("that doesn't look like a token (expected one word, like sk-ant-oat01-...). "
                    "Nothing was saved; run hlyn claude --login again.")
    save(token, env)
    return (f"hlyn: saved in your keychain as \"{SERVICE}\". hlyn claude will use it from now on; "
            "hlyn claude --logout removes it.")


# Ways to sign in that don't need the keychain.
SIGNINS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", TOKEN,
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
)


def signin(env: MutableMapping[str, str]) -> str | None:
    """Sign Claude Code in without opening the keychain to the agent.

    A variable the person set wins (as in OpenAPPA's `credentials::resolve`).
    Otherwise, on macOS, the token `hlyn claude --login` kept is put in `env`
    as CLAUDE_CODE_OAUTH_TOKEN. Returns a note to print, or None.
    """
    if sys.platform != "darwin" or any(env.get(name) for name in SIGNINS):
        return None
    if os.path.exists(os.path.join(state(env), ".credentials.json")):
        return None  # signed in without the keychain
    token = saved(env)
    if token:
        env[TOKEN] = token
        return None
    return (
        "hlyn: Claude Code keeps its sign-in in the macOS keychain, which stays closed to the agent "
        "(opening it could expose other saved passwords too).\n"
        "      Sign in for hlyn once with: hlyn claude --login"
    )


def _loads(path: str) -> object:
    """The JSON in `path`, or None when it is missing or not JSON."""
    import json

    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _asks_renderer(env: MutableMapping[str, str]) -> bool:
    """Whether Claude Code would ask "Try the new fullscreen renderer?" at
    every start because it can't save that it already has.

    It asks when `~/.claude.json` has no `firstStartVersion` (measured on
    2.1.269: a file with only that key added never asks; without it, a start
    asks even with no hlyn, when the file can't be written). Unconfined, the
    first start writes the key before it decides, so it asks nobody twice; here
    the file is read-only (see the module docstring), the write is refused and
    the question comes back each time. Answering "Yes" is saved (`"tui"` in
    `settings.json`, inside the state folder), and a choice made through
    `CLAUDE_CODE_NO_FLICKER` or `tui` is never asked about."""
    if env.get("CLAUDE_CONFIG_DIR") or "CLAUDE_CODE_NO_FLICKER" in env:
        return False  # the file saves in the state folder; or the person chose
    top = _loads(os.path.expanduser("~/.claude.json"))
    if isinstance(top, dict) and "firstStartVersion" in top:
        return False
    settings = _loads(os.path.join(state(env), "settings.json"))
    return not (isinstance(settings, dict) and "tui" in settings)


def prepare(env: MutableMapping[str, str]) -> str:
    """Set up what Claude Code expects before it starts: its state folder
    exists (a grant needs a path that does), its temporary folder is private,
    and traffic that isn't the model is off. Returns the temporary folder."""
    os.makedirs(state(env), mode=0o700, exist_ok=True)
    for path in map(os.path.expanduser, KEEPING):
        if os.path.isdir(os.path.dirname(path)):
            os.makedirs(path, mode=0o700, exist_ok=True)
    box = tempfile.mkdtemp(prefix="hlyn-claude-")
    env["CLAUDE_CODE_TMPDIR"] = box
    env.setdefault("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    if _asks_renderer(env):
        # "0" is the renderer it starts with when nobody has chosen: it only
        # stops the question. Set CLAUDE_CODE_NO_FLICKER yourself to override.
        env["CLAUDE_CODE_NO_FLICKER"] = "0"
    # zsh, the macOS default shell, makes its here-document files at
    # $TMPPREFIX* (/tmp/zsh by default), not under TMPDIR.
    env.setdefault("TMPPREFIX", os.path.join(box, "zsh"))
    if sys.platform == "darwin":
        # xcrun (behind /usr/bin/git) caches in the per-user temporary folder
        # every app shares, and prints an error on each call when refused.
        env.setdefault("xcrun_db", os.path.join(box, "xcrun_db"))
    return box


# -- what it will get, before it starts ---------------------------------------


def record() -> str:
    """Where `hlyn claude` keeps its record of what was allowed and refused.

    Not the terminal: the record's lines would draw over Claude Code's
    screen. A file in the person's own log folder instead, outside the
    project; `--log PATH` puts it elsewhere and `--no-log` turns it off.
    """
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        folder = os.path.join(home, "Library", "Logs", "hlyn")
    else:
        state_home = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
        folder = os.path.join(state_home, "hlyn")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    return os.path.join(folder, "claude.jsonl")


def risky(where: str) -> str | None:
    """Why starting in `where` gives Claude Code far more than a project,
    or None. The project folder is granted whole, read and write."""
    real = os.path.realpath(where)
    home = os.path.realpath(os.path.expanduser("~"))
    if real == home:
        return "this is your home folder: Claude Code could read and change everything in it"
    if real == "/" or real == os.path.dirname(home) or (len(real.split(os.sep)) <= 2 and real != home):
        return f"{real} holds much more than a project: Claude Code could read and change all of it"
    return None


def expected(entry: object) -> bool:
    """Refusals `hlyn claude` expects, left out of its report: Claude Code
    asking the keychain for a sign-in (hlyn gave it one; the keychain stays
    closed), and the `security` tool reading the keychain's message file for
    it, and macOS reading the home folder's text-encoding hint. The record and
    `--json` keep them."""
    kind, target = getattr(entry, "kind", ""), getattr(entry, "target", "")
    if kind == "system" and "com.apple.SecurityServer" in target:
        return True
    return kind == "read" and (
        target.startswith("/var/db/mds/messages/") or os.path.basename(target) == ".CFUserTextEncoding")


def mcp_hosts(env: MutableMapping[str, str] | None = None) -> dict[str, str]:
    """Hosts Claude Code's own MCP servers and plugins reach, by what started
    them, read from the files that configure them (`~/.claude.json`, this
    folder's `.mcp.json`, installed plugins' `.mcp.json`). When Claude Code
    reaches for one, nothing you typed asked for it; this says whose it is.
    Best effort: a file that isn't there or isn't JSON adds nothing."""
    import json

    env = os.environ if env is None else env
    found: dict[str, str] = {}

    def servers(data: object, label: str) -> None:
        if not isinstance(data, dict):
            return
        inner = data.get("mcpServers")
        for name, conf in (inner if isinstance(inner, dict) else data).items():
            url = conf.get("url") if isinstance(conf, dict) else None
            host = urlsplit(url).hostname if isinstance(url, str) else None
            if host:
                found.setdefault(host, label.format(name=name))

    def load(path: str) -> object:
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return None

    top = load(os.path.expanduser("~/.claude.json"))
    if isinstance(top, dict):
        servers(top, 'your MCP server "{name}"')
        for project in (top.get("projects") or {}).values():
            servers(project, 'your MCP server "{name}"')
    servers(load(os.path.join(os.getcwd(), ".mcp.json")), 'this project\'s MCP server "{name}"')
    plugins = os.path.join(state(env), "plugins", "cache")
    for path in sorted(glob.glob(os.path.join(plugins, "*", "*", "*", ".mcp.json"))):
        plugin = path[len(plugins) + 1:].split(os.sep)[1]
        servers(load(path), f'the "{plugin}" plugin')
    return found


def whose(entry: object, hosts: dict[str, str]) -> str:
    """What started a refused connection, if `hosts` says."""
    if getattr(entry, "kind", "") != "net":
        return ""
    return hosts.get(getattr(entry, "target", "").rsplit(":", 1)[0], "")


def _names(paths: list[str]) -> list[str]:
    """`paths` as a person would type them: ./ inside this folder, ~/ in
    the home folder; each once."""
    from .report import safe, tilde

    here = os.path.realpath(os.getcwd())
    names: list[str] = []
    for path in paths:
        real = os.path.realpath(path)
        name = safe("./" + os.path.relpath(real, here) if real.startswith(here + os.sep) else tilde(real))
        if name not in names:
            names.append(name)
    return names


def describe(plan: Policy, base: Policy, signed: tuple[bool, str], secrets: list[str], runs: list[str],
             log: str | None, stream: TextIO | None = None) -> str:
    """What `hlyn claude` is about to give Claude Code, as a table to take in
    at a glance: what it can use (✓), what it can't (✗), what to watch (!).
    Fitted to the window; nothing wraps."""
    from .report import tilde
    from .term import Paint, table, width

    stream = stream or sys.stderr
    paint, cols = Paint(stream), width(stream)
    cwd = os.getcwd()

    lines = [paint("hlyn claude: Claude Code, confined", "bold"), ""]
    danger = risky(cwd)
    if danger:
        # A warning is a sentence, so it wraps to the window (a table cell is cut instead).
        said = textwrap.wrap(danger[0].upper() + danger[1:] + ". Start it inside a project folder instead.",
                             cols - 5)
        lines += [f"  {paint('!', 'red', 'bold')}  {paint(said[0], 'red')}",
                  *(f"     {paint(more, 'red')}" for more in said[1:]), ""]
    rows: list[tuple[str, str, list[str | list[str]]]] = []

    def add(mark: str, colour: str, what: str, where: str | list[str], access: str = "") -> None:
        rows.append((mark, colour, [what, where, access]))

    add("✓", "green", "this folder", tilde(cwd), "read + write")
    state = next((p for p in base.write or () if p not in (cwd, "/dev/tty")), None)
    if state:
        add("✓", "green", "Claude's state", tilde(state), "read + write")
    hosts = (["any host"] if plan.net is True
             else [str(h).removesuffix(":443") for h in plan.net or ()] or ["none"])
    add("✓", "green", "network", hosts, "connect")
    add("✓", "green", "programs", "any, confined the same way", "run")
    ok, how = signed
    add("✓" if ok else "!", "green" if ok else "yellow", "sign-in", how, "use" if ok else "")
    for field, word in (("read", "read"), ("write", "read + write")):
        mine, theirs = getattr(plan, field), getattr(base, field)
        if mine is True:
            add("✓", "green", "also", "every file", word)
        elif isinstance(mine, tuple):
            extra = [tilde(p) for p in mine if p not in (theirs or ())]
            if extra:
                add("✓", "green", "also", extra, word)
    if plan.env is True:
        add("✓", "green", "also", "your whole environment, secrets included")
    add("✗", "red", "everything else", "other folders, hosts, your keys", "blocked")
    if secrets:
        names = _names(secrets)
        add("!", "yellow", "secret" if len(names) == 1 else "secrets", names, "readable")
    if runs:
        add("!", "yellow", "runs later", _names(runs), "writable")
    lines += table(["what", "where", "access"], rows, cols, paint)
    if runs:
        lines.append(paint("  ! runs later: what's written there runs outside hlyn", "dim"))
    if log:
        lines += ["", paint(f"  record of what it's refused: {tilde(log)}", "dim")]
    return "\n".join(lines)
