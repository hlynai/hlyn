# SPDX-License-Identifier: Apache-2.0
"""Files a write grant lets the agent fill in, which something else runs later.

A boundary holds only while the agent is inside it. Writing a command into a
file another program runs -- a git hook, a shell's start-up file, Claude Code's
own settings -- is running code outside the environment, at the moment the
person starts that program themselves. The write is refused by nothing: the
file is in a folder they granted on purpose, usually their own project.

So this names them, before the run, as `secret.py` names exposed credentials.
Neither kernel can grant a folder minus one file, so it cannot be refused
without refusing the folder: the answer is a sentence, and `-W error` for a CI
job that must not allow it at all.

The list is what OpenAPPA's Claude Code battery watches
(`OpenAPPA-main/marketplace/batteries/claude-code/appa.toml`, MIT), read on
2026-10-01 and checked against each program's own documentation.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from .policy import Policy, prune, under

__all__ = ["HOME", "PROJECT", "SYSTEM", "Runs", "found", "warning"]


class Runs(UserWarning):
    """A policy lets the agent write a file something else runs later."""


# Inside any granted folder, by name. Searched at the folder's root and at any
# depth, since a project may hold more than one checkout.
#
# Only what runs *by itself*, the next time the person uses a normal tool: no
# step of theirs beyond `git commit`, `cd`, or starting Claude Code. A build
# file (`Makefile`, `package.json`, `pyproject.toml`, `Dockerfile`, a test's
# `conftest.py`) is deliberately not here, and neither is `CLAUDE.md`: editing
# those is the agent's job, so warning about them every run would teach people
# to ignore this warning -- the mistake `secret.exposed` avoids the same way.
# They are the README's "Writable folders others execute" limit instead.
PROJECT: tuple[str, ...] = (
    ".git/hooks",             # every later git command in that checkout
    ".githooks",              # core.hooksPath, by convention
    ".claude/settings.json",  # Claude Code hooks, next start in that project
    ".claude/settings.local.json",
    ".claude/hooks",
    ".claude/agents",
    ".claude/commands",
    ".claude/skills",
    ".claude/plugins",
    ".mcp.json",              # servers Claude Code starts, outside any environment
    ".envrc",                 # direnv, on the next cd into the folder
)

# In the home folder.
HOME: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks",
    ".claude/agents", ".claude/commands", ".claude/skills", ".claude/plugins",
    ".claude.json",
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".zlogin",
    ".config/fish/config.fish",
    ".gitconfig", ".config/git/config",   # core.hooksPath, aliases, pager
    ".ssh/config",                        # ProxyCommand runs a program
    ".config/direnv/direnvrc",
    "Library/LaunchAgents",               # macOS: runs at login
    ".config/autostart",                  # Linux desktops: the same
    ".config/systemd/user",
    "bin", ".local/bin",                  # earlier on PATH than the system's
)

# Outside both.
SYSTEM: tuple[str, ...] = (
    "/etc/profile.d", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system",
    "/Library/LaunchAgents", "/Library/LaunchDaemons",
)

LOOKS = 20_000  # entries walked, as secret.py bounds its own walk
SHOWN = 12      # paths named in the warning
SKIP = frozenset({"node_modules", ".venv", "venv", "target", "build", "dist", ".mypy_cache"})


def _writable(plan: Policy) -> list[str]:
    """The folders `plan` lets the agent write, links resolved."""
    if not isinstance(plan.write, tuple):
        return []
    return list(prune({os.path.realpath(item) for item in plan.write}))


def found(plan: Policy, known: Iterable[str] = ()) -> list[str]:
    """Paths `plan` lets the agent write that something else runs later.

    Exact paths, that exist: a name the agent could *create* is not listed,
    because every writable folder has infinitely many of those and the useful
    warning is "this file, which you run". Only the folders themselves are
    searched, never the whole filesystem, and the walk is bounded.

    `known` names folders whose contents the caller already accounts for, and
    so are not a surprise: `hlyn claude` passes Claude Code's own state folder,
    which it grants on purpose and the README explains. Same reason
    `secret.exposed` says nothing about a secret granted by name.
    """
    skip = [os.path.realpath(item) for item in known]

    def wanted(path: str) -> bool:
        return not any(under(path, item) for item in skip)

    if plan.write is True:
        every = (path for path in map(os.path.expanduser, _all()) if os.path.exists(path))
        return [path for path in every if wanted(os.path.realpath(path))][:SHOWN]
    roots = [root for root in _writable(plan) if wanted(root)]
    if not roots:
        return []
    home = os.path.realpath(os.path.expanduser("~"))
    hits: list[str] = []
    seen: set[str] = set()

    def note(path: str) -> None:
        real = os.path.realpath(path)
        if real in seen or not os.path.exists(real) or not wanted(real):
            return
        if any(under(real, root) for root in roots):
            seen.add(real)
            hits.append(real)

    for root in roots:
        for name in HOME:
            if under(os.path.join(home, name), root) or root == home:
                note(os.path.join(home, name))
        for name in SYSTEM:
            note(name)
        if os.path.isdir(root):
            for folder in _folders(root):
                for name in PROJECT:
                    note(os.path.join(folder, name))
        else:
            for name in PROJECT:  # a file granted on its own
                if root.endswith(os.sep + name) or os.path.basename(root) == name:
                    note(root)
        if len(hits) >= SHOWN:
            break
    return hits[:SHOWN]


def _all() -> list[str]:
    """Every watched path, for `write=True`."""
    home = os.path.expanduser("~")
    return [*(os.path.join(home, name) for name in HOME), *SYSTEM]


def _folders(root: str) -> list[str]:
    """`root` and the folders under it worth looking in, bounded."""
    out = [root]
    budget = LOOKS
    for here, folders, _files in os.walk(root):
        folders[:] = [name for name in folders if name not in SKIP and not name.startswith(".git")]
        budget -= len(folders) + 1
        if budget <= 0:
            break
        out.extend(os.path.join(here, name) for name in folders)
        if len(out) > 2_000:
            break
    return out


def warning(hits: list[str], cli: bool) -> str:
    """The words for `found`'s answer, with what to do about it."""
    from .report import safe, tilde

    here = os.path.realpath(os.getcwd())

    def near(path: str) -> str:
        if under(path, here) and path != here:
            return "./" + os.path.relpath(path, here)
        return tilde(path)

    shown = "\n".join(f"  {safe(near(path))}" for path in hits)
    one = len(hits) == 1
    narrow = "--write ./out" if cli else 'write=["./out"]'
    silence = (
        "Run with PYTHONWARNINGS=ignore::hlyn.Runs to stop this warning."
        if cli
        else 'warnings.filterwarnings("ignore", category=hlyn.Runs) stops this warning.'
    )
    return (
        f"hlyn: warning: the agent can write {len(hits)} file{'' if one else 's'} that "
        f"{'runs' if one else 'run'} later, outside this environment:\n"
        f"{shown}\n"
        f"  Whatever it writes there runs unconfined the next time you (or git, or CI) "
        f"start that program.\n"
        f"  Grant a narrower folder (e.g. {narrow} instead of the whole project), or check "
        f"these files before you run them again.\n"
        f"  Meant it? {silence}"
    )
