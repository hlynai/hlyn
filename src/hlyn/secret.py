# SPDX-License-Identifier: Apache-2.0
"""Where secrets live, and whether a policy lets them leave.

A grant is a whole tree. `read=["."]` in a project hands over its `.env`, its
service-account key and whatever else is lying about, and Landlock cannot
carve an exception out of a granted folder. On its own that is contained:
with the network closed, a secret the agent reads has nowhere to go. The
danger is the pair -- secrets readable *and* the network open -- because that
is exactly the shape of the attack hlyn exists to stop: read the key, send it
out over the port that was opened for the API.

`exposed` finds that pair before the seal, so `hlyn.on()` and `hlyn run` can
say so while it can still be fixed.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator

from .policy import Policy, prune, under

__all__ = ["Exposed", "credential", "exposed", "secret"]


class Exposed(UserWarning):
    """A policy lets the agent read secrets while the network is open."""


# Where credentials live, relative to the home folder.
HOMES: tuple[str, ...] = (
    ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".password-store",
    ".config/gcloud", ".config/gh", ".config/op", "Library/Keychains",
    ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".pgpass",
)

# And outside it.
SYSTEM: tuple[str, ...] = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssl/private",
    "/etc/pki/tls/private", "/etc/ssh",
)

# File names that hold secrets wherever they are. `.env.example` and friends
# are templates checked in on purpose, and a public key is public.
KEYS = re.compile(
    r"^(id_(rsa|dsa|ecdsa|ed25519)(_sk)?"
    r"|\.env(\.(?!example$|sample$|template$|dist$|defaults$)[^/]+)?"
    r"|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|\.htpasswd"
    r"|credentials(\.json)?|service[-_]?account.*\.json|secrets?\.(ya?ml|json|toml)"
    r"|kubeconfig|terraform\.tfstate(\.backup)?"
    r"|.*\.(pem|key|p12|pfx|ppk|kdbx|keystore|jks|tfvars))$",
    re.IGNORECASE,
)

# Environment variable names that usually hold a secret.
NAMES = re.compile(
    r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|PRIVATE|SESSION|COOKIE|DSN|DATABASE_URL",
    re.IGNORECASE,
)

# Folders not worth walking: installed dependencies and build output. A key
# inside node_modules is someone else's test fixture, and walking it costs
# more than every other folder in the project together.
SKIP = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    "site-packages", "dist-packages", "target", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".cache", ".next", ".terraform",
})

# How much of a granted tree to look through before sealing. Enough for any
# project's own files; bounded so that `read=["/"]` costs milliseconds, not
# minutes. A secret deeper than this is missed, never invented.
DEPTH = 4
LOOKS = 20_000
TIME = 0.5  # seconds, for a slow or network filesystem


_homes: dict[str, tuple[str, ...]] = {}


def _places(home: str) -> tuple[str, ...]:
    """HOMES under `home`, worked out once per home rather than per file."""
    found = _homes.get(home)
    if found is None:
        found = _homes[home] = tuple(os.path.join(home, item) for item in HOMES)
    return found


def credential(path: str) -> bool:
    """True if `path` is somewhere keys, tokens or passwords live."""
    for place in _places(os.path.expanduser("~")):
        if under(path, place):
            return True
    if any(under(path, item) for item in SYSTEM):
        return True
    return bool(KEYS.match(os.path.basename(path)))


def secret(name: str) -> bool:
    """True if an environment variable's name suggests it holds a secret."""
    return bool(NAMES.search(name))


def _walk(root: str, budget: list[float]) -> Iterator[str]:
    """Every file and folder under `root`, shallow first, within the budget.

    `budget` is [entries left, deadline]. Symlinked folders are not followed:
    the kernel resolves a link before checking it, so a link out of a granted
    folder does not make its target readable. A credential folder is yielded
    and not entered -- naming `~/.ssh` once says more than listing its keys.
    """
    level = [root]
    for _ in range(DEPTH):
        below: list[str] = []
        for folder in level:
            if time.monotonic() > budget[1]:
                return
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                budget[0] -= 1
                if budget[0] < 0 or time.monotonic() > budget[1]:
                    return
                yield entry.path
                try:
                    if (
                        entry.is_dir(follow_symlinks=False)
                        and entry.name not in SKIP
                        and not credential(entry.path)
                    ):
                        below.append(entry.path)
                except OSError:
                    continue
        level = below


# Extensions shared with things that are not secrets: `.key` is also a Keynote
# presentation and `.pem` is usually a public certificate. For these the file
# itself is checked for a private key before it is called one.
AMBIGUOUS = (".key", ".pem")


# macOS marks a file whose contents live only in the cloud (iCloud Drive,
# Dropbox, OneDrive) as dataless; opening one downloads it, which can take
# seconds and is not something a safety check should do.
DATALESS = 0x40000000


def _holds_key(path: str) -> bool:
    """Whether a `.key` or `.pem` file actually contains a private key."""
    try:
        info = os.stat(path)
        if getattr(info, "st_flags", 0) & DATALESS or info.st_size > 1 << 20:
            return False  # a cloud placeholder, or far too big to be a key
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return True  # cannot tell, so err towards saying so
    return b"PRIVATE KEY" in head


def _secret_file(path: str) -> bool:
    """`credential`, sharpened for warnings: ambiguous extensions are opened."""
    if not credential(path):
        return False
    if path.lower().endswith(AMBIGUOUS) and os.path.isfile(path):
        return _holds_key(path)
    return True


def _within(path: str, roots: list[str]) -> bool:
    """Whether `path`, links resolved, is inside one of `roots`: whether the
    kernel would actually let the agent read it."""
    real = os.path.realpath(path)
    return any(under(real, root) for root in roots)


def exposed(plan: Policy) -> list[str]:
    """Secrets `plan` lets the agent read, if it also lets it reach the network.

    Only secrets reached *through a folder* count. Granting a secret file on
    its own -- `read=[".env"]` -- is a decision, and repeating it back as a
    warning would teach people to ignore the warning. (Named *inside* a
    granted folder it cannot be told apart: the policy drops a path its folder
    already covers.) A link whose target is outside every grant is not
    counted: the kernel checks the target. Returns at most 20 paths,
    shallowest first.
    """
    if plan.net is False:
        return []
    home = os.path.expanduser("~")
    if plan.read is True:
        return [os.path.join(home, item) for item in HOMES if os.path.exists(os.path.join(home, item))][:20]

    named: set[str] = set()
    for field in (plan.read, plan.write):
        if isinstance(field, tuple):
            named.update(os.path.realpath(item) for item in field)
    roots = list(prune(named))

    found: list[str] = []
    budget: list[float] = [LOOKS, time.monotonic() + TIME]
    for root in roots:
        if not os.path.isdir(root):
            continue  # a file granted on its own: a decision, see above
        if credential(root):
            found.append(root)  # the grant is itself a credential folder
            continue
        for path in _walk(root, budget):
            if _secret_file(path) and _within(path, roots) and os.path.exists(path):
                found.append(path)
                if len(found) >= 20:
                    return found
    return found


def warning(found: list[str], cli: bool) -> str:
    """The words for `exposed`'s answer, with what to do about it."""
    from .report import safe, tilde

    here = os.path.realpath(os.getcwd())

    def near(path: str) -> str:
        real = os.path.realpath(path)
        return "./" + os.path.relpath(real, here) if under(real, here) and real != here else tilde(path)

    shown = "\n".join(f"  {safe(near(path))}" for path in found)
    one = len(found) == 1
    narrow = "--read ./src" if cli else 'read=["./src"]'
    keep = "--env NAME" if cli else 'env=["NAME"]'
    silence = (
        "Run with PYTHONWARNINGS=ignore::hlyn.Exposed to stop this warning."
        if cli
        else 'warnings.filterwarnings("ignore", category=hlyn.Exposed) stops this warning.'
    )
    return (
        f"hlyn: warning: the agent can read {len(found)} secret file{'' if one else 's'} "
        f"and reach the network, so it could send {'it' if one else 'them'} out:\n"
        f"{shown}\n"
        f"  Grant only the folders it needs (e.g. {narrow} instead of the whole project),\n"
        f"  pass a key it needs as a variable instead ({keep}), or move the secrets out.\n"
        f"  Meant it? {silence}"
    )
