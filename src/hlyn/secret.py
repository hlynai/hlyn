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
    r"|credentials(\.json)?|service[-_]?account.*\.json"
    r"|.*\.(pem|key|p12|pfx|kdbx|keystore|jks))$",
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


def credential(path: str) -> bool:
    """True if `path` is somewhere keys, tokens or passwords live."""
    home = os.path.expanduser("~")
    for item in HOMES:
        if under(path, os.path.join(home, item)):
            return True
    if any(under(path, item) for item in SYSTEM):
        return True
    return bool(KEYS.match(os.path.basename(path)))


def secret(name: str) -> bool:
    """True if an environment variable's name suggests it holds a secret."""
    return bool(NAMES.search(name))


def _walk(root: str, budget: list[int]) -> Iterator[str]:
    """Every file and folder under `root`, shallow first, within the budget."""
    level = [root]
    for _ in range(DEPTH):
        below: list[str] = []
        for folder in level:
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                budget[0] -= 1
                if budget[0] < 0:
                    return
                yield entry.path
                try:
                    if entry.is_dir(follow_symlinks=False) and entry.name not in SKIP:
                        below.append(entry.path)
                except OSError:
                    continue
        level = below


def exposed(plan: Policy) -> list[str]:
    """Secrets `plan` lets the agent read, if it also lets it reach the network.

    Only secrets reached *through a folder* count. Granting a secret file on
    its own -- `read=[".env"]` -- is a decision, and repeating it back as a
    warning would teach people to ignore the warning. (Named *inside* a
    granted folder it cannot be told apart: the policy drops a path its folder
    already covers.) Returns at most 20 paths, shallowest first.
    """
    if plan.net is False:
        return []
    if plan.read is True:
        home = os.path.expanduser("~")
        return [
            os.path.join(home, item) for item in HOMES if os.path.exists(os.path.join(home, item))
        ][:20]

    named: set[str] = set()
    for field in (plan.read, plan.write):
        if isinstance(field, tuple):
            named.update(os.path.realpath(item) for item in field)

    found: list[str] = []
    budget = [LOOKS]
    for root in prune(named):
        if not os.path.isdir(root):
            continue  # a file granted on its own: a decision, see above
        if credential(root):
            found.append(root)  # the grant is itself a credential folder
            continue
        for path in _walk(root, budget):
            if credential(path):
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
