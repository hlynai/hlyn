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
import stat
import time
from collections.abc import Iterator

from .policy import Policy, prune, under

__all__ = ["Exposed", "credential", "exposed", "secret", "secret_file"]


class Exposed(UserWarning):
    """A policy lets the agent read secrets while the network is open."""


# Where credentials live, relative to the home folder.
HOMES: tuple[str, ...] = (
    ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".password-store",
    ".config/gcloud", ".config/gh", ".config/op", "Library/Keychains",
    ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".pgpass",
    # Package registries and build tools: publish tokens and repository passwords.
    ".cargo/credentials", ".cargo/credentials.toml", ".gem/credentials", ".config/pnpm/auth.ini",
    ".composer/auth.json", ".config/composer/auth.json", ".m2/settings.xml",
    ".gradle/gradle.properties", ".terraform.d/credentials.tfrc.json", ".config/pulumi/credentials.json",
    # Cloud, hosting and platform CLIs: login tokens.
    ".oci", ".ibmcloud", ".databrickscfg", ".boto", ".s3cfg", ".dockercfg", ".vault-token",
    ".config/doctl", ".config/hub", ".config/glab-cli", ".config/rclone", ".config/stripe",
    ".config/ngrok", ".ngrok2", ".config/configstore/firebase-tools.json", ".config/.wrangler",
    ".supabase/access-token", ".sentryclirc", ".config/containers/auth.json", ".config/git/credentials",
    # AI and ML services: API keys and login tokens.
    ".huggingface/token", ".cache/huggingface/token", ".kaggle/kaggle.json", ".config/kaggle/kaggle.json",
    ".config/github-copilot",
    # The coding agents' own logins.
    ".claude.json", ".claude/.credentials.json", ".codex/auth.json", ".gemini/oauth_creds.json",
    # Databases, mail and version control.
    ".my.cnf", ".mylogin.cnf", ".msmtprc", ".subversion/auth",
    # Key stores, and the browsers' saved passwords and cookies.
    ".config/sops/age", ".local/share/keyrings", ".local/share/kwalletd", ".mozilla/firefox",
    ".config/google-chrome", ".config/chromium", "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox/Profiles",
)

# And outside it.
SYSTEM: tuple[str, ...] = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssl/private",
    "/etc/pki/tls/private", "/etc/ssh", "/etc/shadow-", "/etc/security/opasswd", "/etc/sudoers.d",
    "/etc/NetworkManager/system-connections", "/etc/wireguard", "/etc/ppp/chap-secrets",
    "/etc/ppp/pap-secrets", "/etc/krb5.keytab", "/etc/kubernetes/admin.conf", "/etc/kubernetes/pki",
    "/etc/rancher/k3s/k3s.yaml", "/etc/docker/key.json", "/var/lib/samba/private",
    # macOS keeps /etc under /private, and a granted folder is resolved before it is compared.
    "/etc/master.passwd", "/private/etc/master.passwd", "/private/etc/sudoers", "/private/etc/sudoers.d",
    "/private/etc/ssh",
)

# File names that hold secrets wherever they are. `.env.example` and friends
# are templates checked in on purpose, and a public key is public. The
# template word can come last rather than first (`.env.production.example`,
# which four files in a Claude Code plugin marketplace are named), so it is
# excluded at the end as well as on its own.
TEMPLATE = r"(example|sample|template|dist|defaults)"
KEYS = re.compile(
    r"^(id_(rsa|dsa|ecdsa|ed25519)(_sk)?"
    rf"|\.env(\.(?!{TEMPLATE}$)(?!([^/]+\.)?{TEMPLATE}$)[^/]+)?"
    r"|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|\.htpasswd"
    r"|credentials(\.json)?|service[-_]?account.*\.json|secrets?\.(ya?ml|json|toml)"
    r"|kubeconfig|terraform\.tfstate(\.backup)?|.*\.tfstate"
    r"|\.vault-token|\.boto|\.s3cfg|\.dockercfg|\.my\.cnf|\.mylogin\.cnf|\.msmtprc|_netrc"
    r"|auth\.json|token\.json|client_secrets?.*\.json|wp-config\.php|\.dev\.vars|\.secrets"
    r"|\.sentryclirc|\.databrickscfg|credentials\.tfrc\.json|kaggle\.json"
    r"|.*\.(pem|key|p12|pfx|p8|ppk|kdbx|keystore|jks|jceks|keytab|tfvars))$",
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
_prefixes: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {}


def _account_home() -> str:
    """This user's home from the account database, whatever `$HOME` says."""
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError, OSError):
        return ""


def _places(home: str) -> tuple[str, ...]:
    """HOMES under `home`, worked out once per home rather than per file."""
    found = _homes.get(home)
    if found is None:
        found = _homes[home] = tuple(os.path.join(home, item) for item in HOMES)
    return found


def _tables(home: str) -> tuple[frozenset[str], tuple[str, ...]]:
    """The credential places under `home` and in SYSTEM as an exact-match set
    and a tuple of folder prefixes, so `credential` is one set lookup and one
    C-speed `startswith` per file however long the lists grow."""
    found = _prefixes.get(home)
    if found is None:
        places = (*_places(home), *SYSTEM)
        found = _prefixes[home] = (frozenset(places), (*(p.rstrip(os.sep) + os.sep for p in places),))
    return found


def credential(path: str) -> bool:
    """True if `path` is somewhere keys, tokens or passwords live."""
    exact, prefixes = _tables(os.path.expanduser("~"))
    if path in exact or path.startswith(prefixes):
        return True
    return bool(KEYS.match(os.path.basename(path)))


def secret(name: str) -> bool:
    """True if an environment variable's name suggests it holds a secret."""
    return bool(NAMES.search(name))


def _walk(root: str, budget: list[float]) -> Iterator[os.DirEntry[str]]:
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
                yield entry
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


def secret_file(path: str) -> bool:
    """`credential`, sharpened for warnings: ambiguous extensions are opened."""
    if not credential(path):
        return False
    if path.lower().endswith(AMBIGUOUS) and os.path.isfile(path):
        return _holds_key(path)
    return True


def _is_link_to(entry: os.DirEntry[str], linked: set[tuple[int, int]]) -> bool:
    """Whether `entry` is another name for one of the `linked` secrets."""
    if not linked:
        return False
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) in linked


def _within(path: str, roots: list[str]) -> bool:
    """Whether `path`, links resolved, is inside one of `roots`: whether the
    kernel would actually let the agent read it."""
    real = os.path.realpath(path)
    return any(under(real, root) for root in roots)


# A hardlink is a second name for the same file, so a copy of `~/.ssh/id_rsa`
# called `notes.txt` inside a granted folder is the key, and no name test can
# tell. What can: the secrets worth linking are the ones in HOMES and SYSTEM,
# so their (device, inode) pairs are collected once -- only those with more
# than one link, since a secret with one link has no other name -- and a file
# in the walk is compared to them. Nothing is statted per file unless such a
# secret exists. Hardlinks to a secret anywhere else are not found.
LINKED_LOOKS = 2_000  # entries inspected when listing the known secret places
LINKED_DEPTH = 3


def _linked_secrets(home: str) -> set[tuple[int, int]]:
    """(device, inode) of every known secret file that has another name."""
    found: set[tuple[int, int]] = set()
    left = [LINKED_LOOKS]

    def look(path: str, depth: int) -> None:
        if left[0] <= 0:
            return
        left[0] -= 1
        try:
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink > 1:
                    found.add((info.st_dev, info.st_ino))
            elif stat.S_ISDIR(info.st_mode) and depth < LINKED_DEPTH:
                for name in os.listdir(path):
                    look(os.path.join(path, name), depth + 1)
        except OSError:
            pass

    for place in (*_places(home), *SYSTEM):
        look(place, 0)
    return found


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
    linked = _linked_secrets(home)
    cut.clear()
    renamed.clear()
    names: dict[tuple[int, int], list[str]] = {}
    for root in roots:
        if not os.path.isdir(root):
            continue  # a file granted on its own: a decision, see above
        if credential(root):
            found.append(root)  # the grant is itself a credential folder
            continue
        for entry in _walk(root, budget):
            path = entry.path
            if not (secret_file(path) or _is_link_to(entry, linked)):
                _also_named(path, names, entry)
                continue
            if _within(path, roots) and os.path.exists(path):
                found.append(path)
                if len(found) >= 20:
                    return found
        if budget[0] < 0 or time.monotonic() > budget[1]:
            cut.append(root)
    if not cut and len(found) < 20:
        # Only a complete scan can say a name is missing from it.
        for path in _found_elsewhere(names)[: 20 - len(found)]:
            if path not in found:
                found.append(path)
                renamed.add(path)
    # The known places, checked by name against everything the policy lets the
    # agent read, not only what was typed: the walk skips caches and stops at
    # its budget, and grants the user never typed (the runtime, `tmp`, the
    # network's files) are not walked at all.
    granted = plan.reads()
    if isinstance(granted, tuple):
        reach = [os.path.realpath(item) for item in granted]
        # `$HOME` is the launcher's to set; the account's own home is where the
        # keys really are, so both are looked in.
        homes = {home, _account_home()} - {""}
        places = [place for each in sorted(homes) for place in _places(each)]
        for place in (*places, *SYSTEM):
            real = os.path.realpath(place)
            if real in named or not os.path.exists(real):
                continue  # granted by name: a decision
            if any(real == item or under(real, item) for item in found):
                continue  # already listed, or inside a folder that is
            if any(under(real, root) for root in reach):
                found.append(real)
                if len(found) >= 20:
                    break
    return found


# Files in the granted folders that also have a name where the scan did not look
# (outside the grants, or in a folder it skips): reading one through the granted
# name reads whatever the other name points at, and no file name says what that
# is. Filled by the last `exposed`; `warning` says so beside the paths.
renamed: set[str] = set()


def _also_named(path: str, names: dict[tuple[int, int], list[str]], entry: os.DirEntry[str]) -> None:
    """Note `entry` if it is a regular file with more than one link."""
    try:
        if not entry.is_file(follow_symlinks=False):
            return
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return
    if info.st_nlink > 1:
        names.setdefault((info.st_dev, info.st_ino), [info.st_nlink]).append(path)  # type: ignore[arg-type]


def _found_elsewhere(names: dict[tuple[int, int], list[str]]) -> list[str]:
    """The files with more links than names seen in the scan: another name
    exists that the scan did not see."""
    out = []
    for links, *seen in names.values():
        if links > len(seen):  # type: ignore[operator]
            out.append(seen[0])  # type: ignore[arg-type]
    return sorted(out, key=lambda item: (item.count(os.sep), item))


# The granted folders whose last `exposed` scan stopped at its budget before
# looking at everything, so a clean answer for them is not the whole answer.
cut: list[str] = []


def partial(found: list[str]) -> str | None:
    """A line saying the last scan stopped early, or None if it looked at all."""
    if not cut:
        return None
    where = ", ".join(cut[:3]) + (" and more" if len(cut) > 3 else "")
    what = "found the above" if found else "found nothing"
    return (
        f"hlyn: the secret check stopped early in {where} (more than {LOOKS:,} entries or "
        f"{TIME} s); it {what} but may have missed some. Grant narrower folders to check them fully."
    )


def warning(found: list[str], cli: bool) -> str:
    """The words for `exposed`'s answer, with what to do about it."""
    from .report import safe, tilde

    here = os.path.realpath(os.getcwd())

    def near(path: str) -> str:
        real = os.path.realpath(path)
        return "./" + os.path.relpath(real, here) if under(real, here) and real != here else tilde(path)

    shown = "\n".join(
        f"  {safe(near(path))}" + ("  (also has a name elsewhere)" if path in renamed else "")
        for path in found
    )
    plain = [path for path in found if path not in renamed]
    one = len(found) == 1
    narrow = "--read ./src" if cli else 'read=["./src"]'
    keep = "--env NAME" if cli else 'env=["NAME"]'
    silence = (
        "Run with PYTHONWARNINGS=ignore::hlyn.Exposed to stop this warning."
        if cli
        else 'warnings.filterwarnings("ignore", category=hlyn.Exposed) stops this warning.'
    )
    if renamed and not plain:
        head = (
            f"hlyn: warning: the agent can read {len(found)} file{'' if one else 's'} that "
            f"also {'has' if one else 'have'} a name elsewhere (a hard link), and reach the network. "
            f"Whatever the other name points at is readable through this one:\n"
        )
    elif renamed:
        head = (
            f"hlyn: warning: the agent can read {len(plain)} secret file{'' if len(plain) == 1 else 's'} "
            f"and {len(found) - len(plain)} that also {'has' if len(found) - len(plain) == 1 else 'have'} "
            f"a name elsewhere (a hard link), and reach the network, so it could send them out:\n"
        )
    else:
        head = (
            f"hlyn: warning: the agent can read {len(found)} secret file{'' if one else 's'} "
            f"and reach the network, so it could send {'it' if one else 'them'} out:\n"
        )
    return (
        head +
        f"{shown}\n"
        f"  Grant only the folders it needs (e.g. {narrow} instead of the whole project),\n"
        f"  pass a key it needs as a variable instead ({keep}), or move the secrets out.\n"
        f"  Meant it? {silence}"
    )
