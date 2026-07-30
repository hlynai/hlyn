"""Reading a policy for the grants nobody meant to make.

A policy can be valid, enforced exactly as written, and still hand the agent
everything. The dangerous grants are almost never a single field -- they are
two reasonable-looking fields that combine: write and exec over the same tree,
a read that happens to cover `~/.aws` and a network that happens to be open.
Each half looks fine in review. The pair does not.

    hlyn audit -f policy.toml            findings, and a non-zero exit
    hlyn.audit(policy)                   -> list[Finding]

This is analysis, not proof. Every rule here is a direct check against the
policy's own resolved grants -- no solver, no model, nothing that could be
wrong in an interesting way -- because the policy model is small enough that a
solver would be answering a question we can just look up. What it cannot do is
tell you whether a grant is *justified*: only that it is there, what it makes
possible, and what a reviewer should have had to say out loud to keep it. That
last part is what `accept.py` records.

Findings have stable identifiers, because a finding that cannot be named cannot
be waived, and a control that cannot be waived gets turned off entirely.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass

from .policy import Policy, under

__all__ = ["RANK", "Finding", "check", "rule", "rules"]


# Ordering, worst first. A report sorted by anything else buries the finding
# that matters under the ones that do not.
RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing worth saying about a policy.

    `says` is the claim, `why` is the consequence, and `fix` is the next
    action. All three are required: a finding without a consequence gets
    ignored, and one without a fix gets waived rather than addressed.
    """

    rule: str
    subject: str
    severity: str
    says: str
    why: str
    fix: str

    @property
    def id(self) -> str:
        """The stable name this finding is waived by.

        Rule and subject together, so waiving `credential-reach:/root/.aws`
        does not also waive the same rule firing on `/home/app/.ssh` later.
        """
        return f"{self.rule}:{self.subject}"

    def shape(self) -> dict[str, str]:
        return {
            "id": self.id,
            "rule": self.rule,
            "subject": self.subject,
            "severity": self.severity,
            "says": self.says,
            "why": self.why,
            "fix": self.fix,
        }


# Rules are registered rather than listed, so adding one is a drop-in and the
# set can be extended by a deployment with its own idea of what is dangerous.
rules: dict[str, Callable[[Policy, Mapping[str, object] | None], Iterator[Finding]]] = {}


def rule(name: str) -> Callable[[Callable[..., Iterator[Finding]]], Callable[..., Iterator[Finding]]]:
    """Register a rule under `name`, which becomes the first half of every id."""

    def take(fn: Callable[..., Iterator[Finding]]) -> Callable[..., Iterator[Finding]]:
        rules[name] = fn
        return fn

    return take


# ---------------------------------------------------------------------------
# what counts as sensitive
# ---------------------------------------------------------------------------

# Paths that hold credentials. Names, not contents: this never opens a file, so
# it works against a policy for a machine other than this one -- which is the
# normal case, since a policy is reviewed long before it is deployed.
#
# Kept as trailing path fragments so `~/.aws` matches whatever the home
# directory turns out to be, and `/root/.aws` and `/home/app/.aws` both hit.
SECRETS: tuple[tuple[str, str], ...] = (
    (".ssh", "SSH private keys"),
    (".aws", "AWS credentials"),
    (".azure", "Azure credentials"),
    (".config/gcloud", "Google Cloud credentials"),
    (".kube", "Kubernetes credentials"),
    (".docker/config.json", "registry credentials"),
    (".netrc", "stored passwords"),
    (".npmrc", "npm tokens"),
    (".pypirc", "PyPI tokens"),
    (".gnupg", "GPG private keys"),
    (".git-credentials", "git passwords"),
    (".config/gh", "GitHub tokens"),
    (".terraform.d", "Terraform credentials"),
    ("/etc/shadow", "password hashes"),
    ("/etc/sudoers", "privilege rules"),
    ("/proc", "the environment block captured at exec, secrets included"),
)

# Programs that run code given to them. Granting exec on one of these turns a
# per-path allowlist into "anything", because the allowlist governs which
# *file* is executed and these execute whatever they are handed.
INTERPRETERS: tuple[str, ...] = (
    "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs",
    "php", "lua", "tclsh", "awk", "gawk", "env", "xargs", "find",
)

# Directories where planting a file gets it run or loaded by something else.
HIJACK: tuple[str, ...] = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
    "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib",
    "/etc/ld.so.conf.d", "/etc/profile.d", "/etc/cron.d",
)


def _listed(value: object) -> tuple[str, ...]:
    """The explicit paths in a field, or nothing for a bare bool."""
    return value if isinstance(value, tuple) else ()


# Directories that are a home, or hold them. A grant covering one of these
# reaches every dotfile secret underneath it, which is the single most common
# way a policy turns out to grant credentials nobody listed.
HOMES: tuple[str, ...] = ("/root", "/home", "/Users", "/")


def _is_home(path: str) -> bool:
    """Whether a grant covers somebody's home directory.

    Either one of the roots outright, or a single level beneath `/home` or
    `/Users`, which is what a user's home looks like on Linux and macOS. This
    never touches the filesystem: a policy is normally reviewed long before it
    reaches the machine it will run on, so a check that needed the machine
    would not run when it matters.
    """
    if path in HOMES:
        return True
    parent, name = os.path.split(path.rstrip(os.sep))
    return parent in ("/home", "/Users") and bool(name)


def _touches(path: str, tail: str) -> bool:
    """Whether granting `path` reaches something at `tail`.

    Three ways, and missing any one of them is how a policy passes review while
    granting credentials:

    * the grant *is* the secret, or sits inside it -- `/root/.aws/credentials`;
    * the grant *contains* the secret by name -- `/etc/shadow` under `/etc`;
    * the grant covers a home directory, which contains every dotfile secret
      there is without naming any of them. This is the one that hides, because
      `read = ["/root"]` mentions no credential at all.
    """
    if tail.startswith("/"):
        return under(tail, path) or under(path, tail)
    marker = os.sep + tail
    if path.endswith(marker) or (marker + os.sep) in path:
        return True
    return _is_home(path)


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------


@rule("write-exec")
def _write_and_exec(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """Somewhere the agent can both write a file and run one."""
    runs = plan.runs()
    writes = plan.writes()
    if runs is False:
        return  # nothing may be executed, so nothing writable can be run
    if writes is True:
        yield Finding(
            "write-exec", "everywhere", "critical",
            "the agent may write anywhere and execute programs",
            "it can write a program of its own choosing and then run it, which "
            "makes every other grant in this policy a starting point rather than a limit",
            "name the directories in `write`, and name the programs in `exec`",
        )
        return
    for spot in _listed(writes):
        if runs is True:
            yield Finding(
                "write-exec", spot, "critical",
                f"{spot} is writable and the agent may execute any program",
                "it can write a program there and run it, so the policy does not "
                "constrain what code runs",
                "replace `exec=True` with the specific programs the agent needs",
            )
            continue
        for path in _listed(runs):
            if under(path, spot) or under(spot, path):
                yield Finding(
                    "write-exec", spot, "critical",
                    f"{spot} is both writable and executable",
                    "the agent can write a program into it and then run it, which "
                    "defeats the point of naming programs at all",
                    "keep writable directories and executable ones apart",
                )
                break


@rule("interpreter-exec")
def _interpreter(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """An exec allowlist containing something that runs arbitrary code."""
    runs = plan.runs()
    if runs is True or runs is False:
        return
    for path in _listed(runs):
        name = os.path.basename(path)
        stem = name.split("-")[0].rstrip("0123456789.")
        if name in INTERPRETERS or stem in INTERPRETERS:
            yield Finding(
                "interpreter-exec", path, "high",
                f"{path} is an interpreter, and it is on the exec allowlist",
                "the allowlist governs which file is executed, and an interpreter "
                "executes whatever it is handed -- so this grants running any code, "
                "not just this program",
                "if the agent must run scripts, say so knowingly; the boundary that "
                "still holds is the filesystem and network policy, not the exec list",
            )


@rule("credential-reach")
def _credentials(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """A grant that reaches somewhere credentials live."""
    reads = plan.reads()
    if reads is True:
        yield Finding(
            "credential-reach", "everywhere", "critical",
            "the agent may read the whole filesystem",
            "every credential on the machine is readable, including ones that have "
            "nothing to do with this agent",
            "name the directories the agent actually reads",
        )
        return
    for spot in _listed(reads):
        for tail, what in SECRETS:
            if _touches(spot, tail):
                yield Finding(
                    "credential-reach", spot, "high",
                    f"{spot} reaches {tail} ({what})",
                    "an injected agent reads credentials before it does anything "
                    "else, and this grant is how it would",
                    f"narrow the grant so it does not cover {tail}, or accept it "
                    f"deliberately with a recorded reason",
                )
                break


@rule("exfiltration")
def _exfiltration(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """Both a way to read secrets and a way to send them."""
    if plan.net is False:
        return
    reach = "the whole network" if plan.net is True else f"TCP {', '.join(map(str, plan.net))}"
    secret = [
        spot
        for spot in _listed(plan.reads())
        if any(_touches(spot, tail) for tail, _ in SECRETS)
    ]
    if plan.reads() is True:
        secret = ["everywhere"]
    if not secret:
        return
    yield Finding(
        "exfiltration", reach, "critical",
        f"the agent can read credentials ({', '.join(secret[:3])}) and reach {reach}",
        "these are the two halves of exfiltration; either alone is a risk, and "
        "together they are a route",
        "remove one half. Closing the network is usually easier than narrowing "
        "the read, and `net=False` closes UDP too",
    )


@rule("hijack")
def _hijack(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """Write access somewhere that gets loaded or run by something else."""
    writes = plan.writes()
    if writes is True:
        return  # already reported, and worse, by write-exec
    for spot in _listed(writes):
        for where in HIJACK:
            if under(where, spot) or under(spot, where):
                yield Finding(
                    "hijack", spot, "high",
                    f"{spot} is writable, and it is somewhere programs are found",
                    "a file planted there is executed or loaded by something that "
                    "is not the agent, which puts the escape outside this boundary "
                    "entirely",
                    "write to a directory that belongs to the agent",
                )
                break


@rule("evidence")
def _evidence(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """The agent can rewrite the record of what it did."""
    if not isinstance(plan.log, str):
        return
    where = os.path.abspath(plan.log)
    for spot in _listed(plan.write):
        if under(where, spot):
            yield Finding(
                "evidence", where, "high",
                f"the log is written to {where}, which the agent may also write",
                "an agent that can edit the log can remove the record of what it "
                "did, so the log stops being evidence and becomes a claim",
                "put the log outside every writable path, or send it to a "
                "collector the agent cannot reach",
            )
            return


@rule("everything")
def _everything(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """A field turned off entirely, reported plainly rather than by implication."""
    wide = (
        ("read", plan.read, "high", "every file on the machine is readable"),
        ("write", plan.write, "critical", "every file on the machine can be modified"),
        ("exec", plan.exec, "high", "any program may be launched"),
        ("net", plan.net, "medium", "the agent may reach any host and any port"),
        ("env", plan.env, "high", "every environment variable survives, API keys included"),
    )
    for field, value, level, what in wide:
        if value is True:
            yield Finding(
                "everything", field, level,
                f"`{field}=True` grants everything",
                what + ", so this dimension of the policy is not a boundary",
                f"name what the agent needs in `{field}`",
            )


@rule("udp-open")
def _udp(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """Named TCP ports, with UDP still open underneath them."""
    if not isinstance(plan.net, tuple) or not plan.net:
        return
    yield Finding(
        "udp-open", ", ".join(map(str, plan.net)), "medium",
        "naming TCP ports leaves UDP open",
        "Landlock filters TCP bind and connect; UDP is outside it, so traffic can "
        "still leave over DNS or QUIC regardless of the ports named here",
        "if nothing may leave, use `net=False`, which refuses the socket outright "
        "and closes both",
    )


@rule("proc-write")
def _proc(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """`/proc` granted, which hands back the environment `env` just scrubbed."""
    for spot in _listed(plan.writes()) + _listed(plan.reads()):
        if under("/proc", spot):
            yield Finding(
                "proc-write", spot, "high",
                f"{spot} covers /proc",
                "/proc/self/environ holds the environment captured at exec time and "
                "does not change when os.environ is scrubbed, so the `env` control "
                "is bypassed by reading it",
                "scrub secrets before the process starts rather than relying on "
                "`env`, if /proc must be granted (GPU workloads need it)",
            )
            return


@rule("widened")
def _widened(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """A named path swallowed by a broader one in the same field.

    Correct behaviour -- granting `/usr` and `/usr/lib` is granting `/usr` --
    and still worth saying, because the policy a reviewer reads names a narrow
    path that the kernel never sees.
    """
    if not asked:
        return
    for field in ("read", "write", "exec"):
        raw = asked.get(field)
        if not isinstance(raw, (list, tuple)):
            continue
        given = [os.path.abspath(os.path.expanduser(str(item))) for item in raw]
        for item in given:
            covered = [other for other in given if other != item and under(item, other)]
            if covered:
                yield Finding(
                    "widened", item, "note",
                    f"`{field}` names {item}, which {covered[0]} already covers",
                    "the narrower path has no effect; what is enforced is the "
                    "broader one, which is not what the document appears to say",
                    f"remove {item}, or remove {covered[0]} if the narrow grant was "
                    f"the intent",
                )


@rule("no-boundary")
def _nothing(plan: Policy, asked: Mapping[str, object] | None) -> Iterator[Finding]:
    """Everything open at once, which is a preset with a purpose and not a policy."""
    if all(
        value is True
        for value in (plan.read, plan.write, plan.exec, plan.net, plan.env)
    ):
        yield Finding(
            "no-boundary", "policy", "critical",
            "this policy grants everything and confines nothing",
            "it is the `debug` shape, which exists to answer what an agent touches "
            "before a real policy is written; running on it in production means "
            "there is no boundary at all",
            "run `hlyn watch -- <your agent>` to draft a real policy from what it "
            "actually used",
        )


# ---------------------------------------------------------------------------
# running them
# ---------------------------------------------------------------------------


def check(plan: Policy, asked: Mapping[str, object] | None = None) -> list[Finding]:
    """Every finding for `plan`, worst first.

    `asked` is the policy document as written, when there is one. Some findings
    are about the difference between what a file says and what it resolves to,
    and those cannot be seen from the resolved policy alone.
    """
    out: list[Finding] = []
    for fn in rules.values():
        out.extend(fn(plan, asked))
    out.sort(key=lambda item: (RANK.get(item.severity, 9), item.rule, item.subject))
    return out


def worst(found: Iterable[Finding]) -> str | None:
    """The highest severity present, or None for a clean policy."""
    ranked = sorted(found, key=lambda item: RANK.get(item.severity, 9))
    return ranked[0].severity if ranked else None
