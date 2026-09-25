"""Applying a policy to a process.

Confinement here is one-way. Landlock and seccomp cannot be lifted once set,
and neither can Seatbelt, so there is no `off()` and no context manager that
pretends to restore anything on exit. The three entry points differ only in
*which* process ends up confined:

    on(policy)          this one, permanently
    run(fn, policy)     a forked child, which runs fn and reports back
    spawn(cmd, policy)  this one, which then becomes cmd
"""

from __future__ import annotations

import os
import pickle
import shutil
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from types import ModuleType
from typing import Any

from . import log
from .error import Failed, Invalid, Sealed
from .policy import Policy, preset, presets

__all__ = ["back", "on", "probe", "run", "sealed", "spawn"]

# Given the environment the scrub kept, the variables to add to it.
Extra = Callable[[Mapping[str, str]], Mapping[str, str]]


_sealed = False


def back() -> ModuleType:
    """The enforcement backend for this machine.

    Imported lazily so that a Linux-only or macOS-only module is never loaded
    on the other platform, and an unsupported platform still gets the refusing
    backend rather than an ImportError.
    """
    if sys.platform == "linux":
        from .core import linux

        return linux
    if sys.platform == "darwin":
        from .core import mac

        return mac
    from .core import none

    return none


def sealed() -> bool:
    """True once this process has been confined."""
    return _sealed


def probe() -> dict[str, object]:
    """What this machine can enforce. Changes nothing.

    Worth calling before shipping: it is the difference between believing a
    boundary exists and knowing it does.
    """
    out: dict[str, object] = back().probe()
    return out


def _plan(policy: object, edits: Mapping[str, Any]) -> Policy:
    """Resolve everything a caller may pass into a single Policy.

    Accepts nothing at all, a preset name, a policy file, a Policy, or plain
    keywords, so the one-line and the fully-specified forms are the same call.
    """
    if policy is None:
        base = Policy()
    elif isinstance(policy, Policy):
        base = policy
    elif isinstance(policy, str):
        # A preset name and a filename are both strings, so one has to be
        # tried first. Presets win: they are a closed, known set, and a file
        # called `coder` with no extension is not something to guess at.
        base = preset(policy) if policy in presets else _read(policy)
    elif isinstance(policy, os.PathLike):
        base = _read(policy)
    elif isinstance(policy, Mapping):
        base = Policy(**policy)
    else:
        raise Invalid(
            f"expected a preset name, a policy file, a Policy, or keywords, got "
            f"{type(policy).__name__}. Try hlyn.on(), hlyn.on(\"coder\"), "
            f'hlyn.on("policy.toml"), or hlyn.on(read=["/src"]).'
        )
    return base.with_(**edits) if edits else base


def _read(path: object) -> Policy:
    """Load a policy file, or explain that it was neither a preset nor a file."""
    from .spec import load

    try:
        return load(path)  # type: ignore[arg-type]
    except Invalid as exc:
        known = ", ".join(sorted(presets))
        raise Invalid(f"{exc} (not a known preset either; those are: {known})") from None


def _scratch(policy: Policy) -> tuple[Policy, str | None]:
    """Give the agent a private scratch directory, if it asked for one.

    A fresh empty directory grants no access to anything that already exists,
    which is why it can be on by default without weakening deny-by-default.
    """
    if policy.tmp is True:
        box = tempfile.mkdtemp(prefix="hlyn-")
        return policy.with_(tmp=box), box
    if isinstance(policy.tmp, str):
        os.makedirs(policy.tmp, exist_ok=True)
        return policy, policy.tmp
    return policy, None


def on(policy: object = None, **edits: Any) -> dict[str, object]:
    """Confine this process. Permanently.

        import hlyn; hlyn.on()                     # deny all but the runtime
        hlyn.on("coder")                           # a preset
        hlyn.on(read=["/src"], net=[443])          # named grants

    Returns what was applied. Raises rather than return if the kernel could
    not apply it, because a caller that believes it is confined and is not is
    the worst outcome this package has.
    """
    return _seal(_plan(policy, edits))


def _seal(plan: Policy, extra: Extra | None = None, tag: str | None = None) -> dict[str, object]:
    """`on`, for callers that also shape the environment or tag the seal.

    `extra` returns variables to add after the environment is scrubbed, given
    what the scrub kept; `tag` marks the backend's refusal reports. Both exist
    for `hlyn run`, which uses them to hear what the command is refused.
    """
    global _sealed
    if _sealed:
        raise Sealed(
            "this process is already confined, and confinement cannot be "
            "changed once applied. Build the full policy before calling on()."
        )

    plan, box = _scratch(plan)

    # Find the backend's libraries before the environment is scrubbed. The
    # Landlock shim can be pointed at by HLYN_SHIM, which is not in the safe
    # list, so resolving it any later looks for a variable that is already
    # gone -- `hlyn probe` would honour the override and `hlyn.on()` would not,
    # on the same machine. `ready` reports rather than raises; the real refusal
    # still comes from `load` below, with its own message.
    back().ready()

    # Scrub before sealing, not after: if the seal fails halfway, the secrets
    # are already gone rather than left sitting in a half-confined process.
    keep = plan.keep()
    if box:
        keep["TMPDIR"] = box
    if extra is not None:
        keep.update(extra(keep))
    os.environ.clear()
    os.environ.update(keep)
    tempfile.tempdir = box

    if plan.log is False:
        log.off()
    elif isinstance(plan.log, str):
        log.sink(plan.log)

    level = back().load(plan, tag) if tag else back().load(plan)

    _sealed = True
    log.seal(plan, back().__name__, level, box)

    return {"policy": plan, "tmp": box, "level": level, "backend": back().__name__}


def run(fn: Callable[[], Any], policy: object = None, **edits: Any) -> Any:
    """Run `fn` in a confined child and return its result.

    For work that needs a tighter boundary than the caller wants to live with
    for the rest of its life: a single tool call, a single untrusted document.
    The parent is untouched.

    One hazard worth knowing about, because this is also the documented way to
    seal from a process that has threads. `fork` copies the calling thread and
    no others, but it copies every lock in whatever state it was in, so a child
    that needs a lock another thread was holding waits forever. The libraries
    are loaded in the parent below for exactly that reason -- `dlopen` in the
    child would take the loader lock, which is the one most likely to be held.
    """
    plan = _plan(policy, edits)
    # Before the fork, never after: see the note above.
    back().ready()
    read, write = os.pipe()

    kid = os.fork()
    if kid == 0:  # child
        os.close(read)
        code = 0
        try:
            on(plan)
            out = ("ok", fn())
        except BaseException as exc:  # noqa: BLE001 - report it rather than die silently
            out, code = ("no", exc), 1
        try:
            body = pickle.dumps(out)
        except Exception:  # noqa: BLE001 - any pickling failure, not a known set
            # A result or exception that will not pickle must not look like a
            # crash, which is what an empty pipe would mean.
            body = pickle.dumps(("no", Failed(f"the result could not be returned: {out[0]}")))
        try:
            with os.fdopen(write, "wb") as fh:
                fh.write(body)
        finally:
            os._exit(code)

    os.close(write)
    with os.fdopen(read, "rb") as fh:
        body = fh.read()
    _, status = os.waitpid(kid, 0)

    if not body:
        if os.WIFSIGNALED(status):
            hurt = os.WTERMSIG(status)
            raise Failed(
                f"the confined child was killed by signal {hurt}"
                + (" (SIGSYS: it attempted a refused syscall)" if hurt == 31 else "")
            )
        raise Failed(f"the confined child returned nothing (exit {os.WEXITSTATUS(status)})")

    # The bytes come from a child this process forked moments ago, over a pipe
    # nothing else holds. It is not untrusted input; it is this program's own
    # return value coming back across a process boundary.
    kind, value = pickle.loads(body)  # noqa: S301
    if kind == "ok":
        return value
    raise value


def spawn(cmd: Sequence[str], policy: object = None, **edits: Any) -> None:
    """Confine this process, then become `cmd`. Does not return.

    Used by the command line wrapper. The program being launched is granted
    execute on itself: asking to run something and forbidding it in the same
    breath is a contradiction, not a policy.
    """
    _spawn(cmd, _plan(policy, edits))


def _spawn(
    cmd: Sequence[str] | str, plan: Policy, extra: Extra | None = None, tag: str | None = None
) -> None:
    """`spawn`, with the same additions as `_seal`."""
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        raise Invalid("spawn needs a command to run.")

    where = shutil.which(cmd[0])
    if not where:
        raise Invalid(f"{cmd[0]!r} was not found on PATH, so it cannot be run.")
    where = os.path.realpath(where)

    if plan.exec is not True:
        grant = list(plan.exec) if isinstance(plan.exec, tuple) else []
        if where not in grant:
            grant.append(where)
        plan = plan.with_(exec=grant)

    _seal(plan, extra, tag)
    # No shell, deliberately: the command is executed as given, so nothing in
    # it is ever interpreted as shell syntax.
    os.execv(where, list(cmd))  # noqa: S606
