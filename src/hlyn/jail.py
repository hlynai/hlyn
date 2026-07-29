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
from typing import Any, Callable, Mapping, Sequence

from . import log
from .error import Failed, Invalid, Sealed
from .policy import Policy, preset

__all__ = ["on", "run", "spawn", "probe", "back", "sealed"]


_sealed = False


def back():
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


def probe() -> dict:
    """What this machine can enforce. Changes nothing.

    Worth calling before shipping: it is the difference between believing a
    boundary exists and knowing it does.
    """
    return back().probe()


def _plan(policy: object, edits: Mapping[str, Any]) -> Policy:
    """Resolve everything a caller may pass into a single Policy.

    Accepts nothing at all, a preset name, a Policy, or plain keywords, so the
    one-line and the fully-specified forms are the same call.
    """
    if policy is None:
        base = Policy()
    elif isinstance(policy, Policy):
        base = policy
    elif isinstance(policy, str):
        base = preset(policy)
    elif isinstance(policy, Mapping):
        base = Policy(**policy)
    else:
        raise Invalid(
            f"expected a preset name, a Policy, or keywords, got {type(policy).__name__}. "
            'Try hlyn.on(), hlyn.on("coder"), or hlyn.on(read=["/src"]).'
        )
    return base.with_(**edits) if edits else base


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


def on(policy: object = None, **edits: Any) -> dict:
    """Confine this process. Permanently.

        import hlyn; hlyn.on()                     # deny all but the runtime
        hlyn.on("coder")                           # a preset
        hlyn.on(read=["/src"], net=[443])          # named grants

    Returns what was applied. Raises rather than return if the kernel could
    not apply it, because a caller that believes it is confined and is not is
    the worst outcome this package has.
    """
    global _sealed
    if _sealed:
        raise Sealed(
            "this process is already confined, and confinement cannot be "
            "changed once applied. Build the full policy before calling on()."
        )

    plan, box = _scratch(_plan(policy, edits))

    # Scrub before sealing, not after: if the seal fails halfway, the secrets
    # are already gone rather than left sitting in a half-confined process.
    keep = plan.keep()
    if box:
        keep["TMPDIR"] = box
    os.environ.clear()
    os.environ.update(keep)
    tempfile.tempdir = box

    if plan.log is False:
        log.off()
    elif isinstance(plan.log, str):
        log.sink(plan.log)

    level = back().load(plan)
    _sealed = True
    log.seal(plan, back().__name__, level, box)
    return {"policy": plan, "tmp": box, "level": level, "backend": back().__name__}


def run(fn: Callable[[], Any], policy: object = None, **edits: Any) -> Any:
    """Run `fn` in a confined child and return its result.

    For work that needs a tighter boundary than the caller wants to live with
    for the rest of its life: a single tool call, a single untrusted document.
    The parent is untouched.
    """
    plan = _plan(policy, edits)
    read, write = os.pipe()

    kid = os.fork()
    if kid == 0:  # child
        os.close(read)
        code = 0
        try:
            on(plan)
            out = ("ok", fn())
        except BaseException as exc:  # report it rather than die silently
            out, code = ("no", exc), 1
        try:
            body = pickle.dumps(out)
        except Exception:
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

    kind, value = pickle.loads(body)
    if kind == "ok":
        return value
    raise value


def spawn(cmd: Sequence[str], policy: object = None, **edits: Any) -> None:
    """Confine this process, then become `cmd`. Does not return.

    Used by the command line wrapper. The program being launched is granted
    execute on itself: asking to run something and forbidding it in the same
    breath is a contradiction, not a policy.
    """
    if isinstance(cmd, str):
        cmd = [cmd]
    if not cmd:
        raise Invalid("spawn needs a command to run.")

    plan = _plan(policy, edits)

    where = shutil.which(cmd[0])
    if not where:
        raise Invalid(f"{cmd[0]!r} was not found on PATH, so it cannot be run.")
    where = os.path.realpath(where)

    if plan.exec is not True:
        grant = list(plan.exec) if isinstance(plan.exec, tuple) else []
        if where not in grant:
            grant.append(where)
        plan = plan.with_(exec=grant)

    on(plan)
    os.execv(where, list(cmd))
