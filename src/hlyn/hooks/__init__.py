"""Framework adapters.

Every agent framework eventually calls a plain Python callable to do the work,
so that is where the boundary goes. `wrap` puts a single tool inside its own
confined child process: it runs, returns its result, and the parent's own
permissions are never widened to accommodate it.

This is the per-tool half of the story. The other half is confining the whole
agent process with `hlyn.on()`, which is one line and needs no adapter at all.
Use both: the process-wide boundary is the floor, and a per-tool boundary is
for the handful of tools that should be tighter than the floor.

Adding a framework is a drop-in file here. Nothing else needs to change.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from .. import jail, log

__all__ = ["wrap", "tool", "attach"]


def wrap(fn: Callable[..., Any], policy: object = None, **edits: Any) -> Callable[..., Any]:
    """Return a version of `fn` that runs inside its own confined child.

    The result comes back to the caller; a refusal comes back as the exception
    the tool actually hit, so the agent can report it rather than die.
    """

    @functools.wraps(fn)
    def inner(*args: Any, **kwargs: Any) -> Any:
        name = getattr(fn, "__name__", repr(fn))
        try:
            out = jail.run(lambda: fn(*args, **kwargs), policy, **edits)
        except Exception as exc:
            log.deny("tool", f"{type(exc).__name__}: {exc}", tool=name)
            raise
        log.allow("tool", tool=name)
        return out

    return inner


def tool(policy: object = None, **edits: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator form.

        @hlyn.hooks.tool(read=["/data"], net=False)
        def search(q): ...
    """

    def take(fn: Callable[..., Any]) -> Callable[..., Any]:
        return wrap(fn, policy, **edits)

    return take


# The attribute each framework keeps its callable on, in the order worth
# trying. Wrapping the callable rather than subclassing the tool keeps this
# working across framework versions, which change their class hierarchies far
# more often than they change where the function lives.
SPOTS: tuple[str, ...] = ("func", "_run", "run", "fn", "callable", "on_invoke_tool")


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine a tool, or every tool in a list, in place.

    Works with any object that keeps its callable on one of the usual
    attributes. Anything else is refused by name rather than silently left
    unconfined.
    """
    if isinstance(target, (list, tuple)):
        return type(target)(attach(item, policy, **edits) for item in target)

    if callable(target) and not hasattr(target, "__dict__"):
        return wrap(target, policy, **edits)

    for spot in SPOTS:
        got = getattr(target, spot, None)
        if callable(got):
            try:
                setattr(target, spot, wrap(got, policy, **edits))
            except (AttributeError, ValueError):
                continue  # frozen model; try the next attribute
            return target

    if callable(target):
        return wrap(target, policy, **edits)

    raise TypeError(
        f"{type(target).__name__} does not look like a tool: no callable found on "
        f"any of {', '.join(SPOTS)}. Wrap the function directly with hlyn.hooks.wrap."
    )
