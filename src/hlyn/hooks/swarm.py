"""OpenAI Swarm.

Swarm agents carry plain callables on `.functions`, which makes this the
simplest adapter of the set.
"""

from __future__ import annotations

from typing import Any

from . import attach as _attach, wrap

__all__ = ["attach"]


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine every function on a Swarm agent."""
    fns = getattr(target, "functions", None)
    if fns is not None:
        target.functions = [wrap(f, policy, **edits) if callable(f) else f for f in fns]
        return target
    return _attach(target, policy, **edits)
