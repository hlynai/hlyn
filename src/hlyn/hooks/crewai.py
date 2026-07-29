"""CrewAI.

A Crew holds agents, an agent holds tools. Either is accepted, so this can be
called at whichever level the caller has to hand.
"""

from __future__ import annotations

from typing import Any

from . import attach as _attach

__all__ = ["attach"]


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine every tool on a crew, an agent, or a list of either."""
    crew = getattr(target, "agents", None)
    if crew is not None:
        for agent in crew:
            attach(agent, policy, **edits)
        return target
    tools = getattr(target, "tools", None)
    if tools is not None:
        target.tools = [_attach(item, policy, **edits) for item in tools]
        return target
    return _attach(target, policy, **edits)
