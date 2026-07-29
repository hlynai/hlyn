"""LlamaIndex.

A FunctionTool keeps its callable on `.fn`; the shared attach already looks
there. Agents expose the same tools on `.tools`.
"""

from __future__ import annotations

from typing import Any

from . import attach as _attach

__all__ = ["attach"]


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine every tool in `target`."""
    tools = getattr(target, "tools", None)
    if tools is not None:
        target.tools = [_attach(item, policy, **edits) for item in tools]
        return target
    return _attach(target, policy, **edits)
