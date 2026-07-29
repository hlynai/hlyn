"""LangChain.

Confines each tool's callable. Works on a bare list of tools, or on anything
holding them on `.tools`, which is where an AgentExecutor keeps them.
"""

from __future__ import annotations

from typing import Any

from . import attach as _attach

__all__ = ["attach"]


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine every tool in `target`, in place where possible."""
    tools = getattr(target, "tools", None)
    if tools is not None:
        target.tools = [_attach(item, policy, **edits) for item in tools]
        return target
    return _attach(target, policy, **edits)
