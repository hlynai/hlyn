"""AutoGen.

Registered functions live in a name-to-callable mapping on the agent, so each
value is replaced with a confined version of itself.
"""

from __future__ import annotations

from typing import Any

from . import attach as _attach
from . import wrap

__all__ = ["attach"]


def attach(target: Any, policy: object = None, **edits: Any) -> Any:
    """Confine every function registered on an agent."""
    for spot in ("function_map", "_function_map"):
        table = getattr(target, spot, None)
        if isinstance(table, dict):
            for name, fn in list(table.items()):
                if callable(fn):
                    table[name] = wrap(fn, policy, **edits)
            return target
    return _attach(target, policy, **edits)
