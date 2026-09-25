"""The backend for machines that cannot enforce anything.

It refuses. That is the entire feature.

A containment layer that quietly does nothing on an unsupported platform is
worse than no containment layer at all, because the team ships believing the
boundary is there. Every path through this module raises.
"""

from __future__ import annotations

import platform
import sys

from ..error import Unsupported
from ..policy import Policy
from ..report import Quiet

__all__ = ["listen", "load", "probe", "ready", "seal"]


def ready() -> bool:
    """Never. Nothing here can enforce."""
    return False


def probe() -> dict[str, object]:
    return {
        "platform": sys.platform,
        "machine": platform.machine(),
        "enforce": False,
        "why": "no enforcement backend for this platform",
    }


def load(policy: Policy, tag: str | None = None) -> int:
    raise Unsupported(
        f"there is no enforcement backend for {sys.platform!r}, so this process "
        "cannot be confined. Refusing to continue rather than reporting a "
        "boundary that is not there. Supported platforms are Linux (Landlock "
        "and seccomp) and macOS (Seatbelt)."
    )


seal = load


def listen() -> Quiet:
    return Quiet("there is no enforcement backend for this platform")
