"""Every failure this package can raise.

One base class so callers can catch everything with a single `except`, and
narrow subclasses so they can tell "you asked for something impossible" apart
from "this machine cannot enforce it".
"""

from __future__ import annotations

__all__ = ["Error", "Failed", "Invalid", "Sealed", "Unsupported"]


class Error(Exception):
    """Base for every error raised by this package."""


class Invalid(Error):
    """The policy is malformed, contradictory, or asks for something meaningless.

    Raised before any confinement is applied, so the process is untouched.
    """


class Unsupported(Error):
    """The policy is well-formed but this machine or kernel cannot enforce it.

    Raised rather than silently downgrading. A containment layer that quietly
    enforces less than it was asked to is worse than one that refuses.
    """


class Sealed(Error):
    """Confinement is already applied and cannot be changed.

    Both Landlock and seccomp are one-way within a process. There is no
    honest way to loosen them once set.
    """


class Failed(Error):
    """The kernel refused to apply the confinement.

    Always fail closed: the caller asked to be confined and is not, so this
    propagates instead of letting the process continue unconfined.
    """
