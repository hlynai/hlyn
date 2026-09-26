"""Runtime containment layer for AI agents.

Confinement is applied by the kernel, is scoped to the calling process, and
cannot be lifted once set. There is deliberately no way to turn it off.
"""

from __future__ import annotations

from .error import Error, Failed, Invalid, Sealed, Unsupported
from .jail import on, probe, run, sealed, spawn
from .policy import SAFE, Policy, preset, presets, register, runtime
from .secret import Exposed, exposed
from .spec import load

__version__ = "0.0.1"

__all__ = [
    "SAFE",
    "Error",
    "Exposed",
    "Failed",
    "Invalid",
    "Policy",
    "Sealed",
    "Unsupported",
    "__version__",
    "exposed",
    "load",
    "on",
    "preset",
    "presets",
    "probe",
    "register",
    "run",
    "runtime",
    "sealed",
    "spawn",
]
