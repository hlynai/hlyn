# SPDX-License-Identifier: Apache-2.0
"""PyInstaller support, found through the `pyinstaller40` entry point.

hlyn loads its native libraries (the Landlock shim and the refusal reporter,
in `hlyn/core`) by path with ctypes, which a freezer's import scan can't see.
The hook here bundles them, so a frozen app that calls `hlyn.helper()` can
seal itself and start its helpers.
"""

from __future__ import annotations

import os

__all__ = ["get_hook_dirs"]


def get_hook_dirs() -> list[str]:
    return [os.path.dirname(os.path.abspath(__file__))]
