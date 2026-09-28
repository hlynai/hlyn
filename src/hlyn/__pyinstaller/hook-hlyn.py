# SPDX-License-Identifier: Apache-2.0
"""PyInstaller hook for hlyn: bundle the native libraries in `hlyn/core`
(libhlyn.so and libhlyn_report.so on Linux), which hlyn opens by path and a
freezer's import scan can't see. Where they sit in the bundle is where hlyn
looks for them: next to `hlyn/core/landlock.py`."""

from PyInstaller.utils.hooks import collect_dynamic_libs  # type: ignore[import-not-found]

binaries = collect_dynamic_libs("hlyn")
