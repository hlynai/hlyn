# SPDX-License-Identifier: Apache-2.0
"""One version, in two places: pyproject.toml (what PyPI shows) and hlyn.__version__
(what `hlyn --version` prints). release.yml also refuses a tag that differs."""

from __future__ import annotations

import re
from pathlib import Path

import hlyn

ROOT = Path(__file__).resolve().parent.parent


def test_the_package_version_matches_pyproject():
    declared = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)
    assert declared is not None
    print(f"pyproject {declared.group(1)!r}, hlyn.__version__ {hlyn.__version__!r}")
    assert hlyn.__version__ == declared.group(1)
