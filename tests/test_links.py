# SPDX-License-Identifier: Apache-2.0
"""Links can't widen a grant: a forbidden file stays forbidden under a new name.

On both backends. Symlinks planted inside a grant are in test_landlock.py and
test_mac.py; this is the agent making the link itself.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot


# A hard link is a second name for the same file, so one made inside a
# writable grant would make a forbidden file readable through the grant.
# Landlock refuses it (the source's folder has no REFER right), and Seatbelt
# refuses the link from a folder outside the profile.
@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="no enforcement backend")
@pytest.mark.parametrize("confined", [False, True])
def test_the_agent_cannot_hard_link_a_forbidden_file_into_its_folder(tmp_path, confined):
    inside, outside = tmp_path / "in", tmp_path / "out"
    inside.mkdir()
    outside.mkdir()
    (outside / "key").write_text("SECRET")
    seal = f"hlyn.on(hlyn.Policy(write=[{str(inside)!r}], log=False))" if confined else ""
    done = boot(
        f"""
        import os, hlyn
        {seal}
        try:
            os.link({str(outside / "key")!r}, {str(inside / "x")!r})
            print("READ", open({str(inside / "x")!r}).read())
        except OSError as error:
            print("REFUSED", error.errno)
        """
    )
    print("confined" if confined else "control", done.stdout.strip(), done.stderr.strip()[-200:])
    if confined:
        assert done.stdout.startswith("REFUSED"), done.stdout + done.stderr
        assert not (inside / "x").exists()
    else:
        assert "READ SECRET" in done.stdout  # the control: unconfined, the link works
