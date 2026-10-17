# SPDX-License-Identifier: Apache-2.0
"""A grant is sealed only if it is still the folder that was checked.

A path can name a different folder a moment later without any link: the checked
folder renamed away, another real folder renamed to its place. The policy stores
the (device, inode) of each grant when it resolves it, and the seal refuses a
path that now names something else. Each test prints what happened.
"""

from __future__ import annotations

import importlib
import os

import pytest
from conftest import boot, enforces

from hlyn import Invalid, Policy
from hlyn.core import landlock, mac

jail = importlib.import_module("hlyn.jail")


def pair(tmp_path):
    mine = tmp_path / "mine"
    other = tmp_path / "other"
    mine.mkdir()
    other.mkdir()
    (other / "marker").write_text("the other folder")
    return mine, other


def replace(mine, other):
    """`other` renamed over `mine`'s name; `mine` moved aside. No link anywhere."""
    os.rename(mine, str(mine) + ".moved")
    os.rename(other, mine)


@pytest.mark.parametrize("field", ["read", "write", "exec"])
def test_control_an_unchanged_grant_passes(tmp_path, field):
    mine, _ = pair(tmp_path)
    plan = Policy(**{field: [str(mine)]})
    jail._unchanged(plan)


@pytest.mark.parametrize("field", ["read", "write", "exec"])
def test_a_folder_replaced_by_another_real_folder_is_refused(tmp_path, field):
    mine, other = pair(tmp_path)
    plan = Policy(**{field: [str(mine)]})
    replace(mine, other)
    assert os.path.realpath(mine) == str(mine)  # no link: the old check cannot see it
    with pytest.raises(Invalid, match="different folder") as seen:
        jail._unchanged(plan)
    print("refused:", seen.value)


def test_a_file_replaced_by_another_file_is_refused(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("one")
    second.write_text("two")
    plan = Policy(read=[str(first)])
    os.replace(second, first)
    with pytest.raises(Invalid, match="different folder"):
        jail._unchanged(plan)


def test_the_scratch_folder_is_checked_too(tmp_path):
    scratch = tmp_path / "scratch"
    other = tmp_path / "other"
    scratch.mkdir(mode=0o700)
    other.mkdir(mode=0o700)
    plan = Policy(tmp=str(scratch))
    replace(scratch, other)
    with pytest.raises(Invalid, match="different folder"):
        jail._unchanged(plan)


def test_a_policy_built_after_a_legitimate_replacement_works(tmp_path):
    # Control: the person recreated the folder and then asked for it. Only a
    # change between the policy's resolution and the seal is refused.
    mine, other = pair(tmp_path)
    Policy(read=[str(mine)])
    replace(mine, other)
    jail._unchanged(Policy(read=[str(mine)]))


def test_the_profile_builder_and_the_shim_probe_refuse_it_too(tmp_path):
    mine, other = pair(tmp_path)
    plan = Policy(write=[str(mine)])
    replace(mine, other)
    with pytest.raises(Invalid, match="different folder"):
        mac.where([str(mine)], None, mac.granted(plan))
    refused: list[tuple[str, str]] = []
    landlock._paths((str(mine),), refused, frozenset({str(mine)}))
    print("probe refused:", refused)
    assert refused and "different folder" in refused[0][1]


@pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")
def test_end_to_end_a_replacement_right_after_the_first_check_is_not_sealed(tmp_path):
    mine, other = pair(tmp_path)
    done = boot(f"""
        import os
        import hlyn
        from hlyn import jail

        mine, other = {str(mine)!r}, {str(other)!r}
        real = jail._unchanged

        def swapped(plan):
            real(plan)  # passes: nothing has changed yet
            os.rename(mine, mine + ".moved")
            os.rename(other, mine)

        jail._unchanged = swapped
        try:
            hlyn.on(write=[mine], log=False)
            print("SEALED")
        except hlyn.Error as exc:
            print("REFUSED:", type(exc).__name__, str(exc)[:70])
    """)
    print(done.stdout, done.stderr)
    assert "SEALED" not in done.stdout and "REFUSED" in done.stdout
