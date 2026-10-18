# SPDX-License-Identifier: Apache-2.0
"""The macOS profile names the grant that was checked, not wherever a link
swapped in afterwards points.

`jail._unchanged` checks each grant is its own real path; the profile is built
a moment later. If the profile builder resolved the path again, a folder swapped
for a link in between would put the link's *target* in the rule. These tests
swap the folder at exactly that point and read the profile text, which needs no
confined process (`mac.profile` only builds a string), so they run on any machine.
"""

from __future__ import annotations

import importlib
import os

import pytest

from hlyn import Invalid, Policy
from hlyn.core import mac

jail = importlib.import_module("hlyn.jail")


def make(tmp_path):
    """A granted folder `mine`, a sensitive folder `secret` outside every grant,
    and the policy built the way `hlyn` builds it (grants stored by real path)."""
    mine = tmp_path / "mine"
    secret = tmp_path / "secret"
    mine.mkdir()
    secret.mkdir()
    (secret / "key").write_text("SECRET")
    return mine, secret


def swap(mine, secret):
    os.rename(mine, str(mine) + ".moved")
    os.symlink(secret, mine)


@pytest.mark.parametrize("field", ["read", "write", "exec"])
def test_control_the_profile_names_the_checked_folder_when_nothing_changes(tmp_path, field):
    mine, _ = make(tmp_path)
    plan = Policy(**{field: [str(mine)]})
    jail._unchanged(plan)
    text = mac.profile(plan)
    print(next(line for line in text.splitlines() if str(mine.resolve()) in line))
    assert f'(subpath "{mine.resolve()}")' in text


@pytest.mark.parametrize("field", ["read", "write", "exec"])
def test_a_folder_swapped_for_a_link_after_the_check_never_puts_the_target_in_the_profile(tmp_path, field):
    mine, secret = make(tmp_path)
    plan = Policy(**{field: [str(mine)]})
    jail._unchanged(plan)  # passes: it is still its own real path
    swap(mine, secret)  # the window the profile builder used to leave open
    with pytest.raises(Invalid, match="now leads somewhere else") as seen:
        mac.profile(plan)
    print("refused:", seen.value)


@pytest.mark.parametrize("function", ["lexists", "realpath", "exists", "isdir"])
def test_a_swap_at_any_step_while_the_rule_is_made_never_names_the_target(tmp_path, monkeypatch, function):
    # The folder is replaced by a link just before the first call `where` makes to
    # each filesystem function it uses, so every step between the check and the
    # rule is covered. The rule must name the checked folder, or the policy must
    # be refused: never the target.
    mine, secret = make(tmp_path)
    plan = Policy(write=[str(mine)])
    names = mac.granted(plan)
    original = getattr(os.path, function)
    fired = []

    def hooked(path, *args, **kwargs):
        if not fired and str(path) == str(mine):
            fired.append(path)
            swap(mine, secret)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os.path, function, hooked)
    rules: list[str] = []
    said = "built"
    try:
        rules = mac.where([str(mine)], None, names)
    except Invalid:
        said = "refused"
    monkeypatch.undo()
    print(f"swapped before the first {function}(): fired={bool(fired)}, {said}, rules {rules}")
    assert fired, f"where() never called {function} on the grant, so this swap tested nothing"
    assert not any(str(secret.resolve()) in rule for rule in rules)
    assert said == "refused" or rules == [f'(subpath "{mine}")']


def test_paths_hlyn_adds_itself_are_still_resolved(tmp_path):
    # System folders are links on macOS (/etc -> /private/etc) and must keep working:
    # only the caller's own checked grants are used as they are.
    link = tmp_path / "link"
    target = tmp_path / "target"
    target.mkdir()
    os.symlink(target, link)
    rules = mac.where([str(link)])  # not in `checked`: resolved as before
    print(rules)
    assert rules == [f'(subpath "{target.resolve()}")']


@pytest.mark.parametrize("field", ["read", "write"])
def test_end_to_end_a_swap_right_after_the_check_never_lets_the_program_read_the_target(tmp_path, field):
    """The whole path with a real seal, on whichever system this is (Seatbelt on
    macOS, Landlock on Linux): the folder is swapped for a link to a secret folder
    in the instant after `_unchanged` passes. Either the seal is refused, or the
    program is sealed and reading the secret fails. It must never read it."""
    from conftest import boot, enforces

    if not enforces():
        pytest.skip("this machine can't seal (see hlyn probe)")
    mine, secret = make(tmp_path)
    done = boot(f"""
        import os
        import hlyn
        from hlyn import jail

        mine, secret = {str(mine)!r}, {str(secret)!r}
        real = jail._unchanged

        def swapped(plan):
            real(plan)  # passes: nothing has changed yet
            os.rename(mine, mine + ".moved")
            os.symlink(secret, mine)

        jail._unchanged = swapped
        try:
            hlyn.on({field}=[mine], log=False)
        except hlyn.Error as exc:
            print("SEAL REFUSED:", type(exc).__name__)
            raise SystemExit(0)
        try:
            print("READ THE SECRET:", open(os.path.join(secret, "key")).read())
        except OSError as exc:
            print("SEALED; the secret is refused, errno", exc.errno)
    """)
    print(done.stdout, done.stderr)
    assert "READ THE SECRET" not in done.stdout
    assert "SEAL REFUSED" in done.stdout or "SEALED; the secret is refused" in done.stdout
