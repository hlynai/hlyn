"""The public entry points.

These are what a user actually types, so they are tested the way a user would
hit them: from a fresh interpreter, on whatever platform this is.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot, enforces

import hlyn
from hlyn.error import Invalid
from hlyn.jail import _plan
from hlyn.policy import Policy

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")


# ---------------------------------------------------------------------------
# the API shape
# ---------------------------------------------------------------------------


def test_there_is_no_way_to_turn_it_off():
    # Landlock, seccomp, and Seatbelt are all one-way. An off() could only lie,
    # so its absence is a guarantee worth pinning down.
    assert not hasattr(hlyn, "off")
    assert not hasattr(hlyn, "unseal")
    assert not hasattr(hlyn, "release")


def test_the_entry_points_exist():
    for name in ("on", "run", "spawn", "probe"):
        assert callable(getattr(hlyn, name))


def test_probe_changes_nothing():
    hlyn.probe()
    hlyn.probe()
    assert not hlyn.sealed()


def test_probe_reports_this_machine():
    out = hlyn.probe()
    assert out["platform"] == sys.platform
    assert isinstance(out["enforce"], bool)


@here
def test_probe_says_this_machine_can_enforce():
    # A real backend existing is not the same claim: Linux ABI 1-5 has real
    # Landlock and still refuses every seal, so this only holds on a machine
    # that actually clears hlyn's floor.
    if not enforces():
        pytest.skip("this machine cannot fully enforce (see `hlyn probe`)")
    out = hlyn.probe()
    assert out["enforce"] is True, f"this machine cannot enforce: {out.get('why')}"


def test_an_unenforceable_platform_is_reported_honestly():
    from hlyn.core import none

    assert none.ready() is False
    assert none.probe()["enforce"] is False
    with pytest.raises(hlyn.Unsupported):
        none.load(Policy())


# ---------------------------------------------------------------------------
# resolving what the caller meant
# ---------------------------------------------------------------------------


def test_nothing_means_the_default_policy():
    assert _plan(None, {}) == Policy()


def test_a_string_means_a_preset():
    assert _plan("web", {}) == hlyn.preset("web")


def test_a_policy_passes_through():
    p = Policy(read=["/srv"])
    assert _plan(p, {}) is p


def test_keywords_build_a_policy():
    assert _plan(None, {"net": [443]}).net == (443,)


def test_keywords_override_a_preset():
    assert _plan("web", {"net": False}).net is False


def test_nonsense_is_refused_with_a_usable_message():
    with pytest.raises(Invalid) as caught:
        _plan(42, {})
    assert "hlyn.on()" in str(caught.value)


# ---------------------------------------------------------------------------
# on()
# ---------------------------------------------------------------------------


@here
def test_one_line_confines_the_process():
    done = boot(
        """
        import hlyn
        hlyn.on()
        try:
            open("/etc/hosts").read()
        except (PermissionError, FileNotFoundError):
            print("CONFINED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """
    )
    assert done.returncode == 0, f"hlyn.on() did not confine: {done.stdout}{done.stderr}"
    assert "CONFINED" in done.stdout


@here
def test_on_reports_what_it_applied():
    done = boot(
        """
        import hlyn
        out = hlyn.on()
        assert out["backend"].startswith("hlyn.core")
        assert isinstance(out["policy"], hlyn.Policy)
        assert hlyn.sealed()
        print("REPORTED")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "REPORTED" in done.stdout


@here
def test_confining_twice_is_refused():
    done = boot(
        """
        import hlyn
        hlyn.on()
        try:
            hlyn.on()
        except hlyn.Sealed:
            print("REFUSED"); raise SystemExit(0)
        print("ALLOWED TWICE"); raise SystemExit(1)
        """
    )
    assert done.returncode == 0, f"a second seal was allowed: {done.stdout}"


@here
def test_secrets_are_scrubbed_from_the_environment():
    done = boot(
        """
        import os
        os.environ["OPENAI_API_KEY"] = "sk-secret"
        import hlyn
        hlyn.on()
        print("LEAKED" if "OPENAI_API_KEY" in os.environ else "SCRUBBED")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "SCRUBBED" in done.stdout


@here
def test_a_named_secret_survives_scrubbing():
    done = boot(
        """
        import os
        os.environ["OPENAI_API_KEY"] = "sk-secret"
        import hlyn
        hlyn.on(env=["OPENAI_API_KEY"])
        print("KEPT" if os.environ.get("OPENAI_API_KEY") == "sk-secret" else "LOST")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "KEPT" in done.stdout


@here
def test_the_scratch_directory_is_writable():
    done = boot(
        """
        import hlyn, tempfile, os
        hlyn.on()
        with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
            fh.write("scratch"); name = fh.name
        assert open(name).read() == "scratch"
        print("SCRATCH OK")
        """
    )
    assert done.returncode == 0, f"the private scratch directory did not work:\n{done.stderr}"
    assert "SCRATCH OK" in done.stdout


@here
def test_a_granted_directory_is_reachable(tmp_path):
    (tmp_path / "data.txt").write_text("visible")
    done = boot(
        f"""
        import hlyn
        hlyn.on(read=[{str(tmp_path)!r}])
        print(open({str(tmp_path / 'data.txt')!r}).read())
        """
    )
    assert done.returncode == 0, done.stderr
    assert "visible" in done.stdout


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------


@here
def test_run_returns_the_result_from_the_confined_child():
    done = boot(
        """
        import hlyn
        assert hlyn.run(lambda: 6 * 7) == 42
        print("RESULT OK")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "RESULT OK" in done.stdout


@here
def test_run_leaves_the_parent_unconfined():
    # The point of run(): borrow a tighter boundary for one call without
    # spending the rest of the process's life inside it.
    done = boot(
        """
        import hlyn
        hlyn.run(lambda: 1)
        assert not hlyn.sealed(), "the parent was confined too"
        open("/etc/hosts").read()
        print("PARENT FREE")
        """
    )
    assert done.returncode == 0, f"run() confined the parent:\n{done.stderr}"
    assert "PARENT FREE" in done.stdout


@here
def test_run_reports_a_denial_instead_of_hanging():
    done = boot(
        """
        import hlyn
        def peek():
            return open("/etc/hosts").read()
        try:
            hlyn.run(peek)
        except (PermissionError, OSError, hlyn.Error):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """
    )
    assert done.returncode == 0, f"the child read outside its boundary: {done.stdout}"


@here
def test_run_propagates_an_ordinary_exception():
    done = boot(
        """
        import hlyn
        try:
            hlyn.run(lambda: 1 / 0)
        except ZeroDivisionError:
            print("PROPAGATED"); raise SystemExit(0)
        raise SystemExit(1)
        """
    )
    assert done.returncode == 0, done.stderr
    assert "PROPAGATED" in done.stdout


# ---------------------------------------------------------------------------
# spawn()
# ---------------------------------------------------------------------------


@here
def test_spawn_runs_the_command_confined():
    done = boot(
        """
        import hlyn, sys
        hlyn.spawn([sys.executable, "-c",
                    "print('CHILD ALIVE');"
                    "\\ntry:\\n open('/etc/hosts').read();print('ESCAPED')\\n"
                    "except OSError: print('CHILD CONFINED')"])
        """
    )
    assert "CHILD ALIVE" in done.stdout, f"spawn did not run the command: {done.stderr}"
    assert "CHILD CONFINED" in done.stdout, f"the spawned child was not confined: {done.stdout}"


@here
def test_spawn_refuses_a_command_it_cannot_find():
    done = boot(
        """
        import hlyn
        try:
            hlyn.spawn(["definitely-not-a-real-program-xyz"])
        except hlyn.Invalid:
            print("REFUSED"); raise SystemExit(0)
        raise SystemExit(1)
        """
    )
    assert done.returncode == 0, done.stderr
    assert "REFUSED" in done.stdout


# ---------------------------------------------------------------------------
# order of operations around the scrub
# ---------------------------------------------------------------------------


def test_the_backend_is_found_before_the_environment_is_scrubbed():
    """HLYN_SHIM names where the Landlock shim lives, and is not a safe name.

    So it is gone by the time anything reads it, unless the backend's libraries
    are resolved first. The symptom was `hlyn probe` honouring the override and
    `hlyn.on()` refusing to find a shim, on the same machine and in the same
    shell -- a probe that disagrees with the seal is worse than no probe.

    The backend is faked because the ordering is the whole assertion and it
    holds on every platform, including ones with no Landlock to point at.
    """
    done = boot(
        """
        import os, hlyn
        from hlyn import jail

        os.environ["HLYN_SHIM"] = "/nowhere/libhlyn.so"
        saw = {}

        class Fake:
            __name__ = "hlyn.core.fake"

            @staticmethod
            def ready():
                saw["ready"] = os.environ.get("HLYN_SHIM")
                return True

            @staticmethod
            def load(plan):
                saw["load"] = os.environ.get("HLYN_SHIM")
                return 6

        jail.back = lambda: Fake
        hlyn.on(log=False, tmp=False)
        print("ready saw", saw["ready"])
        print("load saw", saw["load"])
        """
    )
    assert "ready saw /nowhere/libhlyn.so" in done.stdout, done.stdout + done.stderr
    # And the scrub still happens: the override is read early, not kept around.
    assert "load saw None" in done.stdout, done.stdout + done.stderr
