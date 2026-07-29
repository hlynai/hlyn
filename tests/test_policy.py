"""The policy layer decides what the kernel will later be told to enforce.

A mistake here is not a crash, it is a boundary that is quietly wider than the
caller asked for, so these tests lean on the permissive direction: they check
what is *absent* from a grant at least as hard as what is present.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import sysconfig

import pytest

from hlyn import Policy, preset, presets, register, runtime
from hlyn.error import Invalid, Unsupported
from hlyn.policy import SAFE, paths, ports, prune, under


# ---------------------------------------------------------------------------
# deny by default
# ---------------------------------------------------------------------------


def test_default_grants_nothing():
    p = Policy()
    assert p.read == ()
    assert p.write == ()
    assert p.exec is False
    assert p.net is False
    assert p.env is False


def test_default_reads_only_the_runtime():
    assert Policy().reads() == runtime()


def test_default_writes_nothing_of_the_users():
    for item in Policy().writes():
        assert item.startswith("/dev/"), f"default policy grants write to {item}"


def test_policy_is_frozen():
    p = Policy()
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.read = ("/etc",)  # type: ignore[misc]


def test_with_copies_instead_of_mutating():
    p = Policy()
    q = p.with_(read=["/srv"])
    assert p.read == ()
    assert q.read == (os.path.abspath("/srv"),)


# ---------------------------------------------------------------------------
# the bootstrap set: what keeps Python alive
# ---------------------------------------------------------------------------


def test_runtime_paths_all_exist():
    for item in runtime():
        assert os.path.exists(item), f"runtime() returned a missing path: {item}"


def test_runtime_paths_are_absolute():
    assert all(os.path.isabs(item) for item in runtime())


def test_runtime_covers_the_stdlib():
    stdlib = sysconfig.get_paths()["stdlib"]
    assert any(under(stdlib, item) for item in runtime()), "stdlib not readable"


def test_runtime_covers_the_interpreter():
    exe = os.path.abspath(sys.executable)
    assert any(under(exe, item) for item in runtime()), "interpreter not readable"


def test_runtime_covers_os_module_source():
    # A concrete stand-in for "the next lazy import will succeed".
    where = os.path.abspath(os.__file__)
    assert any(under(where, item) for item in runtime())


def test_runtime_covers_urandom():
    assert any(under("/dev/urandom", item) for item in runtime())


def test_runtime_excludes_proc():
    # /proc/self/environ still holds the environment captured at exec time, so
    # it survives scrubbing os.environ. Granting /proc would undo the env control.
    assert not any(item == "/proc" or item.startswith("/proc/") for item in runtime())


def test_runtime_excludes_the_working_directory():
    cwd = os.getcwd()
    assert not any(under(cwd, item) for item in runtime()), (
        "runtime() grants the working directory, which is the user's data"
    )


def test_runtime_excludes_ssh_keys():
    secret = os.path.expanduser("~/.ssh")
    assert not any(under(secret, item) for item in runtime())


def test_runtime_is_pruned():
    items = runtime()
    for item in items:
        others = [other for other in items if other != item]
        assert not any(under(item, other) for other in others), f"{item} is redundant"


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------


def test_paths_accepts_a_bare_string():
    assert paths("/srv", "read") == ("/srv",)


def test_paths_accepts_a_list():
    assert paths(["/srv", "/opt"], "read") == ("/opt", "/srv")


def test_paths_makes_relative_absolute():
    assert paths("srv", "read") == (os.path.join(os.getcwd(), "srv"),)


def test_paths_expands_home():
    assert paths("~/x", "read") == (os.path.expanduser("~/x"),)


def test_paths_passes_bools_through():
    assert paths(True, "read") is True
    assert paths(False, "read") is False
    assert paths(None, "read") is False


def test_paths_rejects_nonsense():
    with pytest.raises(Invalid):
        paths(42, "read")
    with pytest.raises(Invalid):
        paths([""], "read")


def test_prune_drops_covered_children():
    assert prune(["/usr", "/usr/lib", "/usr/lib/x", "/opt"]) == ("/opt", "/usr")


def test_prune_keeps_sibling_prefixes():
    # /usr/libexec is not beneath /usr/lib despite sharing a string prefix.
    assert prune(["/usr/lib", "/usr/libexec"]) == ("/usr/lib", "/usr/libexec")


def test_under_is_not_string_prefix_matching():
    assert under("/usr/lib/x", "/usr/lib")
    assert under("/usr/lib", "/usr/lib")
    assert not under("/usr/libexec", "/usr/lib")


# ---------------------------------------------------------------------------
# network: refuse what cannot be enforced
# ---------------------------------------------------------------------------


def test_net_accepts_bools_and_ports():
    assert ports(True) is True
    assert ports(False) is False
    assert ports(443) == (443,)
    assert ports([443, 80, 443]) == (80, 443)
    assert ports(["443"]) == (443,)


def test_net_refuses_host_names_loudly():
    # The kernel filters ports, not hosts. Accepting this would imply an
    # enforcement that does not exist, which is the one unacceptable failure.
    with pytest.raises(Unsupported) as caught:
        Policy(net=["api.openai.com"])
    assert "api.openai.com" in str(caught.value)


def test_net_rejects_impossible_ports():
    for bad in (0, -1, 65536, 99999):
        with pytest.raises(Invalid):
            ports(bad)


# ---------------------------------------------------------------------------
# environment scrubbing
# ---------------------------------------------------------------------------


ENV = {"OPENAI_API_KEY": "sk-secret", "AWS_SECRET_ACCESS_KEY": "s3cr3t", "PATH": "/usr/bin"}


def test_env_scrubs_secrets_by_default():
    kept = Policy().keep(ENV)
    assert "OPENAI_API_KEY" not in kept
    assert "AWS_SECRET_ACCESS_KEY" not in kept


def test_env_keeps_what_the_runtime_needs():
    assert Policy().keep(ENV)["PATH"] == "/usr/bin"


def test_env_allowlist_is_additive():
    kept = Policy(env=["OPENAI_API_KEY"]).keep(ENV)
    assert kept["OPENAI_API_KEY"] == "sk-secret"
    assert "AWS_SECRET_ACCESS_KEY" not in kept
    assert "PATH" in kept


def test_env_true_keeps_everything():
    assert Policy(env=True).keep(ENV) == ENV


def test_safe_set_holds_no_credentials():
    for name in SAFE:
        assert not any(word in name for word in ("KEY", "TOKEN", "SECRET", "PASS"))


# ---------------------------------------------------------------------------
# derived grants
# ---------------------------------------------------------------------------


def test_named_paths_are_readable():
    p = Policy(read=["/srv"], write=["/out"], exec=["/usr/bin/git"])
    for item in ("/srv", "/out", "/usr/bin/git"):
        assert any(under(item, got) for got in p.reads())


def test_write_everywhere_does_not_imply_read_everywhere():
    # The dimensions stay independent, so a broad write grant cannot silently
    # widen the read boundary.
    assert Policy(write=True).reads() is not True


def test_exec_defaults_to_denied():
    assert Policy().runs() is False


def test_exec_is_a_legal_keyword():
    # `exec` stopped being a reserved word in Python 3; this is the API the
    # handoff specifies, so it is worth pinning.
    assert Policy(exec=False).exec is False


def test_log_path_becomes_writable():
    assert any(under("/var/log/a.jsonl", item) for item in Policy(log="/var/log/a.jsonl").writes())


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------


def test_every_preset_builds():
    for name in presets:
        assert isinstance(preset(name), Policy)


def test_expected_presets_exist():
    assert {"strict", "coder", "web", "data", "debug"} <= set(presets)


def test_strict_grants_nothing_at_all():
    p = preset("strict")
    assert p.read == () and p.write == () and p.exec is False
    assert p.net is False and p.env is False and p.tmp is False


def test_coder_can_reach_the_project():
    p = preset("coder")
    assert any(under(os.getcwd(), item) for item in p.reads())


def test_web_allows_network_but_not_the_disk():
    p = preset("web")
    assert p.net is True
    assert p.write == ()


def test_presets_are_computed_late_not_at_import():
    # `coder` depends on the working directory, which is unknown at import.
    here = os.getcwd()
    try:
        os.chdir("/")
        assert any(under("/", item) or item == "/" for item in preset("coder").reads())
    finally:
        os.chdir(here)


def test_unknown_preset_names_the_known_ones():
    with pytest.raises(Invalid) as caught:
        preset("nope")
    assert "strict" in str(caught.value)


def test_registering_a_preset_is_a_drop_in():
    register("probe_only", lambda: Policy(net=[443]))
    try:
        assert preset("probe_only").net == (443,)
    finally:
        presets.pop("probe_only", None)


# ---------------------------------------------------------------------------
# sufficiency: the bootstrap set must actually keep the interpreter alive
# ---------------------------------------------------------------------------


# Sealing reads to nothing kills Python at the next lazy import. These modules
# stand in for what a real agent pulls in, including C extensions, TLS, and the
# subprocess machinery. Every file they resolve to must already be covered.
LATE = [
    "asyncio", "base64", "ctypes", "email", "gzip", "hashlib", "http.client",
    "json", "logging.handlers", "multiprocessing", "queue", "random", "secrets",
    "select", "socket", "sqlite3", "ssl", "subprocess", "tempfile", "threading",
    "urllib.request", "uuid", "zipfile",
]


def test_runtime_covers_every_late_import():
    import importlib

    allow = runtime()
    missing = []
    for name in LATE:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue  # optional extension not built here; nothing to cover
        where = getattr(module, "__file__", None)
        if not where:
            continue  # built into the interpreter, no file to read
        where = os.path.abspath(where)
        if not any(under(where, item) for item in allow):
            missing.append(where)
    assert not missing, f"deny-by-default would break these imports: {missing}"


def test_runtime_covers_loaded_extension_modules():
    # C extensions are dlopen'd at import time and live outside the pure-Python
    # tree, so they are the likeliest thing for the bootstrap set to miss.
    import importlib
    import importlib.machinery

    allow = runtime()
    missing = []
    for name in LATE:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            continue
        origin = getattr(spec, "origin", None) if spec else None
        if not origin or not origin.endswith(tuple(importlib.machinery.EXTENSION_SUFFIXES)):
            continue
        origin = os.path.abspath(origin)
        if not any(under(origin, item) for item in allow):
            missing.append(origin)
    assert not missing, f"extension modules unreachable under deny-by-default: {missing}"


def test_naming_an_executable_also_grants_the_loader():
    # Execute on the binary alone is not enough: the ELF interpreter needs it
    # too, and without this execve fails with a bare "Permission denied".
    from hlyn.policy import loader

    runs = Policy(exec=["/usr/bin/env"]).runs()
    assert runs is not False
    for item in loader():
        assert any(under(item, got) for got in runs), f"loader path {item} is not executable"


def test_the_loader_grant_does_not_cover_the_interpreter_bin_directory():
    # Handing execute to all of sys.prefix would quietly make every tool
    # shipped alongside Python runnable.
    from hlyn.policy import loader

    where = os.path.join(sys.prefix, "bin")
    assert not any(under(where, item) for item in loader()), (
        "the loader grant reaches sys.prefix/bin, which makes bundled tools runnable"
    )


def test_no_loader_grant_when_exec_is_denied():
    assert Policy().runs() is False
    assert Policy(exec=False).runs() is False
