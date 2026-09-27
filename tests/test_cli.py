"""The command line.

`hlyn run -- python agent.py` is the onboarding path for anyone who would
rather not edit their agent, so it is worth testing that it confines rather
than merely launches.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import threading

import pytest
from conftest import SRC, enforces, skip_if_too_old

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")


@contextlib.contextmanager
def _listening():
    """A real TCP server on loopback, on a free port picked by the OS.

    Used to prove --net enforcement against an actual connection rather than
    an absence of one: a refused connect to a port nothing listens on would
    look identical whether hlyn blocked it or the OS just had nobody home.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        srv.close()
        t.join(timeout=2)


_CONNECT = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "s.settimeout(3)\n"
    "try:\n"
    "    s.connect(('127.0.0.1', {port}))\n"
    "    print('CONNECTED {port}')\n"
    "except OSError as e:\n"
    "    print('REFUSED {port}', repr(e))\n"
)


def hlyn(*args: str) -> subprocess.CompletedProcess:
    # A deliberately bare environment, so these tests prove the CLI works from
    # a clean shell rather than inheriting something from the test runner.
    # HLYN_SHIM is the one exception: it names where the Landlock shim lives,
    # and without forwarding it the CLI silently finds no shim, reports that it
    # cannot enforce, and exits non-zero anywhere the build tree is not laid
    # out exactly as expected.
    env = {"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin:/usr/local/bin"}
    shim = os.environ.get("HLYN_SHIM")
    if shim:
        env["HLYN_SHIM"] = shim
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    skip_if_too_old(done)
    return done


def test_version_is_one_flag_away():
    done = hlyn("--version")
    assert done.returncode == 0
    assert done.stdout.startswith("hlyn ")


def test_probe_prints_json_when_asked():
    out = json.loads(hlyn("probe", "--json").stdout)
    assert "enforce" in out and "platform" in out


def test_probe_speaks_to_a_person_by_default():
    out = hlyn("probe").stdout
    assert "hlyn can" in out and "isolation between agents" in out
    with pytest.raises(ValueError):
        json.loads(out)


@here
def test_probe_exits_zero_when_the_machine_can_enforce():
    # Usable as a preflight gate in a pipeline, not just something to read.
    # Gated on `enforces()`, not merely on the platform: a real backend can
    # exist and still refuse every seal (Linux ABI 1-5), and testing "probe
    # exits 0" on such a machine would be testing this suite's own hardware,
    # not hlyn.
    if not enforces():
        pytest.skip("this machine cannot fully enforce (see `hlyn probe`)")
    assert hlyn("probe").returncode == 0


def test_presets_lists_the_built_ins():
    names = {line.split()[0] for line in hlyn("presets").stdout.splitlines()}
    assert {"strict", "coder", "web", "data", "debug"} <= names


def test_presets_say_what_each_one_grants():
    lines = {line.split()[0]: line for line in hlyn("presets").stdout.splitlines()}
    assert "any network" in lines["web"]
    assert "run any program" in lines["coder"]


def test_show_prints_the_resolved_policy():
    out = json.loads(hlyn("show", "--read", "/srv", "--net", "443", "--json").stdout)
    assert out["net"] == [443]
    assert any(item == "/srv" for item in out["read"])


def test_show_prints_toml_by_default_like_watch():
    out = hlyn("show", "--net", "443", "--intent").stdout
    assert "net = [" in out and "443" in out


def test_show_applies_a_preset():
    assert json.loads(hlyn("show", "--preset", "web", "--json").stdout)["net"] is True


def test_show_never_leaks_secrets_in_the_env_summary():
    out = json.loads(hlyn("show", "--json").stdout)
    assert all("KEY" not in name and "SECRET" not in name for name in out["env"])


def test_flags_add_to_a_policy_file_never_replace_it(tmp_path):
    # `--net 8080` on top of a file granting 443 used to drop 443 -- read and
    # write were merged but exec, net and env were overwritten.
    policy = tmp_path / "policy.toml"
    policy.write_text('net = [443]\nexec = ["/usr/bin/true"]\nenv = ["A"]\n')
    out = json.loads(hlyn(
        "show", "-f", str(policy), "--net", "8080", "--exec", "/bin/ls", "--env", "B",
        "--intent", "--json",
    ).stdout)
    assert out["net"] == [443, 8080]
    assert set(out["exec"]) == {"/usr/bin/true", "/bin/ls"}
    assert set(out["env"]) == {"A", "B"}


def test_a_flag_never_narrows_read_or_write_that_grant_everything(tmp_path):
    # Naming a path on top of read=true/write=true is a no-op -- the wider
    # grant already covers it -- so, unlike --net (below), it stays true
    # rather than being replaced by the named path. Design 4.1 draws this
    # line: net narrowing is the point of the feature, read/write widening a
    # full grant is harmless.
    policy = tmp_path / "policy.toml"
    policy.write_text("read = true\nwrite = true\n")
    done = hlyn(
        "show", "-f", str(policy), "--read", "/srv", "--write", "/out", "--intent", "--json",
    )
    print("show --read /srv --write /out on top of read=true/write=true:", done.stdout, done.stderr)
    out = json.loads(done.stdout)
    assert out["read"] is True
    assert out["write"] is True


def test_net_narrows_an_open_network_named_by_a_flag_from_a_preset():
    # Gap 8.6: `--preset web` (net=true) plus `--net 443` used to leave net
    # at true, so the flag silently restricted nothing. Design 4.1 says
    # naming a port must narrow an open network instead, and say so.
    done = hlyn("show", "--preset", "web", "--net", "443", "--json")
    print("show --preset web --net 443:", done.stdout, done.stderr)
    assert (
        "hlyn: net was any network (from --preset web); --net narrows it to 443. "
        "Use --net-any to keep it open." in done.stderr
    )
    out = json.loads(done.stdout)
    assert out["net"] == [443]


def test_net_narrows_an_open_network_named_by_a_flag_from_a_policy_file(tmp_path):
    # The same rule for `net = true` in a policy file, not only a preset.
    policy = tmp_path / "policy.toml"
    policy.write_text("net = true\n")
    done = hlyn("show", "-f", str(policy), "--net", "443", "--json")
    print(f"show -f {policy} --net 443:", done.stdout, done.stderr)
    assert (
        f"hlyn: net was any network (from net = true in {policy}); --net narrows it to 443. "
        "Use --net-any to keep it open." in done.stderr
    )
    out = json.loads(done.stdout)
    assert out["net"] == [443]


def test_net_any_keeps_an_open_network_open_and_says_nothing():
    done = hlyn("show", "--preset", "web", "--net-any", "--json")
    print("show --preset web --net-any:", done.stdout, done.stderr)
    assert "narrows" not in done.stderr
    out = json.loads(done.stdout)
    assert out["net"] is True


def test_net_narrowing_does_not_fire_when_the_base_is_not_already_open(tmp_path):
    # `net = [443]` plus `--net 8080` is ordinary widening (tested above in
    # test_flags_add_to_a_policy_file_never_replace_it); it must not also
    # print the "was any network" narrowing notice, which only applies when
    # the base already granted everything.
    policy = tmp_path / "policy.toml"
    policy.write_text("net = [443]\n")
    done = hlyn("show", "-f", str(policy), "--net", "8080", "--json")
    print(f"show -f {policy} --net 8080:", done.stdout, done.stderr)
    assert "narrows" not in done.stderr
    out = json.loads(done.stdout)
    assert out["net"] == [443, 8080]


def test_a_host_is_shown_in_canonical_form():
    done = hlyn("show", "--net", "API.OpenAI.com.", "--net", "localhost:5432", "--json")
    print("show --net API.OpenAI.com. --net localhost:5432:", done.stdout, done.stderr)
    assert done.returncode == 0
    assert json.loads(done.stdout)["net"] == ["api.openai.com:443", "localhost:5432"]


def test_running_with_a_host_runs_where_hosts_are_enforced_and_is_refused_elsewhere():
    # macOS enforces hosts (the proxy behind Seatbelt); Linux does from design
    # phase 4. Until then a Linux run must be refused, never quietly treated
    # as ports. The macOS run itself is tested in test_hostmode.py.
    from hlyn.jail import back

    done = hlyn("run", "--no-report", "--net", "api.openai.com", "--", sys.executable, "-c", "print('RAN')")
    print("run --net api.openai.com:", done.returncode, done.stdout, done.stderr)
    assert "invalid int" not in done.stderr
    if getattr(back(), "HOSTS", False):
        assert done.returncode == 0 and "RAN" in done.stdout
        return
    assert done.returncode == 2
    assert "RAN" not in done.stdout
    assert "aren't enforced on Linux yet" in done.stderr or "doesn't enforce host names" in done.stderr
    assert "--net 443" in done.stderr


def test_a_malformed_host_names_the_fix():
    done = hlyn("show", "--net", "https://api.openai.com/v1")
    print(done.returncode, done.stderr)
    assert done.returncode == 2
    assert "--net api.openai.com" in done.stderr


def test_ports_and_hosts_do_not_mix_even_across_a_file_and_a_flag(tmp_path):
    # Design 4.1: the check runs on the final merged policy.
    policy = tmp_path / "policy.toml"
    policy.write_text("net = [443]\n")
    done = hlyn("show", "-f", str(policy), "--net", "api.openai.com")
    print(done.returncode, done.stderr)
    assert done.returncode == 2
    assert "mixes ports (443) and hosts (api.openai.com:443)" in done.stderr
    assert "--net api.openai.com" in done.stderr and "--net 443" in done.stderr


def test_a_host_narrows_an_open_network():
    done = hlyn("show", "--preset", "web", "--net", "api.openai.com", "--json")
    print(done.stdout, done.stderr)
    assert "net was any network (from --preset web); --net narrows it to api.openai.com:443" in done.stderr
    assert json.loads(done.stdout)["net"] == ["api.openai.com:443"]


def test_a_local_service_port_is_warned_about():
    done = hlyn("show", "--net", "localhost:2375", "--json")
    print(done.returncode, done.stderr)
    assert done.returncode == 0
    assert "localhost:2375 is Docker's API port" in done.stderr
    assert "Remove --net localhost:2375" in done.stderr


def test_the_local_service_warning_can_be_made_an_error():
    env_error = {"PYTHONWARNINGS": "error::hlyn.Reach"}
    done = subprocess.run(
        [sys.executable, "-m", "hlyn.cli", "show", "--net", "localhost:2375"],
        capture_output=True, text=True, timeout=60, check=False,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": SRC, **env_error},
    )
    print(done.returncode, done.stderr)
    assert done.returncode == 2
    assert "hlyn: refused: localhost:2375" in done.stderr


def test_run_without_a_command_explains_itself():
    done = hlyn("run")
    assert done.returncode == 2
    assert "hlyn run --" in done.stderr


@here
def test_run_confines_the_command_it_launches():
    done = hlyn(
        "run", "--", sys.executable, "-c",
        "print('AGENT UP')\n"
        "try:\n"
        "    open('/etc/hosts').read(); print('ESCAPED')\n"
        "except OSError: print('CONFINED')",
    )
    assert "AGENT UP" in done.stdout, f"the command did not run: {done.stderr}"
    assert "CONFINED" in done.stdout, f"the command was not confined: {done.stdout}"


@here
def test_run_records_the_boundary_it_applied():
    done = hlyn("run", "--", sys.executable, "-c", "print('UP')")
    seals = [
        json.loads(line)
        for line in done.stderr.splitlines()
        if line.startswith("{") and '"seal"' in line
    ]
    assert seals, f"no seal record was written:\n{done.stderr}"
    assert seals[0]["kind"] == "seal"


@here
def test_run_can_be_told_to_record_nothing():
    done = hlyn("run", "--no-log", "--", sys.executable, "-c", "print('UP')")
    assert '"seal"' not in done.stderr
    assert "UP" in done.stdout


# ---------------------------------------------------------------------------
# --net actually narrows an open network (design 4.1, gap 8.6)
# ---------------------------------------------------------------------------


@here
def test_run_net_narrows_an_open_network_so_the_unnamed_port_is_refused():
    if not enforces():
        pytest.skip("this machine cannot fully enforce (see `hlyn probe`)")
    with _listening() as allowed, _listening() as other:
        reached = hlyn(
            "run", "--preset", "web", "--net", str(allowed), "--no-log",
            "--", sys.executable, "-c", _CONNECT.format(port=allowed),
        )
        print(f"connect to the named port {allowed}:", reached.stdout, reached.stderr)
        assert (
            f"hlyn: net was any network (from --preset web); --net narrows it to {allowed}. "
            "Use --net-any to keep it open." in reached.stderr
        )
        assert f"CONNECTED {allowed}" in reached.stdout, (
            f"the named port should still be reachable: {reached.stdout}{reached.stderr}"
        )

        blocked = hlyn(
            "run", "--preset", "web", "--net", str(allowed), "--no-log",
            "--", sys.executable, "-c", _CONNECT.format(port=other),
        )
        print(f"connect to the un-named port {other}:", blocked.stdout, blocked.stderr)
        assert f"REFUSED {other}" in blocked.stdout, (
            f"a port --net never named should be refused, even though the base "
            f"policy (--preset web) was any network: {blocked.stdout}{blocked.stderr}"
        )
        assert f"CONNECTED {other}" not in blocked.stdout


@here
def test_run_net_any_keeps_an_open_network_open():
    if not enforces():
        pytest.skip("this machine cannot fully enforce (see `hlyn probe`)")
    with _listening() as port:
        done = hlyn(
            "run", "--preset", "web", "--net-any", "--no-log",
            "--", sys.executable, "-c", _CONNECT.format(port=port),
        )
        print(f"connect to {port} under --net-any:", done.stdout, done.stderr)
        assert "narrows" not in done.stderr
        assert f"CONNECTED {port}" in done.stdout, (
            f"--net-any should keep the network open: {done.stdout}{done.stderr}"
        )


# ---------------------------------------------------------------------------
# the command line as a gate
# ---------------------------------------------------------------------------


@here
def test_a_separator_inside_the_command_is_left_alone():
    # `--` is a separator to argparse and an argument to git, cargo, npm and
    # pytest. Stripping every one of them rewrote the command being launched
    # into a different command, silently -- which for a tool whose claim is
    # that the boundary matches the document is the wrong bug to have.
    done = hlyn(
        "run", "--exec-any", "--", sys.executable, "-c",
        "import sys; print('ARGV', sys.argv[1:])",
        "--", "kept",
    )
    assert "ARGV ['--', 'kept']" in done.stdout, f"the separator was eaten: {done.stdout}{done.stderr}"


@here
def test_run_passes_on_the_exit_code_and_says_what_to_try():
    # --no-report: this is the hint for when nothing was heard, which a
    # Python that lists its start folder on launch (macOS) would replace.
    done = hlyn("run", "--no-log", "--no-report", "--", sys.executable, "-c", "import sys; sys.exit(3)")
    assert done.returncode == 3
    assert "Allow it with --read" in done.stderr
    assert "hlyn watch --" in done.stderr, "a Python command should be pointed at watch"


@here
def test_run_is_silent_when_the_command_succeeds():
    done = hlyn("run", "--no-log", "--", sys.executable, "-c", "print('UP')")
    assert done.returncode == 0
    assert done.stderr == ""


def test_a_command_that_cannot_start_gets_one_message_not_a_hint():
    done = hlyn("run", "--no-log", "--", "no-such-program-hlyn")
    assert done.returncode == 1
    assert "was not found" in done.stderr
    assert "Allow it with" not in done.stderr
