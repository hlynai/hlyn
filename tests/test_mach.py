# SPDX-License-Identifier: Apache-2.0
"""macOS system services (Mach), per mode (DESIGN-host-allowlisting.md 5.4, gap 8.3).

Every mode but an open network allows only the services measured to be
needed (tools/hostlab/machlab.py; FINDINGS.md, "which Mach services programs
need"): user and group lookups, preferences, group membership (Swift). With
ports, the two that reach the network for a program (trustd, dnssd) too,
since ports already allow HTTPS to any host. The keychain's service only
when the policy lets the program read a keychain file. Never the pasteboard
or the notification centre, which carried data between two agents.

Each test asks launchd for the service (`bootstrap_look_up`), which changes
nothing: no clipboard, notification or keychain is touched.
"""

from __future__ import annotations

import sys

import pytest
from conftest import SRC, boot, enforces

pytestmark = [
    pytest.mark.skipif(sys.platform != "darwin", reason="Mach services are macOS's"),
    pytest.mark.skipif(sys.platform == "darwin" and not enforces(), reason="Seatbelt is unavailable"),
]

SERVICES = {
    "libinfo": "com.apple.system.opendirectoryd.libinfo",
    "prefs": "com.apple.cfprefsd.agent",
    "membership": "com.apple.system.opendirectoryd.membership",
    "trustd": "com.apple.trustd.agent",
    "dnssd": "com.apple.dnssd.service",
    "keychain": "com.apple.SecurityServer",
    "pasteboard": "com.apple.pasteboard.1",
    "notifications": "com.apple.system.notification_center",
}

LOOK = f"""
import ctypes, hlyn
def look():
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    bp = ctypes.c_uint.in_dll(libc, "bootstrap_port")
    out = {{}}
    for short, name in {SERVICES!r}.items():
        port = ctypes.c_uint(0)
        out[short] = libc.bootstrap_look_up(bp, name.encode(), ctypes.byref(port)) == 0
    return out
"""


def reach(**policy: object) -> dict[str, bool]:
    done = boot(LOOK + f"\nprint(hlyn.run(look, log=False, **{policy!r}))\n")
    print(policy, "->", done.stdout.strip(), done.stderr[-600:])
    assert done.returncode == 0, done.stderr
    return eval(done.stdout.strip())  # noqa: S307 - this test's own child printed a dict of bools


def test_unconfined_every_service_is_there():
    done = boot(LOOK + "\nprint(look())\n")
    print(done.stdout)
    assert all(eval(done.stdout.strip()).values())  # noqa: S307 - our own child's dict


@pytest.mark.parametrize("net", [False, ["pypi.org"]], ids=["off", "hosts"])
def test_with_the_network_off_or_hosts_only_the_measured_services(net):
    got = reach(net=net)
    assert got["libinfo"] and got["prefs"] and got["membership"]
    for refused in ("trustd", "dnssd", "keychain", "pasteboard", "notifications"):
        assert not got[refused], refused


def test_with_ports_the_services_that_reach_the_network_too():
    got = reach(net=[443])
    assert got["libinfo"] and got["prefs"] and got["membership"]
    assert got["trustd"] and got["dnssd"]
    for refused in ("keychain", "pasteboard", "notifications"):
        assert not got[refused], refused


def test_an_open_network_leaves_every_service():
    got = reach(net=True)
    assert all(got.values()), got


def test_the_keychain_service_comes_with_a_readable_keychain(tmp_path):
    keychain = tmp_path / "work.keychain-db"
    keychain.write_bytes(b"")
    assert not reach()["keychain"]
    assert reach(read=[str(keychain)])["keychain"]


NOTIFY = """
import ctypes, hlyn, os, uuid
NAME = os.environ.get("HLYN_TEST_NAME") or "org.hlyn.test." + uuid.uuid4().hex
def put(value):
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    token = ctypes.c_int(0)
    rc = libc.notify_register_check(NAME.encode(), ctypes.byref(token))
    if rc != 0:
        return f"register failed {rc}"
    return f"set {libc.notify_set_state(token, ctypes.c_uint64(value))}"
def get():
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    token = ctypes.c_int(0)
    rc = libc.notify_register_check(NAME.encode(), ctypes.byref(token))
    if rc != 0:
        return f"register failed {rc}"
    state = ctypes.c_uint64(0)
    libc.notify_get_state(token, ctypes.byref(state))
    return f"state {state.value}"
"""


@pytest.mark.parametrize("net", [False, [443], True], ids=["off", "ports", "open"])
def test_notifyd_carries_nothing_between_agents_in_any_mode(net):
    """Measured 2026-09-28: under hlyn's profile notifyd refuses to register
    a sealed caller (status 8) in every mode, an open network included, so
    it carries nothing between agents. (An earlier note that it did came
    from machlab's own profile.) The name is this test's own."""
    done = boot(NOTIFY + f"""
a = hlyn.run(lambda: put(4242), net={net!r}, log=False)
b = hlyn.run(get, net={net!r}, log=False)
print("agent a:", a, "| agent b:", b)
""")
    print(done.stdout, done.stderr[-500:])
    assert "state 4242" not in done.stdout


def test_two_agents_pass_nothing_through_a_pasteboard_unless_the_network_is_open():
    """A pasteboard carried a value from one sealed agent to another in every
    mode (measured) until the Mach allowlist left the pasteboard service out.
    Each agent is its own `hlyn run` (CoreFoundation can't be used across a
    plain fork). The pasteboard is one this test makes, never the user's."""
    import os
    import subprocess

    here = os.path.dirname(os.path.abspath(__file__))
    agent = os.path.join(here, "pbagent.py")
    env = dict(os.environ, PYTHONPATH=SRC)

    def plain(*args: str) -> str:
        return subprocess.run([sys.executable, agent, *args], capture_output=True, text=True,
                              check=True).stdout.strip()

    def sealed(net: list[str], *args: str) -> str:
        done = subprocess.run([sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report",
                               "--read", here, *net, "--", sys.executable, agent, *args],
                              capture_output=True, text=True, env=env, check=False)
        return (done.stdout.strip().splitlines() or [done.stderr.strip()[-200:]])[-1]

    name = plain("new", "-")
    try:
        assert plain("write", name) == "wrote True" and plain("read", name) == "read secret-4242"
        for net, open_ in (([], False), (["--net", "443"], False), (["--net-any"], True)):
            plain("clear", name)
            a, b = sealed(net, "write", name), sealed(net, "read", name)
            print(f"net {' '.join(net) or 'off'}: agent a: {a} | agent b: {b}")
            assert (b == "read secret-4242") is open_
    finally:
        plain("done", name)
