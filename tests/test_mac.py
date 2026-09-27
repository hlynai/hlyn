"""Seatbelt confinement, exercised on a real macOS kernel.

`sandbox_init` is deprecated API on a very new OS, so the first thing these
tests establish is that it still enforces at all. Everything else is worthless
if it does not.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import jail

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Seatbelt is a macOS facility"
)

SEAL = "mac.load"


@pytest.fixture
def box(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "ok.txt").write_text("granted")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("classified")
    return inside, outside


# ---------------------------------------------------------------------------
# does it still work at all
# ---------------------------------------------------------------------------


def test_seatbelt_still_enforces():
    # The deprecation check. If Apple ever turns this into a no-op that still
    # returns success, this test is how we find out.
    done = jail(
        """
        try:
            open("/etc/hosts").read()
        except PermissionError:
            print("ENFORCED"); raise SystemExit(0)
        print("NOT ENFORCED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"sandbox_init reported success but did not enforce: {done.stdout}"
    assert "ENFORCED" in done.stdout


def test_python_survives_deny_by_default():
    # (deny default) on its own kills the interpreter before it reaches user
    # code. This proves the base allowances are sufficient.
    done = jail(
        """
        import json, hashlib, uuid, base64, random, threading, queue
        assert hashlib.sha256(b"x").hexdigest()
        assert len(os.urandom(16)) == 16
        print("ALIVE")
        """,
        before="import os",
        seal=SEAL,
    )
    assert done.returncode == 0, f"deny-by-default broke the interpreter:\n{done.stderr}"
    assert "ALIVE" in done.stdout


# ---------------------------------------------------------------------------
# reads and writes
# ---------------------------------------------------------------------------


def test_a_granted_path_is_readable(box):
    inside, _ = box
    done = jail(
        f"print(open({str(inside / 'ok.txt')!r}).read())",
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a granted path was not readable:\n{done.stderr}"
    assert "granted" in done.stdout


def test_a_path_outside_the_grant_is_refused(box):
    inside, outside = box
    done = jail(
        f"""
        try:
            open({str(outside / 'secret.txt')!r}).read()
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"read escaped the boundary: {done.stdout}"


def test_writing_outside_the_grant_is_refused(box):
    inside, outside = box
    done = jail(
        f"""
        try:
            open({str(outside / 'planted.txt')!r}, "w").write("owned")
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(write=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"write escaped the boundary: {done.stdout}"
    assert not (outside / "planted.txt").exists(), "the file was actually created"


def test_ssh_keys_are_refused_by_default():
    done = jail(
        """
        import os
        try:
            os.listdir(os.path.expanduser("~/.ssh"))
        except (PermissionError, FileNotFoundError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"~/.ssh was readable: {done.stdout}"


def test_a_symlink_cannot_leave_the_grant(box):
    inside, outside = box
    os.symlink(str(outside / "secret.txt"), str(inside / "escape"))
    done = jail(
        f"""
        try:
            open({str(inside / 'escape')!r}).read()
        except PermissionError:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        policy=f"Policy(read=[{str(inside)!r}])",
        seal=SEAL,
    )
    assert done.returncode == 0, f"a symlink walked out of the boundary: {done.stdout}"


# ---------------------------------------------------------------------------
# execution and network
# ---------------------------------------------------------------------------


def test_running_a_program_is_refused_by_default():
    done = jail(
        """
        import subprocess
        try:
            subprocess.run(["/bin/echo", "ESCAPED"], capture_output=True)
        except (PermissionError, OSError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"a program ran with exec denied: {done.stdout}"
    assert "ESCAPED" not in done.stdout


def test_network_is_refused_by_default():
    done = jail(
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(("1.1.1.1", 80))
        except (PermissionError, OSError):
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """,
        seal=SEAL,
    )
    assert done.returncode == 0, f"the network was reachable by default: {done.stdout}"


# ---------------------------------------------------------------------------
# the profile itself
# ---------------------------------------------------------------------------


def test_profile_denies_by_default():
    from hlyn.core import mac
    from hlyn.policy import Policy

    text = mac.profile(Policy())
    assert "(deny default)" in text
    assert text.startswith("(version 1)")


def test_profile_resolves_symlinked_paths():
    # The trap: /tmp is a symlink to /private/tmp, and Seatbelt matches after
    # resolution. An unresolved rule does not error, it simply never matches.
    from hlyn.core import mac
    from hlyn.policy import Policy

    text = mac.profile(Policy(read=["/tmp"]))
    assert "/private/tmp" in text, "paths were not resolved, so the rule cannot match"


def test_profile_uses_literal_for_files_and_subpath_for_directories():
    from hlyn.core import mac
    from hlyn.policy import Policy

    # The paths are asserted post-resolution, because that is the only form
    # Seatbelt ever sees. /etc and /usr/share/zoneinfo are both symlinks on
    # current macOS, which is exactly why the rule is written this way.
    text = mac.profile(Policy(read=["/etc/hosts", "/usr/share/zoneinfo"]))
    assert f'(literal "{os.path.realpath("/etc/hosts")}")' in text
    assert f'(subpath "{os.path.realpath("/usr/share/zoneinfo")}")' in text


def test_profile_refuses_a_path_that_does_not_exist():
    # It used to skip it. A typo in a security policy was therefore an error on
    # Linux and a silently missing rule on macOS -- and policies get written on
    # macOS and deployed on Linux, so the platform that drops the rule is the
    # one where nobody finds out.
    from hlyn.core import mac
    from hlyn.error import Invalid
    from hlyn.policy import Policy

    with pytest.raises(Invalid) as caught:
        mac.profile(Policy(read=["/tmp", "/definitely/not/here"]))
    assert "/definitely/not/here" in str(caught.value)


def test_profile_refuses_paths_it_cannot_express():
    from hlyn.core import mac
    from hlyn.error import Invalid

    with pytest.raises(Invalid):
        mac.quote('/tmp/we"ird')


def test_ready_is_true_here():
    from hlyn.core import mac

    assert mac.ready()


def test_profile_grants_the_root_directory_node():
    # Without this a spawned program dies inside dyld with SIGABRT and no
    # diagnostic. A subpath rule on a child never matches the root node, so
    # this is the one grant that cannot be inferred from the policy's paths.
    from hlyn.core import mac
    from hlyn.policy import Policy

    assert '(allow file-read* (literal "/"))' in mac.profile(Policy())


def test_framework_python_can_reach_its_inner_interpreter():
    # bin/pythonX.Y is a stub that re-execs Resources/Python.app. Granting
    # execute on the stub alone fails with a bare posix_spawn error.
    import os as _os

    from hlyn.policy import loader

    inner = _os.path.join(sys.prefix, "Resources")
    if not _os.path.exists(inner):
        pytest.skip("not a framework build")
    assert inner in loader()


def test_a_virtualenv_python_runs_under_hlyn_run(tmp_path):
    # A venv's python is a link to a framework stub that re-execs the real
    # interpreter in Resources/Python.app. Only the stub used to be granted,
    # so `hlyn run -- .venv/bin/python` failed every time on python.org builds.
    import subprocess as _sp

    from conftest import SRC

    venv = tmp_path / "venv"
    _sp.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    done = _sp.run(
        [sys.executable, "-m", "hlyn.cli", "run", "--no-log", "--no-report", "--",
         str(venv / "bin" / "python"), "-c", "print('UP')"],
        capture_output=True, text=True, env={"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin"}, check=False,
    )
    assert "UP" in done.stdout, done.stderr


def test_companion_finds_the_framework_interpreter():
    from hlyn.policy import companion

    inner = companion(sys.executable)
    if "/Python.framework/" not in os.path.realpath(sys.executable):
        assert inner is None
    else:
        assert inner and inner.endswith("/Resources/Python.app")
    assert companion("/bin/ls") is None


# ---------------------------------------------------------------------------
# system services that reach the network for the caller (net=False)
# ---------------------------------------------------------------------------
#
# The base profile allows Mach lookups, and two macOS services go on the
# network for whoever asks: trustd fetches the issuer URLs written inside a
# certificate it is asked to check, and dnssd.service looks up names. Both
# carried data past net=False until they were refused (FINDINGS.md, "the
# blanket mach-lookup grant").

# Asks Security.framework to check a certificate, network fetches allowed, the
# way any HTTPS client on macOS does. Plain Python, so no compiler is needed.
CHECK = """
import ctypes, ctypes.util, sys
cf = ctypes.CDLL(ctypes.util.find_library("CoreFoundation"))
sec = ctypes.CDLL(ctypes.util.find_library("Security"))
V = ctypes.c_void_p
cf.CFDataCreate.restype = V
cf.CFDataCreate.argtypes = [V, ctypes.c_char_p, ctypes.c_long]
sec.SecCertificateCreateWithData.restype = V
sec.SecCertificateCreateWithData.argtypes = [V, V]
sec.SecPolicyCreateBasicX509.restype = V
sec.SecTrustCreateWithCertificates.argtypes = [V, V, ctypes.POINTER(V)]
sec.SecTrustSetNetworkFetchAllowed.argtypes = [V, ctypes.c_bool]
sec.SecTrustEvaluateWithError.restype = ctypes.c_bool
sec.SecTrustEvaluateWithError.argtypes = [V, ctypes.POINTER(V)]
der = open(sys.argv[1], "rb").read()
cert = sec.SecCertificateCreateWithData(None, cf.CFDataCreate(None, der, len(der)))
trust = V()
sec.SecTrustCreateWithCertificates(cert, sec.SecPolicyCreateBasicX509(), ctypes.byref(trust))
sec.SecTrustSetNetworkFetchAllowed(trust, True)
err = V()
print("CHECKED, trusted:", sec.SecTrustEvaluateWithError(trust, ctypes.byref(err)))
"""


@pytest.fixture
def listener():
    """A local HTTP server that records every path requested of it."""
    got: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the stdlib's name
            got.append(f"{self.path} (User-Agent: {self.headers.get('User-Agent')})")
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], got
    server.shutdown()


def _leaf(folder, url: str):
    """A certificate whose issuer is missing, with its issuer URL set to `url`."""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is needed to make a test certificate")

    def run(*args: str) -> None:
        subprocess.run([openssl, *args], cwd=folder, check=True, capture_output=True)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "2", "-subj", "/CN=hlyn test issuer")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
        "-subj", "/CN=leak.example")
    (folder / "leaf.ext").write_text(f"authorityInfoAccess=caIssuers;URI:{url}\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", "leaf.der", "-outform", "DER", "-days", "2",
        "-extfile", "leaf.ext")
    return folder / "leaf.der"


def test_trustd_cannot_fetch_for_a_program_with_the_network_off(tmp_path, listener):
    port, got = listener
    secret = f"SECRET-{uuid.uuid4().hex[:8]}"
    leaf = _leaf(tmp_path, f"http://127.0.0.1:{port}/{secret}.cer")
    check = tmp_path / "check.py"
    check.write_text(CHECK)

    # The control: unconfined, trustd does fetch the URL. Without this the
    # confined half would pass on any machine where trustd happens not to.
    free = subprocess.run([sys.executable, str(check), str(leaf)],
                          capture_output=True, text=True, timeout=60, check=False)
    print("unconfined:", free.stdout.strip(), free.stderr.strip(), "| listener got:", got)
    if not any(secret in hit for hit in got):
        pytest.skip("trustd did not fetch the issuer URL even unconfined, so this proves nothing")

    got.clear()
    secret = f"SECRET-{uuid.uuid4().hex[:8]}"
    leaf = _leaf(tmp_path, f"http://127.0.0.1:{port}/{secret}.cer")
    done = jail(
        f"""
        import runpy, sys
        sys.argv = [{str(check)!r}, {str(leaf)!r}]
        runpy.run_path({str(check)!r})
        """,
        policy=f"Policy(read=[{str(tmp_path)!r}])",
        seal=SEAL,
    )
    time.sleep(2)  # trustd fetches asynchronously
    print("net=False:", done.stdout.strip(), done.stderr.strip()[-300:], "| listener got:", got)
    assert "CHECKED" in done.stdout, f"the check never ran: {done.stderr}"
    assert not got, f"trustd fetched a URL for a program with net=False: {got}"


FETCH = """
import Foundation
let sem = DispatchSemaphore(value: 0)
URLSession.shared.dataTask(with: URL(string: CommandLine.arguments[1])!) { _, r, e in
    if let h = r as? HTTPURLResponse { print("STATUS", h.statusCode) }
    else { print("ERROR", (e as NSError?)?.code ?? 0, e?.localizedDescription ?? "?") }
    sem.signal()
}.resume()
_ = sem.wait(timeout: .now() + 20)
"""
CANNOT_FIND_HOST = -1003  # NSURLErrorCannotFindHost


@pytest.fixture(scope="module")
def fetch(tmp_path_factory):
    """A Swift URLSession client, which looks names up through dnssd.service."""
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is needed to build a URLSession client")
    folder = tmp_path_factory.mktemp("fetch")
    (folder / "fetch.swift").write_text(FETCH)
    subprocess.run([swiftc, "-O", "fetch.swift", "-o", "fetch"], cwd=folder, check=True,
                   capture_output=True, timeout=300)
    return folder / "fetch"


def test_dnssd_cannot_look_up_names_with_the_network_off(fetch):
    url = "http://example.com/"
    free = subprocess.run([str(fetch), url], capture_output=True, text=True, timeout=60,
                          check=False)
    print("unconfined:", free.stdout.strip())
    if f"ERROR {CANNOT_FIND_HOST}" in free.stdout or not free.stdout:
        pytest.skip("example.com does not resolve here even unconfined, so this proves nothing")

    done = jail(
        f"""
        import subprocess
        out = subprocess.run([{str(fetch)!r}, {url!r}], capture_output=True, text=True)
        print(out.stdout)
        """,
        policy=f"Policy(exec=[{str(fetch)!r}])",
        seal=SEAL,
    )
    print("net=False:", done.stdout.strip())
    # Before the fix the name resolved and only the TCP connect was refused
    # (ERROR 1, "Operation not permitted"): the lookup itself had left.
    assert f"ERROR {CANNOT_FIND_HOST}" in done.stdout, (
        f"the name lookup was not refused, so it left the machine: {done.stdout}{done.stderr}"
    )


def test_the_two_services_are_refused_only_with_the_network_off():
    from hlyn.core import mac
    from hlyn.policy import Policy

    for net, refused in ((False, True), ([443], False), (True, False)):
        text = mac.profile(Policy(net=net), tag="T")
        print(f"net={net!r}:", [line for line in text.splitlines() if "mach-lookup" in line])
        for name in ("com.apple.trustd.agent", "com.apple.dnssd.service"):
            rule = f'(deny mach-lookup (with message "T") (global-name "{name}"))'
            assert (rule in text) is refused
            if refused:
                # Seatbelt takes the last matching rule, so the refusal must
                # come after the blanket grant or it does nothing.
                assert text.index(rule) > text.index("(allow mach-lookup)")


def test_a_refused_service_is_reported_with_what_to_do():
    from hlyn.policy import Policy
    from hlyn.report import Denial, Report

    report = Report(Policy())
    for name in ("com.apple.trustd.agent", "com.apple.dnssd.service"):
        report.add(Denial(kind="system", target=name, op="mach-lookup", by="curl", pid=1,
                          count=1, source="kernel"))
    report.add(Denial(kind="system", target="com.apple.cfprefsd.daemon", op="mach-lookup",
                      by="curl", pid=1, count=1, source="kernel"))
    text = report.text(1, ["curl"])
    print(text)
    assert "macOS service com.apple.trustd.agent" in text
    assert "macOS service com.apple.dnssd.service" in text
    assert "--net 443" in text
    assert "cfprefsd" not in text  # plumbing stays out of the list
    assert report.system == 1
