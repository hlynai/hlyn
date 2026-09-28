# SPDX-License-Identifier: Apache-2.0
"""macOS host mode at the Seatbelt level (DESIGN-host-allowlisting.md 5.4).

The profile a policy naming hosts produces, and what a process sealed with it
can and cannot reach: the proxy's port and `localhost:PORT` entries only, no
DNS, unix sockets only under write grants and never the refused list, and no
Mach service but the measured allowlist. Matrix rows 1, 2 (kernel half), 7,
22 and 25 at this layer; the whole path through the proxy is in
test_route.py. Every test prints what the sealed process saw.
"""

from __future__ import annotations

import os
import socket
import sys
import threading

import pytest
from conftest import jail

from hlyn.core import mac
from hlyn.policy import Policy

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is a macOS facility")


def serve(family=socket.AF_INET, host="127.0.0.1", path=None):
    """A listener that answers every connection with b'hi'. Returns (socket, port or path)."""
    if path:
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
    else:
        srv = socket.socket(family)
        srv.bind((host, 0))
    srv.listen(16)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(b"hi")
            conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv, (path or srv.getsockname()[1])


def sealed(body: str, policy: str, port: int):
    done = jail(body, policy=policy, seal=f"(lambda p: mac.load(p, None, {port}))")
    print(done.stdout, done.stderr[-2000:], sep="\n")
    return done


REACH = """
import socket
def reach(host, port, family=socket.AF_INET):
    s = socket.socket(family)
    s.settimeout(5)
    try:
        s.connect((host, port))
        print(host, port, "CONNECTED", s.recv(2))
    except OSError as e:
        print(host, port, "REFUSED", e.errno)
"""


# ---------------------------------------------------------------------------
# the profile text
# ---------------------------------------------------------------------------


def test_host_mode_replaces_the_blanket_mach_grant_with_the_allowlist():
    text = mac.profile(Policy(net=["api.openai.com"]), "TAG", 50000)
    print(text)
    assert "(allow mach-lookup)" not in text
    assert '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))' in text
    assert '(deny mach-lookup (with message "TAG") (global-name "com.apple.trustd.agent"))' in text
    assert '(deny mach-lookup (with message "TAG") (global-name "com.apple.dnssd.service"))' in text


def test_host_mode_allows_tcp_only_to_the_proxy_and_localhost_entries():
    text = mac.profile(Policy(net=["api.openai.com", "localhost:5432", "10.0.0.5:6379"]), None, 50000)
    tcp = [line for line in text.splitlines() if "remote tcp" in line]
    print("\n".join(tcp))
    assert tcp == [
        '(allow network-outbound (remote tcp "localhost:50000"))',
        '(allow network-outbound (remote tcp "localhost:5432"))',
    ]
    assert "(allow network*)" not in text and "mDNSResponder\"))" not in text.split("(deny")[0]
    assert "network-bind" not in text and "udp" not in text


def test_the_refused_unix_sockets_come_after_every_allow():
    text = mac.profile(Policy(net=["api.openai.com"], write=True), None, 50000)
    lines = text.splitlines()
    unix = "(allow network-outbound (remote unix-socket"
    last_allow = max(i for i, line in enumerate(lines) if unix in line)
    first_deny = min(i for i, line in enumerate(lines) if "(deny network-outbound" in line)
    print(lines[last_allow], lines[first_deny], sep="\n")
    assert last_allow < first_deny


def test_host_mode_needs_the_proxy_port():
    from hlyn.error import Invalid

    with pytest.raises(Invalid) as caught:
        mac.profile(Policy(net=["api.openai.com"]))
    print(caught.value)
    assert "proxy's port" in str(caught.value)


def test_port_mode_allows_the_measured_services_and_the_two_that_reach_the_network():
    text = mac.profile(Policy(net=[443]), None)
    print([line for line in text.splitlines() if "mach-lookup" in line or "443" in line])
    assert '(remote tcp "*:443")' in text
    assert "(allow mach-lookup)" not in text
    for name in (*mac.MACH, "com.apple.trustd.agent", "com.apple.dnssd.service"):
        assert f'(allow mach-lookup (global-name "{name}"))' in text


# ---------------------------------------------------------------------------
# a sealed process
# ---------------------------------------------------------------------------


def test_row_1_and_2_only_the_proxy_port_and_listed_localhost_ports_connect():
    proxy, port = serve()
    listed, db = serve()
    other, unlisted = serve()
    v6 = same = None
    try:
        v6, port6 = serve(socket.AF_INET6, "::1")
        # The proxy listens on [::1] too, on the same port number.
        same = socket.socket(socket.AF_INET6)
        same.bind(("::1", port))
        same.listen()
        threading.Thread(target=lambda: same.accept()[0].sendall(b"hi"), daemon=True).start()
    except OSError:
        port6 = None
    try:
        body = REACH + f"""
reach("127.0.0.1", {port})
reach("127.0.0.1", {db})
reach("127.0.0.1", {unlisted})
reach("1.1.1.1", 443)
reach("127.0.0.2", {port})
"""
        if port6:
            body += f'reach("::1", {port6}, socket.AF_INET6)\nreach("::1", {port}, socket.AF_INET6)\n'
        done = sealed(body, f'Policy(net=["api.example.com", "localhost:{db}"])', port)
    finally:
        for srv in (proxy, listed, other, v6, same):
            if srv:
                srv.close()
    out = done.stdout
    assert f"127.0.0.1 {port} CONNECTED b'hi'" in out
    assert f"127.0.0.1 {db} CONNECTED b'hi'" in out
    assert f"127.0.0.1 {unlisted} REFUSED 1" in out
    assert "1.1.1.1 443 REFUSED 1" in out
    assert f"127.0.0.2 {port} REFUSED 1" in out
    if port6:
        assert f"::1 {port6} REFUSED 1" in out
        assert f"::1 {port} CONNECTED b'hi'" in out


def test_row_7_no_name_resolves_but_localhost_and_udp_is_refused():
    body = """
import socket
for name in ("example.com", "localhost"):
    try:
        print(name, "RESOLVED", socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)[0][4])
    except OSError as e:
        print(name, "NO", e)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b"x" * 20, ("1.1.1.1", 53)); print("UDP SENT")
except OSError as e:
    print("UDP REFUSED", e.errno)
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("/var/run/mDNSResponder"); print("MDNS CONNECTED")
except OSError as e:
    print("MDNS REFUSED", e.errno)
"""
    proxy, port = serve()
    try:
        done = sealed(body, 'Policy(net=["api.example.com"])', port)
    finally:
        proxy.close()
    assert "example.com NO" in done.stdout
    assert "localhost RESOLVED" in done.stdout
    assert "UDP REFUSED 1" in done.stdout and "MDNS REFUSED 1" in done.stdout


def test_row_22_unix_sockets_need_a_write_grant_and_the_refused_list_always_wins():
    import shutil
    import tempfile

    # A short folder: macOS limits a socket path to 104 bytes.
    base = os.path.realpath(tempfile.mkdtemp(prefix="hlyn-", dir="/tmp"))
    granted = os.path.join(base, "granted")
    other = os.path.join(base, "other")
    os.makedirs(granted)
    os.makedirs(other)
    paths = [os.path.join(granted, "db.sock"), os.path.join(granted, "docker.sock"),
             os.path.join(granted, "podman.sock"), os.path.join(other, "db.sock")]
    servers = [serve(path=path)[0] for path in paths]
    body = "import socket\n" + "".join(
        f"""
s = socket.socket(socket.AF_UNIX)
try:
    s.connect({path!r}); print({path!r}, "CONNECTED", s.recv(2))
except OSError as e:
    print({path!r}, "REFUSED", e.errno)
""" for path in paths)
    proxy, port = serve()
    try:
        for policy in (f'Policy(net=["api.example.com"], write=[{granted!r}])',
                       'Policy(net=["api.example.com"], write=True)'):
            done = sealed(body, policy, port)
            said = dict(line.split(" ", 1) for line in done.stdout.splitlines() if line.startswith("/"))
            assert said[paths[0]].startswith("CONNECTED")
            assert said[paths[1]] == "REFUSED 1" and said[paths[2]] == "REFUSED 1"
            assert said[paths[3]] == ("CONNECTED b'hi'" if "write=True" in policy else "REFUSED 1")
    finally:
        for srv in (*servers, proxy):
            srv.close()
        shutil.rmtree(base)


def test_row_25_trustd_and_dnssd_are_refused_and_libinfo_works():
    body = """
import ctypes, pwd, os
lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
port = ctypes.c_uint32()
task = ctypes.c_uint32.in_dll(lib, "mach_task_self_")
bootstrap = ctypes.c_uint32.in_dll(lib, "bootstrap_port")
for name in (b"com.apple.trustd.agent", b"com.apple.dnssd.service", b"com.apple.nsurlsessiond",
             b"com.apple.system.opendirectoryd.libinfo"):
    rc = lib.bootstrap_look_up(bootstrap, name, ctypes.byref(port))
    print(name.decode(), "LOOKED UP" if rc == 0 else f"REFUSED {rc}")
print("user", pwd.getpwuid(os.getuid()).pw_name)
"""
    proxy, port = serve()
    try:
        done = sealed(body, 'Policy(net=["api.example.com"])', port)
    finally:
        proxy.close()
    out = done.stdout
    assert "com.apple.trustd.agent REFUSED" in out
    assert "com.apple.dnssd.service REFUSED" in out
    assert "com.apple.nsurlsessiond REFUSED" in out
    assert "com.apple.system.opendirectoryd.libinfo LOOKED UP" in out
    assert "user " in out
