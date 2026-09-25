"""Allowing the network has to mean the network works.

`net=[443]` used to confine a program so tightly it could not make an HTTPS
request: on Linux the resolver could not read `/etc/resolv.conf` and no
certificate authority loaded; on macOS the resolver's socket was refused. None
of those failures mention a path, so they read as a network problem rather
than a policy one. Every check here runs offline.
"""

from __future__ import annotations

import os
import sys

import pytest
from conftest import boot

from hlyn.policy import LOOKUP, TRUST, Policy, network, under

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")

# Where keys live beside the certificates. None of it may ever be granted.
PRIVATE = ("/etc/ssl/private", "/etc/pki/tls/private", "/etc/pki/CA/private")


def test_network_files_never_reach_a_private_key_directory():
    granted = network()
    for secret in PRIVATE:
        assert not any(under(secret, item) for item in granted), (
            f"{secret} is reachable through {granted}"
        )


def test_the_fixed_lists_never_name_a_directory_that_holds_keys():
    # Checked against the lists themselves, not just this machine: a layout
    # that does not exist here still ships to machines where it does.
    for item in (*LOOKUP, *TRUST):
        for secret in PRIVATE:
            assert not under(secret, item), f"{item} would grant {secret}"


def test_network_files_exist_or_are_left_out():
    # A path that does not exist refuses the whole seal on both backends.
    assert all(os.path.exists(item) for item in network())


def test_allowing_the_network_grants_the_files_it_needs():
    reads = Policy(net=[443]).reads()
    assert isinstance(reads, tuple)
    missing = [item for item in network() if not any(under(item, root) for root in reads)]
    assert not missing, f"allowed the network but not {missing}"


def test_a_closed_network_grants_none_of_them():
    reads = Policy().reads()
    assert isinstance(reads, tuple)
    for item in LOOKUP:
        if os.path.exists(item):
            assert not any(under(item, root) for root in reads), f"{item} granted with net off"


def test_the_whole_network_gets_them_too():
    reads = Policy(net=True).reads()
    assert isinstance(reads, tuple)
    for item in network():
        assert any(under(item, root) for root in reads)


@here
@pytest.mark.parametrize("net", ["[443]", "True"])
def test_certificate_authorities_load_under_confinement(net):
    done = boot(
        f"""
        import hlyn, ssl
        hlyn.on(hlyn.Policy(net={net}, log=False))
        print("CA", ssl.create_default_context().cert_store_stats()["x509_ca"])
        """
    )
    count = int(done.stdout.split("CA")[1]) if "CA" in done.stdout else 0
    assert count > 0, f"no certificate authority loaded, so TLS cannot verify:\n{done.stderr}"


@here
def test_a_name_resolves_under_confinement():
    done = boot(
        """
        import hlyn, socket
        hlyn.on(hlyn.Policy(net=[443], log=False))
        print("OK", socket.getaddrinfo("localhost", 443)[0][4][0])
        """
    )
    assert "OK" in done.stdout, f"name lookup failed with the network allowed:\n{done.stderr}"


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock")
def test_the_resolver_configuration_stays_closed_when_the_network_is():
    if not os.path.exists("/etc/resolv.conf"):
        pytest.skip("no /etc/resolv.conf here")
    done = boot(
        """
        import hlyn
        hlyn.on(hlyn.Policy(log=False))
        try:
            open("/etc/resolv.conf").read(); print("OPEN")
        except PermissionError:
            print("CLOSED")
        """
    )
    assert "CLOSED" in done.stdout, done.stdout + done.stderr
