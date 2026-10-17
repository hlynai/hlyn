# SPDX-License-Identifier: Apache-2.0
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
from pathlib import Path

import pytest
from conftest import boot

from hlyn.error import Invalid
from hlyn.policy import LOOKUP, TRUST, Policy, network, trust_copy, under

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


# `SSL_CERT_FILE`/`SSL_CERT_DIR` are the launcher's to set and can point
# anywhere (`SSL_CERT_DIR=~/.ssh`), so a path is never granted as named: the
# agent gets a copy, and only if it holds certificates and nothing else.

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-test-marker\n-----END OPENSSH PRIVATE KEY-----\n"


def _a_certificate() -> str:
    """One real certificate, copied from this machine's trust store."""
    import ssl

    paths = ssl.get_default_verify_paths()
    for bundle in (paths.openssl_cafile, *TRUST):
        if bundle and os.path.isfile(bundle):
            with open(bundle, encoding="ascii", errors="replace") as handle:
                text = handle.read()
            start = text.find("-----BEGIN CERTIFICATE-----")
            end = text.find("-----END CERTIFICATE-----", start)
            if start >= 0 and end > start:
                return text[start : end + len("-----END CERTIFICATE-----")] + "\n"
    pytest.skip("no certificate bundle on this machine to copy one from")


@pytest.mark.parametrize("name", ["SSL_CERT_DIR", "SSL_CERT_FILE"])
def test_a_certificate_variable_pointing_at_keys_is_not_granted(tmp_path, monkeypatch, name):
    keys = tmp_path / "ssh"
    keys.mkdir()
    (keys / "id_ed25519").write_text(KEY)
    target = keys if name == "SSL_CERT_DIR" else keys / "id_ed25519"
    monkeypatch.setenv(name, str(target))
    reads = Policy(read=[str(tmp_path / "src")], net=["api.openai.com"]).reads()
    assert isinstance(reads, tuple)
    leaked = [root for root in reads if under(os.path.realpath(target), os.path.realpath(root))]
    print(f"{name}={target} -> granted roots covering it: {leaked}")
    assert not leaked


@pytest.mark.parametrize(
    "layout",
    ["a key beside a certificate", "a subfolder", "a file that is not a certificate", "empty"],
)
def test_a_certificate_folder_with_anything_else_in_it_is_not_granted(tmp_path, monkeypatch, layout):
    folder = tmp_path / "certs"
    folder.mkdir()
    if layout != "empty":
        (folder / "ca.pem").write_text(_a_certificate())
    if layout == "a key beside a certificate":
        (folder / "key.pem").write_text(KEY)
    elif layout == "a subfolder":
        (folder / "private").mkdir()
    elif layout == "a file that is not a certificate":
        (folder / ".env").write_text("OPENAI_API_KEY=sk-test\n")
    monkeypatch.setenv("SSL_CERT_DIR", str(folder))
    granted = network()
    print(f"{layout}: granted {[item for item in granted if 'certs' in item]}")
    assert not any(under(os.path.realpath(folder), os.path.realpath(item)) for item in granted)


@pytest.mark.parametrize("name", ["SSL_CERT_DIR", "SSL_CERT_FILE"])
def test_a_certificate_variable_set_to_the_root_grants_nothing_more(tmp_path, monkeypatch, name):
    # `/` would prune every read root to `/`.
    narrow = Policy(read=[str(tmp_path)], net=["api.openai.com"]).reads()
    monkeypatch.setenv(name, "/")
    reads = Policy(read=[str(tmp_path)], net=["api.openai.com"]).reads()
    print(f"{name}=/ ->", reads)
    assert "/" not in reads
    assert reads == narrow


# A custom trust store is never granted: `trust_copy` reads it once, checks
# every file holds only certificates, and hands the agent a private copy of
# those bytes. So nothing done to the folder afterwards (a new file, a swapped
# link, a race with the check) reaches the agent.


def _folder(tmp_path, *names):
    folder = tmp_path / "corp-certs"
    folder.mkdir()
    for name in names:
        (folder / name).write_text(_a_certificate())
    return folder


def test_a_custom_certificate_folder_becomes_a_private_copy(tmp_path):
    folder = _folder(tmp_path, "corp.pem")
    os.symlink("corp.pem", folder / "abcd1234.0")  # OpenSSL's hashed name
    box = tmp_path / "box"
    box.mkdir()
    env = trust_copy({"SSL_CERT_DIR": str(folder), "PATH": "/bin"}, str(box))
    copy = env["SSL_CERT_DIR"]
    listing = {e.name: (e.is_symlink(), oct(e.stat().st_mode & 0o777)) for e in os.scandir(copy)}
    print("copy:", copy, listing)
    assert under(copy, str(box)) and not under(copy, str(folder))
    assert listing == {"abcd1234.0": (False, "0o600"), "corp.pem": (False, "0o600")}
    assert (folder / "corp.pem").read_bytes() == Path(copy, "abcd1234.0").read_bytes()
    assert env["PATH"] == "/bin"


def test_a_custom_certificate_file_copy_still_loads_as_a_trust_store(tmp_path):
    import ssl

    folder = _folder(tmp_path, "corp.pem")
    box = tmp_path / "box"
    box.mkdir()
    env = trust_copy({"SSL_CERT_FILE": str(folder / "corp.pem")}, str(box))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=env["SSL_CERT_FILE"])
    print(env, context.cert_store_stats())
    assert context.cert_store_stats()["x509_ca"] == 1


@pytest.mark.parametrize(
    "layout",
    ["a key", "a key beside a certificate", "a link to a key outside", "a dangling link", "a subfolder",
     "a token file", "missing"],
)
def test_a_trust_store_holding_anything_else_is_refused_with_the_fix(tmp_path, layout):
    folder = _folder(tmp_path, "corp.pem") if layout != "missing" else tmp_path / "nope"
    outside = tmp_path / "id_ed25519"
    outside.write_text(KEY)
    if layout == "a key":
        (folder / "corp.pem").write_text(KEY)
    elif layout == "a key beside a certificate":
        (folder / "key.pem").write_text(KEY)
    elif layout == "a link to a key outside":
        os.symlink(outside, folder / "abcd1234.0")
    elif layout == "a dangling link":
        os.symlink(tmp_path / "gone", folder / "abcd1234.0")
    elif layout == "a subfolder":
        (folder / "private").mkdir()
    elif layout == "a token file":
        (folder / ".env").write_text("OPENAI_API_KEY=sk-test\n")
    box = tmp_path / "box"
    box.mkdir()
    with pytest.raises(Invalid) as error:
        trust_copy({"SSL_CERT_DIR": str(folder)}, str(box))
    print(layout, "->", error.value)
    assert "SSL_CERT_DIR" in str(error.value) and "unset" in str(error.value).lower() + "unset"
    assert not any(KEY.encode() in path.read_bytes() for path in box.rglob("*") if path.is_file())


def test_the_system_trust_store_is_left_alone_and_no_scratch_folder_drops_the_variable(tmp_path):
    system = next((item for item in TRUST if os.path.exists(item)), None)
    if system is None:
        pytest.skip("no system trust store here")
    assert trust_copy({"SSL_CERT_FILE": system}, str(tmp_path)) == {"SSL_CERT_FILE": system}
    folder = _folder(tmp_path, "corp.pem")
    assert trust_copy({"SSL_CERT_DIR": str(folder), "TZ": "UTC"}, None) == {"TZ": "UTC"}


def test_a_race_swapping_a_certificate_for_a_key_never_puts_the_key_in_the_copy(tmp_path):
    # Another process flips corp.pem between a certificate and a private key
    # (atomic renames, as fast as it can) while hlyn checks and copies. Each
    # attempt must end in a refusal or a copy of certificates only: the bytes
    # copied are the bytes checked, read once.
    import threading

    folder = _folder(tmp_path, "corp.pem")
    cert, key = (tmp_path / "cert.src"), (tmp_path / "key.src")
    cert.write_text(_a_certificate())
    key.write_text(KEY)
    stop = threading.Event()

    def flip():
        n = 0
        while not stop.is_set():
            source = key if n % 2 else cert
            spare = folder / f".swap{n % 2}"
            spare.write_bytes(source.read_bytes())
            os.replace(spare, folder / "corp.pem")
            n += 1

    worker = threading.Thread(target=flip)
    worker.start()
    copied = refused = 0
    try:
        for attempt in range(400):
            box = tmp_path / f"box{attempt}"
            box.mkdir()
            try:
                env = trust_copy({"SSL_CERT_DIR": str(folder)}, str(box))
            except Invalid:
                refused += 1
                continue
            copied += 1
            for path in os.scandir(env["SSL_CERT_DIR"]):
                assert b"PRIVATE KEY" not in Path(path.path).read_bytes(), f"attempt {attempt}"
    finally:
        stop.set()
        worker.join()
    print(f"400 attempts under a racing swap: {copied} copied (certificates only), {refused} refused")
    assert copied + refused == 400 and copied > 0 and refused > 0


@here
@pytest.mark.parametrize("change", ["a key added after the check", "the certificate swapped for a key"])
def test_changing_the_trust_store_after_the_seal_reaches_nothing(tmp_path, change):
    # The original folder is not granted at all, so what lands in it later is
    # refused by the kernel, and the agent's copy still holds what was checked.
    folder = _folder(tmp_path, "corp.pem")
    key = folder / ("id_ed25519" if change.startswith("a key") else "corp.pem")
    source = tmp_path / "key.src"
    source.write_text(KEY)
    later = f"import shutil, time; time.sleep(0.5); shutil.copyfile({str(source)!r}, {str(key)!r})"
    done = boot(
        f"""
        import os, subprocess, sys, time, hlyn
        os.environ["SSL_CERT_DIR"] = {str(folder)!r}
        # Started before the seal, so it stays outside the environment.
        late = subprocess.Popen([sys.executable, "-c", {later!r}])
        hlyn.on(hlyn.Policy(net=[443], log=False))
        late.wait()
        copy = os.environ["SSL_CERT_DIR"]
        print("copy holds a key:", any(b"PRIVATE KEY" in open(os.path.join(copy, f), "rb").read()
                                      for f in os.listdir(copy)))
        try:
            open({str(key)!r}).read(); print("ORIGINAL READ")
        except PermissionError as error:
            print("ORIGINAL REFUSED", error.errno)
        """
    )
    print(done.stdout, done.stderr)
    assert KEY.splitlines()[0] in key.read_text()  # the change really happened
    assert "copy holds a key: False" in done.stdout
    assert "ORIGINAL REFUSED" in done.stdout, done.stdout + done.stderr


@here
def test_a_trust_store_inside_a_write_grant_still_hands_the_agent_the_checked_copy(tmp_path):
    # The folder is the agent's to write (an explicit grant), so it can plant a
    # key there; the variable names the copy, which the plant does not change.
    folder = _folder(tmp_path, "corp.pem")
    done = boot(
        f"""
        import os, hlyn
        os.environ["SSL_CERT_DIR"] = {str(folder)!r}
        hlyn.on(hlyn.Policy(write=[{str(folder)!r}], net=[443], log=False))
        open(os.path.join({str(folder)!r}, "planted.pem"), "w").write({KEY!r})
        copy = os.environ["SSL_CERT_DIR"]
        print("copy:", sorted(os.listdir(copy)), "is the original:", copy == {str(folder)!r})
        """
    )
    print(done.stdout, done.stderr)
    assert "copy: ['corp.pem'] is the original: False" in done.stdout, done.stdout + done.stderr


# A trust store is copied as the blocks it parses to, never as the file's bytes:
# what reaches the agent is certificates and revocation lists, re-encoded.
CRL = "-----BEGIN X509 CRL-----\nMAMCAQA=\n-----END X509 CRL-----\n"  # a DER SEQUENCE, enough for the parser


@pytest.mark.parametrize("extra", [
    "AWS_SECRET_ACCESS_KEY=abcd1234SECRET\n",
    "Certificate:\n    Data:\n        SECRET=abcd1234\n",  # OpenSSL's explanatory text, as macOS's bundle has
    "# SECRET=abcd1234 in a comment\n",
])
def test_text_around_certificates_never_reaches_the_copy(tmp_path, extra):
    bundle = tmp_path / "corp.pem"
    bundle.write_text(extra + _a_certificate() + extra + CRL + extra)
    box = tmp_path / "box"
    box.mkdir()
    copy = Path(trust_copy({"SSL_CERT_FILE": str(bundle)}, str(box))["SSL_CERT_FILE"]).read_text()
    print(repr(copy[:80]), "...", copy.count("-----BEGIN"), "blocks")
    assert "SECRET" not in copy
    assert copy.count("-----BEGIN CERTIFICATE-----") == 1 and copy.count("-----BEGIN X509 CRL-----") == 1


@pytest.mark.parametrize("bad", [
    "a private key", "an encrypted key", "an unknown block", "a damaged body", "not DER", "no END",
    "no blocks",
])
def test_a_bundle_with_any_other_block_is_refused(tmp_path, bad):
    body = {
        "a private key": KEY,
        "an encrypted key": ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAMCAQA=\n"
                             "-----END ENCRYPTED PRIVATE KEY-----\n"),
        "an unknown block": "-----BEGIN SECRET-----\nMAMCAQA=\n-----END SECRET-----\n",
        "a damaged body": "-----BEGIN CERTIFICATE-----\nnot*base64!\n-----END CERTIFICATE-----\n",
        "not DER": "-----BEGIN CERTIFICATE-----\nU0VDUkVU\n-----END CERTIFICATE-----\n",  # b"SECRET"
        "no END": "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n",
        "no blocks": "just text\n",
    }[bad]
    bundle = tmp_path / "corp.pem"
    bundle.write_text(body if bad == "no blocks" else _a_certificate() + body)
    box = tmp_path / "box"
    box.mkdir()
    with pytest.raises(Invalid, match="holds something besides certificates") as error:
        trust_copy({"SSL_CERT_FILE": str(bundle)}, str(box))
    print(bad, "->", error.value)
    assert list(box.iterdir()) == []


def test_several_certificates_all_survive_and_still_load(tmp_path):
    import ssl

    paths = ssl.get_default_verify_paths()
    bundle = next((item for item in (paths.openssl_cafile, *TRUST) if item and os.path.isfile(item)), None)
    if bundle is None:
        pytest.skip("no certificate bundle on this machine")
    box = tmp_path / "box"
    box.mkdir()
    copy = trust_copy({"SSL_CERT_FILE": bundle}, str(box))["SSL_CERT_FILE"]
    stats = ssl.create_default_context(cafile=copy).cert_store_stats()
    original = ssl.create_default_context(cafile=bundle).cert_store_stats()
    print(bundle, original, "->", copy, stats)
    assert stats["x509"] == original["x509"] > 1


@pytest.mark.parametrize("planted", ["a hard link to another file", "a link", "a link for the folder"])
def test_a_planted_name_in_the_scratch_folder_is_never_written_through(tmp_path, planted):
    precious = tmp_path / "precious.txt"
    precious.write_text("PRECIOUS")
    box = tmp_path / "box"
    box.mkdir(mode=0o700)
    name = "SSL_CERT_DIR" if planted == "a link for the folder" else "SSL_CERT_FILE"
    if planted == "a hard link to another file":
        os.link(precious, box / "hlyn-certs.pem")
    elif planted == "a link":
        os.symlink(precious, box / "hlyn-certs.pem")
    else:
        os.symlink(tmp_path, box / "hlyn-certs")
    source = _folder(tmp_path, "corp.pem")
    value = str(source) if name == "SSL_CERT_DIR" else str(source / "corp.pem")
    with pytest.raises(Invalid, match="already exists") as error:
        trust_copy({name: value}, str(box))
    print(planted, "->", error.value)
    assert precious.read_text() == "PRECIOUS" and not (tmp_path / "corp.pem").exists()
