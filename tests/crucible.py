#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Black-box regression probes for Hlyn's actual process sandbox.

Only creates synthetic canaries under a fresh temporary directory. Run as a
regular user with Hlyn installed, preferably in a disposable VM:
    python tests/crucible.py   (or: python3 -m pytest -vv -rA tests/crucible.py)

The probes deliberately attempt the action from inside hlyn.run()'s confined
child. Host-side code verifies the outcome after the child exits.
"""
from __future__ import annotations

import importlib.metadata
import os
import pathlib
import platform
import socket
import sys
import tempfile

try:
    import hlyn
except Exception as exc:
    print(f"ERROR: cannot import hlyn: {type(exc).__name__}: {exc}")
    print("Install the published build (or run from the tested checkout) first.")
    raise SystemExit(2)

CANARY = "HLYN_SYNTHETIC_PRIVATE_KEY_CANARY_7cbd6aa6"
FORGED = '{"kind":"seal","FORGED":true}\n'


def result(name: str, status: str, detail: str) -> None:
    print(f"{status:18} {name}: {detail}")


def call_hlyn(name: str, fn, **policy):
    """Run a probe in Hlyn. Separate policy refusal from execution outcome."""
    try:
        value = hlyn.run(fn, **policy)
        return ("RETURNED", value)
    except Exception as exc:
        return ("RAISED", f"{type(exc).__name__}: {exc}")


def main() -> int:
    try:
        version = importlib.metadata.version("hlyn")
    except Exception:
        version = "unknown (source checkout?)"
    print(f"Hlyn version: {version}")
    print(f"Platform: {platform.platform()}")
    if os.geteuid() == 0:
        print("WARNING: running as root; repeat as an ordinary user in a disposable VM.")
    print("All target files below are synthetic and created in a fresh temp directory.\n")

    failures = 0
    inconclusive = 0
    with tempfile.TemporaryDirectory(prefix="hlyn-blackbox-") as td:
        base = pathlib.Path(td)
        home = base / "fake-home"
        keydir = home / ".ssh"
        keydir.mkdir(parents=True)
        canary = keydir / "id_ed25519"
        canary.write_text(CANARY, encoding="utf-8")
        os.chmod(canary, 0o600)

        work = base / "project"
        work.mkdir()
        link = work / "scratch-link"
        link.symlink_to(keydir, target_is_directory=True)

        # Prevent ambient custom trust-store variables from causing unrelated
        # setup behavior; all resources in this test are synthetic.
        saved_ssl = {k: os.environ.get(k) for k in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
        for key in saved_ssl:
            os.environ.pop(key, None)
        try:
            def read_canary():
                try:
                    data = canary.read_text(encoding="utf-8")
                    return ("READ", data)
                except OSError as exc:
                    return ("BLOCKED", type(exc).__name__, exc.errno)

            state, value = call_hlyn(
                "tmp-symlink",
                read_canary,
                read=[], write=[], exec=False, net=False, env=False,
                tmp=str(link), log=False,
            )
            if state == "RETURNED" and isinstance(value, tuple) and value[0] == "READ" and value[1] == CANARY:
                result("tmp symlink to fake ~/.ssh", "VULNERABLE", "confined child read the synthetic key through tmp")
                failures += 1
            elif state == "RETURNED" and isinstance(value, tuple) and value[0] == "BLOCKED":
                result("tmp symlink to fake ~/.ssh", "BLOCKED", f"kernel denied read ({value[1]}, errno={value[2]})")
            elif state == "RAISED":
                # A policy rejection here is expected on a fixed build; other
                # setup failures need examination rather than being called pass.
                detail = str(value)
                if any(word in detail.lower() for word in ("tmp", "scratch", "symlink", "link", "key folder", "private")):
                    result("tmp symlink to fake ~/.ssh", "REFUSED", detail)
                else:
                    result("tmp symlink to fake ~/.ssh", "INCONCLUSIVE", detail)
                    inconclusive += 1
            else:
                result("tmp symlink to fake ~/.ssh", "INCONCLUSIVE", f"unexpected result: {state} {value!r}")
                inconclusive += 1

            # Black-box check for a prohibited TCP connection to a host-side
            # loopback canary. This tests the kernel boundary, not the proxy.
            tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp_server.bind(("127.0.0.1", 0))
            tcp_server.listen(1)
            tcp_server.settimeout(0.3)
            tcp_port = tcp_server.getsockname()[1]

            def attempt_tcp():
                # The socket is made inside the try: on Linux with the network
                # off, seccomp refuses creating it at all (EPERM), which is a block.
                client = None
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(0.5)
                    client.connect(("127.0.0.1", tcp_port))
                    return ("CONNECTED", None)
                except OSError as exc:
                    return ("BLOCKED", type(exc).__name__, exc.errno)
                finally:
                    if client is not None:
                        client.close()

            state, value = call_hlyn(
                "network-tcp", attempt_tcp,
                read=[], write=[], exec=False, net=False, env=False,
                tmp=False, log=False,
            )
            if state == "RETURNED" and isinstance(value, tuple) and value[0] == "CONNECTED":
                result("TCP to host loopback", "VULNERABLE", f"connected to denied port {tcp_port}")
                failures += 1
            elif state == "RETURNED" and isinstance(value, tuple) and value[0] == "BLOCKED":
                result("TCP to host loopback", "BLOCKED", f"kernel denied connection ({value[1]}, errno={value[2]})")
            else:
                result("TCP to host loopback", "INCONCLUSIVE", f"state={state}, result={value!r}")
                inconclusive += 1
            tcp_server.close()

            # UDP is checked by observing delivery at a local receiver. A
            # successful sendto() return alone is not enough to call a bypass.
            udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_server.bind(("127.0.0.1", 0))
            udp_server.settimeout(0.35)
            udp_port = udp_server.getsockname()[1]
            udp_marker = b"HLYN_UDP_EGRESS_CANARY_7cbd6aa6"

            def attempt_udp():
                client = None  # made inside the try, as for TCP
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sent = client.sendto(udp_marker, ("127.0.0.1", udp_port))
                    return ("SENT", sent)
                except OSError as exc:
                    return ("BLOCKED", type(exc).__name__, exc.errno)
                finally:
                    if client is not None:
                        client.close()

            state, value = call_hlyn(
                "network-udp", attempt_udp,
                read=[], write=[], exec=False, net=False, env=False,
                tmp=False, log=False,
            )
            delivered = False
            try:
                packet, _ = udp_server.recvfrom(2048)
                delivered = packet == udp_marker
            except socket.timeout:
                pass
            finally:
                udp_server.close()
            if delivered:
                result("UDP to host loopback", "VULNERABLE", f"denied datagram reached port {udp_port}")
                failures += 1
            elif state == "RETURNED" and isinstance(value, tuple) and value[0] in ("SENT", "BLOCKED"):
                result("UDP to host loopback", "BLOCKED", "no datagram reached the host-side receiver")
            else:
                result("UDP to host loopback", "INCONCLUSIVE", f"state={state}, result={value!r}")
                inconclusive += 1

            # A writable target directory is synthetic. The log path itself
            # lives in a non-writable-by-agent directory, but aliases that target.
            out = base / "writable-out"
            out.mkdir()
            logdir = base / "private-log-dir"
            logdir.mkdir()
            target = out / "audit.jsonl"
            target.write_text("initial\n", encoding="utf-8")
            loglink = logdir / "audit.jsonl"
            loglink.symlink_to(target)

            def replace_symlink_target():
                try:
                    target.unlink()
                    target.write_text(FORGED, encoding="utf-8")
                    return "FORGED_WRITTEN"
                except OSError as exc:
                    return f"BLOCKED:{type(exc).__name__}:{exc.errno}"

            state, value = call_hlyn(
                "log-symlink", replace_symlink_target,
                read=[], write=[str(out)], exec=False, net=False, env=False,
                tmp=False, log=str(loglink),
            )
            try:
                content = loglink.read_text(encoding="utf-8")
            except OSError as exc:
                content = f"<unreadable: {exc}>"
            if state == "RETURNED" and value == "FORGED_WRITTEN" and "FORGED" in content:
                result("audit log via symlink", "VULNERABLE", "confined child replaced the target; operator-facing log path is forged")
                failures += 1
            elif state == "RAISED" and any(word in str(value).lower() for word in ("log", "link", "symlink", "alias", "name")):
                result("audit log via symlink", "REFUSED", str(value))
            elif state == "RETURNED" and isinstance(value, str) and value.startswith("BLOCKED:"):
                result("audit log via symlink", "BLOCKED", value)
            else:
                result("audit log via symlink", "INCONCLUSIVE", f"state={state}, result={value!r}, log={content[:120]!r}")
                inconclusive += 1

            # Repeat with a hard link. It bypasses path-only checks because two
            # different names refer to the same inode.
            target2 = out / "audit-hardlink-target.jsonl"
            target2.write_text("initial-hardlink\n", encoding="utf-8")
            hardlog = logdir / "audit-hardlink.jsonl"
            os.link(target2, hardlog)

            def overwrite_hardlink_target():
                try:
                    target2.write_text(FORGED, encoding="utf-8")
                    return "FORGED_WRITTEN"
                except OSError as exc:
                    return f"BLOCKED:{type(exc).__name__}:{exc.errno}"

            state, value = call_hlyn(
                "log-hardlink", overwrite_hardlink_target,
                read=[], write=[str(out)], exec=False, net=False, env=False,
                tmp=False, log=str(hardlog),
            )
            try:
                content = hardlog.read_text(encoding="utf-8")
            except OSError as exc:
                content = f"<unreadable: {exc}>"
            if state == "RETURNED" and value == "FORGED_WRITTEN" and "FORGED" in content:
                result("audit log via hard link", "VULNERABLE", "confined child overwrote the inode shared with the audit path")
                failures += 1
            elif state == "RAISED" and any(word in str(value).lower() for word in ("log", "link", "alias", "name", "regular file")):
                result("audit log via hard link", "REFUSED", str(value))
            elif state == "RETURNED" and isinstance(value, str) and value.startswith("BLOCKED:"):
                result("audit log via hard link", "BLOCKED", value)
            else:
                result("audit log via hard link", "INCONCLUSIVE", f"state={state}, result={value!r}, log={content[:120]!r}")
                inconclusive += 1

        finally:
            for key, value in saved_ssl.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    print()
    if failures:
        print(f"RESULT: {failures} confirmed policy/audit integrity failure(s). Do not use this build as the sole boundary.")
        return 1
    if inconclusive:
        print(f"RESULT: no exploit was confirmed, but {inconclusive} probe(s) were inconclusive. This is not a pass.")
        return 2
    print("RESULT: no exploit was confirmed by these probes. This is still not proof that no escape exists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def crucible():
    """The probe above, run by the suite: every case must end refused (by the
    policy) or blocked (by the kernel). A confirmed failure or an inconclusive
    case both fail the test, since an inconclusive probe is not a pass."""
    import pytest

    if sys.platform not in ("linux", "darwin"):
        pytest.skip("no enforcement backend on this platform")
    assert main() == 0
