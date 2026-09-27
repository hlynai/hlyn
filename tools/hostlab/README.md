# hostlab

Experiments behind DESIGN-host-allowlisting.md section 11 and the 2026-09-27 FINDINGS.md entries.

Linux (any 6.12+ kernel; Docker Desktop's VM works):

```bash
docker build -t hlynlab tools/hostlab
docker run --rm -v "$PWD/tools/hostlab:/lab" hlynlab python3 /lab/q1.py                                   # unbound unix sockets in /proc/PID/net/unix
docker run --rm -v "$PWD/tools/hostlab:/lab" hlynlab sh -c 'gcc -o /tmp/t /lab/q2.c -lseccomp && /tmp/t'   # notify fd POLLHUP
docker run --rm --security-opt seccomp=unconfined -v "$PWD/tools/hostlab:/lab" hlynlab sh -c 'gcc -o /tmp/t /lab/q3b.c -lseccomp && /tmp/t'   # socket-family allowlist
docker run --rm --security-opt seccomp=unconfined -v "$PWD/tools/hostlab:/lab" hlynlab sh -c 'gcc -o /tmp/t /lab/q5.c && /tmp/t'   # Landlock vs TCP Fast Open
```

The Fast Open bypass against hlyn itself: unzip a Linux wheel into `tools/hostlab/wheel`, then in the container start `tfo_listen.py` and run `tfo_agent.py` under `hlyn run --net 443 --read /lab`.

macOS: `./certs.sh`, `swiftc -O fetch.swift -o fetch`, `python3 listen.py &`, then `python3 machlab.py` (Mach services each client needs). The trustd fetch: `security verify-cert` stopped fetching issuer URLs by default on macOS 27.0, so use a client that allows network fetches, as `tests/test_mac.py::test_trustd_cannot_fetch_for_a_program_with_the_network_off` does (Security.framework through ctypes, `SecTrustSetNetworkFetchAllowed`).
