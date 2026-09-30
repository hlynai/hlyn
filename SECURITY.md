# Security

hlyn is a containment layer. A defect in it is not a crash — it is a boundary
that is quietly wider than the person who configured it believes. Please treat
findings accordingly.

## Reporting a vulnerability

Email **security@hlyn.dev** with:

- what the boundary was configured to be,
- what you were able to do anyway,
- the kernel version and `hlyn probe` output from the machine.

Please do not open a public issue for a working escape.

We will acknowledge within 3 working days and aim to have a fix or a clear
explanation within 30 days. Credit is given to reporters who want it.

## What counts as a vulnerability

Anything that lets a confined process reach past its policy:

- reading, writing, or executing a path the policy did not grant,
- reaching a TCP port the policy did not name,
- reaching a host `net` does not list, or reaching anything at all except
  through hlyn's proxy when `net` names hosts (a direct connection, UDP, DNS,
  another socket family, another run's proxy, or hlyn's helpers themselves),
- anything in the "It stops" list below that you can make happen,
- reaching another agent's process, memory, signals, or descriptors when the
  policy did not allow it,
- removing, weakening, or escaping the confinement after it has been applied,
- `seal` returning success when the kernel applied less than the whole policy.

That last one matters as much as the rest. Reporting a boundary that is not
there is the single worst outcome this project can produce, so a silent
downgrade is a vulnerability even if nothing escaped.

## What does not

These are documented limits, not defects. They are in the README, in the API
docstrings, and in the error messages:

- **Named ports restrict TCP only, and reach every host on them.**
  `net=[443]` leaves UDP reachable. Name hosts instead, or use `net=False` to
  close the network entirely.
- **What naming hosts does not stop**, listed below: data sent to a host you
  allowed, domain fronting, two corners of unix sockets (a refused socket inside
  a write grant on Linux 7.1+ without a gate; a datagram socket handed in from
  outside before 7.1), and the rest.
- **macOS: an open network shares system services.** Unless the network is
  open, an agent reaches only measured system services (no pasteboard, no
  notifications, the keychain only with a readable keychain file). With
  `--net-any`, every service is allowed, so two agents on one Mac can pass
  data through the pasteboard.
- **macOS: the start folder's names.** A program may read the folder it starts
  in (its path and the names in it, not the files), because macOS reports a
  folder's path only to a program that may read it.
- **A kernel below Landlock ABI 6 cannot be used.** hlyn refuses to seal rather
  than enforcing part of the policy.
- **A policy that grants something dangerous is doing as it was told.**
  Granting write and exec on the same directory lets the agent write a program
  and run it; that is the policy's meaning, not an escape.

If you think one of these limits is worse than we have described, that is worth
an email too.

## Threat model for host names in `net`

From [DESIGN-host-allowlisting.md](DESIGN-host-allowlisting.md), section 6, in
the same words; section numbers refer to that document. The README carries the
same text.

**It stops**, for code running inside the environment, including code that deliberately races threads:

- Opening a TCP connection to any host and port not on the list, whether through the proxy, directly, by IP address, or by exploiting a shared port. On Linux the kernel never runs such a connect.
- Reaching private, loopback, link-local or cloud-metadata addresses through a public name, whether by DNS rebinding or by a name that resolves privately.
- UDP of any kind (DNS, QUIC, anything tunnelled over it), raw IP, SCTP, packet sockets, and every socket family other than unix, TCP and route netlink.
- DNS lookups, whether over UDP, over TCP, through the resolver daemons or D-Bus, or through DoH to hosts not on the list, whatever folders are granted. See residual 3 below.
- Unix datagram sockets, which can name any socket file in `sendmsg`: none can be made while the network is limited on Linux before 7.1; from 7.1 the kernel checks each one's path.
- Reaching a container runtime's socket (`docker.sock` and the like), whatever folders are granted. See residual 3 below.
- Connections opened before the seal: the sealed child closes them, or `hlyn.on()` refuses.
- Tricks with how names and addresses are written: case, trailing dots, Unicode confusables, octal, hex or decimal IPv4, IPv4-mapped IPv6, zone IDs, NUL bytes, CRLF.
- A mismatch between the CONNECT target and the TLS SNI.
- Using another environment's proxy, killing or tracing hlyn's own helpers, or answering its own connection checks.
- On macOS, system services that resolve names or fetch URLs on the agent's behalf (`com.apple.dnssd.service`, `trustd`): refused (5.4).

**It does not stop.**

1. **Sending data to an allowed host.** A gist on `github.com`, an object in a bucket under `*.s3.amazonaws.com`, or a prompt sent to `api.openai.com` all look like normal traffic. This is the third leg of the lethal trifecta (private data, untrusted content, a way out). Host allowlisting narrows that way out; it can't close it for a host the agent needs. The mitigation is still hlyn's first rule: don't let the agent read what it shouldn't send. The secret warning stays on. This point is inferred from how network filtering works; the research found no direct citation for it.
2. **Domain fronting, shared TLS endpoints, HTTP/2 connection coalescing, and ECH on connections that are already open.** Without looking inside TLS, the proxy sees the SNI but not the HTTP `Host`. A 2024 study found fronting still works on 22 of 30 CDNs, Akamai and Fastly among them. Claude Code's own documentation carries the same warning.
3. **Unix sockets in three corners.** On Linux 7.1 and newer with the network off or limited to ports, no gate runs, and Landlock allows every socket file inside a write-granted folder: a refused socket (a resolver's, D-Bus, `docker.sock`) that sits in one is reachable. `hlyn show` warns when a grant holds one. And before 7.1, a unix datagram socket handed to the agent by a process outside (`SCM_RIGHTS`, over a socket the policy already lets it reach) can send to any socket file by name. And before 7.1 with the network limited to ports, the gate lets each TCP `connect()` run for Landlock to check its port, and a program that races its own threads can have such a call reach a socket file instead (found by reading the kernel's source, not measured). Everything else is checked without a race. Every unix `connect()` and `sendto()` naming a path: the gate connects the socket file it checked itself (0 races won in 10 million tries, against 611-781 in 3,000 before). Every other `connect()` while the gate checks socket files: the gate answers it without letting it run. Unix datagram sockets, whose `sendmsg` can name any socket file where no filter can read it: while the network is limited on Linux before 7.1 none can be made, and `hlyn.on()` refuses to seal while one is open (5.3). From 7.1 the kernel checks each datagram's path against the write grants (built, not yet run on a 7.1 kernel). TCP is unaffected.
4. **Other programs on the same Mac.** On macOS, `localhost:P` also matches the machine's own network addresses. A process outside the environment that listens on P at the Mac's LAN address could receive agent traffic.
5. **Behind a corporate proxy.** The address checks are skipped when chaining to a corporate proxy (5.5).
6. **Kernel bugs, side channels, and denial of service against the machine.** These are the same as for the rest of hlyn. For tenants who may be hostile to each other, use a microVM outer boundary; nono and Sandlock both say the same.
7. **Services you allow on this machine.** An address or `localhost:PORT` entry makes that service part of the boundary. A local HTTP or SOCKS proxy, Tor (9050), Docker's API (2375, 2376), the Kubernetes API (6443) or a kubelet (10250) each give full onward reach. hlyn warns when an entry names one of those ports:
   ```
   hlyn: localhost:2375 is Docker's API port. An agent that reaches it controls this
     machine. Remove --net localhost:2375 unless you mean it.
   ```
8. **Other processes on the machine.** Processes outside the environment can connect to the proxy's port like any local port, and can write a PROXY header themselves. They reach only the allowlist, which they could reach anyway. Blocks they cause show up in this run's report.
9. **Mach services on the macOS allowlist.** Each one is measured before it goes on the list (5.4), but a service that acts for its caller in a way no test covers would be a route out. The list starts empty and stays short.

## Scope

The library, the CLI, the native shim, the proxy and gate helpers, and the
framework adapters in this repository. The kernel facilities underneath —
Landlock, seccomp, Seatbelt — belong to their own projects; report kernel bugs
upstream, though we would like to know so we can work around them.
