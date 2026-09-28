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
  allowed, domain fronting, unix datagrams sent with `sendmsg` on Linux before
  7.1, and the rest.
- **macOS agents share system services.** Signals stay within each agent's
  sandbox, as Landlock scopes them on Linux, but macOS services such as the
  pasteboard and notifications are shared: two agents on one Mac can pass data
  through them. `hlyn probe` reports this.
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

**It stops**, for code running inside the sandbox, including code that deliberately races threads:

- Opening a TCP connection to any host and port not on the list, whether through the proxy, directly, by IP address, or by exploiting a shared port. On Linux the kernel never runs such a connect.
- Reaching private, loopback, link-local or cloud-metadata addresses through a public name, whether by DNS rebinding or by a name that resolves privately.
- UDP of any kind (DNS, QUIC, anything tunnelled over it), raw IP, SCTP, packet sockets, and every socket family other than unix, TCP and route netlink.
- DNS lookups, whether over UDP, over TCP, through the resolver daemons or D-Bus, or through DoH to hosts not on the list, whatever folders are granted. See residual 3 below.
- Reaching a container runtime's socket (`docker.sock` and the like), whatever folders are granted. See residual 3 below.
- Connections opened before the seal: the sealed child closes them, or `hlyn.on()` refuses.
- Tricks with how names and addresses are written: case, trailing dots, Unicode confusables, octal, hex or decimal IPv4, IPv4-mapped IPv6, zone IDs, NUL bytes, CRLF.
- A mismatch between the CONNECT target and the TLS SNI.
- Using another sandbox's proxy, killing or tracing hlyn's own helpers, or answering its own connection checks.
- On macOS, system services that resolve names or fetch URLs on the agent's behalf (`com.apple.dnssd.service`, `trustd`): refused (5.4).

**It does not stop.**

1. **Sending data to an allowed host.** A gist on `github.com`, an object in a bucket under `*.s3.amazonaws.com`, or a prompt sent to `api.openai.com` all look like normal traffic. This is the third leg of the lethal trifecta (private data, untrusted content, a way out). Host allowlisting narrows that way out; it can't close it for a host the agent needs. The mitigation is still hlyn's first rule: don't let the agent read what it shouldn't send. The secret warning stays on. This point is inferred from how network filtering works; the research found no direct citation for it.
2. **Domain fronting, shared TLS endpoints, HTTP/2 connection coalescing, and ECH on connections that are already open.** Without looking inside TLS, the proxy sees the SNI but not the HTTP `Host`. A 2024 study found fronting still works on 22 of 30 CDNs, Akamai and Fastly among them. Claude Code's own documentation carries the same warning.
3. **Unix datagrams sent with `sendmsg`, on Linux before 7.1.** Its address sits inside a struct no filter can read, so a datagram `sendmsg` to a unix path isn't checked (5.3). It reaches only datagram sockets, such as the system log, never a stream service like the resolver, D-Bus or a container runtime. Every unix `connect()` and every `sendto()` naming a path is checked without a race, with hosts and, before 7.1, with ports or no network too: the gate connects the socket file it checked itself, so racing threads or a folder swapped for a symlink reach nothing else (0 of 3,000 in a test, against 611-781 before). On Linux 7.1 and newer the kernel refuses datagrams outside the write-granted folders as well (built, not yet run on a 7.1 kernel). TCP is unaffected.
4. **Other programs on the same Mac.** On macOS, `localhost:P` also matches the machine's own network addresses. A process outside the sandbox that listens on P at the Mac's LAN address could receive agent traffic.
5. **Behind a corporate proxy.** The address checks are skipped when chaining to a corporate proxy (5.5).
6. **Kernel bugs, side channels, and denial of service against the machine.** These are the same as for the rest of hlyn. For tenants who may be hostile to each other, use a microVM outer boundary; nono and Sandlock both say the same.
7. **Services you allow on this machine.** An address or `localhost:PORT` entry makes that service part of the boundary. A local HTTP or SOCKS proxy, Tor (9050), Docker's API (2375, 2376), the Kubernetes API (6443) or a kubelet (10250) each give full onward reach. hlyn warns when an entry names one of those ports:
   ```
   hlyn: localhost:2375 is Docker's API port. An agent that reaches it controls this
     machine. Remove --net localhost:2375 unless you mean it.
   ```
8. **Other processes on the machine.** Processes outside the sandbox can connect to the proxy's port like any local port, and can write a PROXY header themselves. They reach only the allowlist, which they could reach anyway. Blocks they cause show up in this run's report.
9. **Mach services on the macOS allowlist.** Each one is measured before it goes on the list (5.4), but a service that acts for its caller in a way no test covers would be a route out. The list starts empty and stays short.

## Scope

The library, the CLI, the native shim, the proxy and gate helpers, and the
framework adapters in this repository. The kernel facilities underneath —
Landlock, seccomp, Seatbelt — belong to their own projects; report kernel bugs
upstream, though we would like to know so we can work around them.
