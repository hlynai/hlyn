<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/hero-dark.svg">
    <img alt="hlyn: kernel-level agent isolation" src="docs/assets/hero-light.svg" width="860">
  </picture>
</p>

<p align="center"><b>One file controls what an agent can read, write and reach.</b><br>Enforced at the kernel. Auditable by design.</p>

<p align="center">
<img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-52525b?style=flat-square&labelColor=000000">
<img alt="Linux and macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-52525b?style=flat-square&labelColor=000000">
<img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-52525b?style=flat-square&labelColor=000000">
<img alt="Tests" src="https://img.shields.io/github/actions/workflow/status/hlynai/hlyn/test.yml?branch=main&label=tests&style=flat-square&labelColor=000000&color=52525b">
<img alt="Zero runtime dependencies" src="https://img.shields.io/badge/dependencies-0-52525b?style=flat-square&labelColor=000000">
</p>

---

## What is hlyn?

An AI agent is a program that reads files, runs commands and uses the internet for you. If it is tricked, it can do all of that against you. hlyn puts a fence around the agent: you list the folders, programs and websites it may use, and the operating system blocks everything else. When something is blocked, hlyn tells you what and how to allow it.

## How it works

Any web page or document an agent reads can hide an instruction, and catching every trick isn't realistic. So hlyn assumes one will work and limits what the agent can do. The operating system enforces the limits (Landlock and seccomp on Linux, Seatbelt on macOS), and the agent has no switch to turn them off.

## What you control

| You control | In plain words | Flag |
|---|---|---|
| **Files** | Which folders the agent can read and write. Your keys and other projects stay closed. | `--read` `--write` |
| **Programs** | Which programs it may start. No surprise `curl` or `bash`. | `--exec` |
| **Network** | Off by default. Allow named websites, or a port. DNS tricks, raw IP addresses and UDP are blocked. | `--net` |
| **Secrets** | API keys and tokens are removed from its environment unless you pass one on purpose. | `--env` |
| **Other agents** | One agent can't signal, connect to or share memory with another on the same machine. | built in |
| **Dangerous kernel calls** | `io_uring`, `ptrace`, `mount` and similar are always refused (Linux). | built in |
| **Warnings** | Tells you before the run if the agent could read a secret and reach the internet, or plant a file that runs later. | built in |
| **Audit trail** | A JSON log of what was locked and what was refused. `--json` on every command. | `--log` |

## Quick start

**1. Check the machine**

```bash
hlyn probe
```

**2. Wrap any command** (any language)

```bash
hlyn run -p coder -- python agent.py                       # a preset: this folder, any program
hlyn run --read ./src --net 443 --env OPENAI_API_KEY -- ./my-agent
hlyn run -f policy.toml -- ./my-agent                      # rules kept in a file
```

**3. Or lock a Python program from inside**

```python
import hlyn

hlyn.on(read=["./data"], write=["./out"], net=["api.openai.com"])   # from here on, locked
text = hlyn.run(lambda: summarise("/tmp/upload.txt"), read=["/tmp/upload.txt"])  # lock one risky step
```

**4. Claude Code, confined to your project**

```bash
hlyn claude
```

It shows a table of what Claude Code will get, asks `y` or `n`, and at the end lists what was refused, which plugin or MCP server asked, and the one command to allow what you trust.

Presets: `strict` (nothing), `data`, `coder`, `web`, `debug`. Run `hlyn presets`.

## Where it runs

| | Linux | macOS |
|---|---|---|
| Needs | Kernel 6.12+ with Landlock, libseccomp | Any current macOS |
| CPUs | x86_64, aarch64 | Apple silicon, Intel |
| Files, programs, ports, websites, isolation between agents | ✅ | ✅ |
| Dangerous kernel calls blocked | ✅ | not applicable |
| `hlyn claude` | ✅ | ✅ (keychain sign-in) |

Python 3.10+. Zero runtime dependencies. Not supported: Windows, Alpine (musl). Works inside Docker. [Details and requirements](docs/REFERENCE.md#install).

## Evidence

Numbers we measured, and where. Nothing here is estimated.

| Claim | Measured |
|---|---|
| Automated tests | 1,327 pass on macOS, 1,498 on Linux, 0 failing |
| Tests can fail | Bugs were planted on purpose and caught |
| Fuzzing of the website filter's parsers | 238 million inputs, nothing found |
| Race harness against the Linux gate | 10 million attempts under plain, ASan and TSan builds, none won |
| Packet capture during bypass attempts | No packet reached an unlisted destination |
| Start-up | `hlyn run` 92 ms against 202 ms for `docker run --rm alpine true` (median, Apple M1). A warm `docker exec` is faster, so the fair line is "faster than starting a container". On GitHub's x86_64 runner: 74 ms against 707 ms. |
| CI | Every push runs the suite on Linux x86_64 (kernel 6.17) |

## Honest limits

An environment that oversells itself is worse than none. The three that matter most:

- **Data can still go to a website you allowed.** hlyn stops the agent reaching *other* sites, not sending something to a listed one. The rule that matters most: don't let the agent read what it shouldn't send.
- **A granted folder is a granted folder.** If the agent can write somewhere that something else later runs (a git hook, a scheduled job), that is running code outside hlyn. hlyn names these before the run.
- **A kernel bug or a hostile tenant** is outside what any process-level boundary covers. For tenants who may attack each other, add a microVM.

<details>
<summary><b>The full threat model: what it stops, and what it does not</b></summary>

This is the threat model, in the same words as [SECURITY.md](SECURITY.md).

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

#### What naming hosts does not stop

1. **Sending data to an allowed host.** A gist on `github.com`, an object in a bucket under `*.s3.amazonaws.com`, or a prompt sent to `api.openai.com` all look like normal traffic. This is the third leg of the lethal trifecta (private data, untrusted content, a way out). Host allowlisting narrows that way out; it can't close it for a host the agent needs. The mitigation is still hlyn's first rule: don't let the agent read what it shouldn't send. The secret warning stays on. This point is inferred from how network filtering works; the research found no direct citation for it.
2. **Domain fronting, shared TLS endpoints, HTTP/2 connection coalescing, and ECH on connections that are already open.** Without looking inside TLS, the proxy sees the SNI but not the HTTP `Host`. A 2024 study found fronting still works on 22 of 30 CDNs, Akamai and Fastly among them. Claude Code's own documentation carries the same warning.
3. **Unix sockets in three corners.** On Linux 7.1 and newer with the network off or limited to ports, no gate runs, and Landlock allows every socket file inside a write-granted folder: a refused socket (a resolver's, D-Bus, `docker.sock`) that sits in one is reachable. `hlyn show` warns when a grant holds one. And before 7.1, a unix datagram socket handed to the agent by a process outside (`SCM_RIGHTS`, over a socket the policy already lets it reach) can send to any socket file by name. And before 7.1 with the network limited to ports, where hlyn's gate can't take a copy of a program's socket (a stock `docker run` refuses `pidfd_getfd`; `hlyn probe` says so), it lets each TCP `connect()` run for Landlock to check its port, and a program that races its own threads can have such a call reach a socket file instead (found by reading the kernel's source, not measured). Everything else is checked without a race. Every unix `connect()` and `sendto()` naming a path: the gate connects the socket file it checked itself (0 races won in 10 million tries, against 611-781 in 3,000 before). Every other `connect()` while the gate checks socket files: the gate answers it without letting it run. Unix datagram sockets, whose `sendmsg` can name any socket file where no filter can read it: while the network is limited on Linux before 7.1 none can be made, and `hlyn.on()` refuses to seal while one is open (5.3). From 7.1 the kernel checks each datagram's path against the write grants (built, not yet run on a 7.1 kernel). TCP is unaffected.
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

</details>

## Documentation

[Reference](docs/REFERENCE.md): every flag, the policy format, the Python API, the log and the FAQ.

## Security

Found a way out? Email **founders@hlynai.com**. [SECURITY.md](SECURITY.md) says what to include.

## Develop

```bash
pip install -e '.[dev]' && python -m pytest        # macOS or Linux
tools/linuxtest.sh                                   # Linux suite in Docker
```

## License

Apache-2.0. See [LICENSE](LICENSE).
