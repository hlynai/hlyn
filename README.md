# hlyn

Runtime containment for AI agents. You declare what an agent may read, write,
run, and reach; the kernel enforces it. Everything not granted is denied.

The bet is that detection eventually fails, so the useful question is not "can
we spot the attack" but "what can the attacker do once they are inside". A
compromised agent under hlyn inherits an agent that can only touch what you
named.

```python
import hlyn

hlyn.on(read=["/srv/data"], write=["/srv/out"], net=[443])
```

That call is one-way. There is no `off()`, and nothing the agent can do will
lift it — the boundary is not implemented in a language the agent has access
to.

## Install

```bash
pip install hlyn
```

Linux wheels carry a prebuilt shim. Building from source needs a Rust
toolchain; macOS needs nothing beyond Python.

## Use

**Confine the process you are in.** One line, anywhere before the untrusted
work starts.

```python
import hlyn; hlyn.on("coder")
```

**Confine a program without touching its code.**

```bash
hlyn run --read /srv --net 443 -- python agent.py
```

**Confine one tool rather than the whole agent.** It runs in its own child
process; the parent's permissions are never widened to accommodate it.

```python
@hlyn.hooks.tool(read=["/data"])
def read_customer_file(path): ...
```

Adapters exist for LangChain, CrewAI, AutoGen, LlamaIndex and OpenAI Swarm,
but they are conveniences. Every framework eventually calls a plain Python
callable, and that is where the boundary goes.

**Check what a machine can enforce, before trusting it to.**

```bash
hlyn probe
```

Exits non-zero when the machine cannot enforce, so it works as a preflight gate
in a pipeline rather than something to read.

## Policy

| Field | Grants | Default |
|---|---|---|
| `read` | Readable paths | Nothing but the interpreter's own files |
| `write` | Writable paths | Nothing |
| `exec` | Programs that may be launched | None |
| `net` | Reachable TCP ports | None |
| `env` | Environment variables that survive | Only names known not to carry secrets |
| `tmp` | A private scratch directory | Yes |
| `log` | Where the record goes | stderr |

Each takes `False` for nothing, `True` for everything, or an explicit list.
Presets cover the common shapes: `strict`, `coder`, `web`, `data`, and `debug`
— the last of which confines almost nothing and exists to answer "what does my
agent actually touch?" before a real policy is written.

## What it enforces

**Linux** — Landlock for filesystem paths, TCP ports, and isolation between
agents on one machine, plus a seccomp filter for the syscalls that would
otherwise undo it: `io_uring` (which bypasses syscall filtering entirely),
`ptrace` and `pidfd_getfd` (which reach into another process), kernel module
loading, mount, namespace creation, and fileless execution.

**macOS** — Seatbelt. Filesystem, execution and network work. It has no
equivalent of Landlock's scoping, so isolation *between* agents on one machine
is weaker than on Linux, and `probe` says so rather than implying otherwise.

**Anywhere else** — it refuses to run. A containment layer that quietly does
nothing on an unsupported platform is worse than none, because the team ships
believing the boundary is there.

## Requirements

| | Needs |
|---|---|
| Linux | Kernel **6.12 or newer** with Landlock enabled, and libseccomp |
| macOS | Anything current |
| Python | 3.10+ |

The kernel floor is real and it is recent. hlyn asks for Landlock ABI 6 —
which is what confines signals and abstract sockets between agents — and
refuses to seal if the kernel applies less than the whole policy, rather than
reporting success for a boundary that is narrower than requested. Several
current LTS distributions ship older kernels, and some ship Landlock disabled
at boot; `hlyn probe` answers the question for a specific machine, and is the
only answer worth trusting.

## What it costs

Nothing sits between the agent and the kernel, so there is nothing in the path
to add delay. The measured numbers, from `tools/bench.sh` on Linux 6.12
(aarch64, Landlock ABI 6):

**Once, at startup.** `hlyn.on()` takes about **2 ms** for a small policy and
about **3 ms** for one naming 64 paths. Landlock opens a descriptor per granted
path, so that half grows with the policy; the syscall filter compiles a fixed
BPF program and stays flat at roughly 1 ms.

**Afterwards, per call.** Only the calls that ask permission pay, and they ask
once:

| Call | Added |
|---|---|
| `open` | ~90 ns |
| `bind` | ~0.5 µs |
| `connect` | under its own variance; bounded at a few hundred ns |
| `read`, `write`, `stat`, `getpid` | at or below the noise floor |

A descriptor or connection that is already open is never re-checked, so
throughput through it is untouched. For comparison, enforcing a network policy
with a proxy in the connection path costs an extra TCP handshake and usually a
TLS terminate and re-originate **per connection** — three to four orders of
magnitude more, paid repeatedly rather than once.

`tools/bench.py` documents the method, and each measuring process proves the
boundary was actually applied before its numbers are believed — a filter that
silently failed to load would benchmark beautifully.

## Known limits

Stated here because a containment layer that overstates itself is worse than
one that does less.

**Host names are not enforceable.** `net=["api.openai.com"]` is refused with an
error rather than accepted and ignored. Landlock filters ports; a classic
seccomp filter cannot dereference the `sockaddr` passed to `connect`, so
nothing in this design can see a host name.

**Named ports restrict TCP only.** `net=[443]` leaves UDP open, so traffic can
still leave over DNS or QUIC. Closing it would take all of UDP with it —
the same wall that stops host filtering stops us reading a UDP port — and that
breaks every hostname lookup. `net=False` closes both by refusing the socket
outright.

**GPU workloads need `/proc` writable.** CUDA writes thread names under
`/proc/<pid>/task/<tid>/comm`, and `/proc` is excluded by default because
`/proc/self/environ` still holds the environment captured at exec time and
would hand back every secret the `env` control removed. Grant it explicitly if
you need it, and scrub secrets at the source if you do.

## Development

```bash
tools/check.sh
```

Runs ruff, mypy `--strict`, clippy, cargo-audit and cargo-deny. The test suite
runs against a real kernel:

```bash
docker build -t hlyn-test tools/ && docker run --rm -v "$PWD":/work -w /work hlyn-test python -m pytest tests -q
```

Most of the suite is escape attempts, each of which fails the build if the
escape succeeds. Neither platform can run the other's kernel tests, so a pass
on one machine is not a pass — Landlock and seccomp tests skip on macOS,
Seatbelt tests skip on Linux.

`tools/mutate.sh` and `tools/fuzz.sh` run mutation testing and fuzzing;
`tools/confirm.py` re-checks that the suite catches a specific list of mistakes
it has caught before. `tools/bench.sh` measures what confinement costs, and
produces the numbers above.

## Licence

Apache-2.0.
