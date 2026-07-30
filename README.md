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

## Writing the first policy

The hard part of deny-by-default is not enforcing it, it is knowing what to
allow. Run the agent once with nothing confined and let it say:

```bash
hlyn watch -- python agent.py > policy.toml
```

That records every path and port the run touched and prints a policy covering
them. Read it, cut it down, and check it in. Then use it:

```bash
hlyn run -f policy.toml -- python agent.py
```

A policy file is TOML, JSON, or YAML, and it is a document a security team can
review and diff rather than a set of flags buried in a shell script:

```toml
read  = ["src", "/etc/ssl/certs"]   # relative paths resolve next to this file
write = ["out"]
net   = [443]
exec  = false
env   = ["OPENAI_API_KEY"]
```

`hlyn show --intent` turns a set of flags that already works into a starter
file. Two things about this format are deliberate:

- **An unrecognised field is an error, not a warning.** `reed = [...]` is
  refused outright. Silently ignoring it would leave a boundary that differs
  from the document everyone believes describes it.
- **Relative paths resolve against the file, not the working directory**, so a
  policy checked in beside its agent means the same thing from anywhere.

Two honest caveats on `watch`. It confines nothing while running, so it is a
drafting tool and never a boundary. And it observes what *Python* does, via
audit hooks — it cannot see a C extension calling `open(2)` behind Python's
back. A policy drafted this way can therefore come out too narrow, and the
agent will hit a refusal the watch run never predicted. That is loud, safe, and
the right direction to be wrong in.

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
| `attest` | Where to write a record of what was enforced | Off |

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

## Auditing a policy

A policy can be valid, enforced exactly as written, and still hand the agent
everything. The dangerous grants are rarely one field — they are two
reasonable-looking fields that combine, and each half passes review on its own.

```bash
hlyn audit -f policy.toml
```

```
!! critical the agent can read credentials (/root) and reach TCP 443
              these are the two halves of exfiltration; either alone is a risk,
              and together they are a route
    fix:      remove one half. Closing the network is usually easier than
              narrowing the read, and `net=False` closes UDP too
    waive as: exfiltration:TCP 443
```

It exits non-zero when something is outstanding, so it belongs in CI rather
than in a report someone means to read. Among what it looks for:

| Finding | Why it matters |
|---|---|
| `write-exec` | Write a program and then run it — every other grant becomes a starting point |
| `exfiltration` | Credentials readable *and* a network to send them over |
| `credential-reach` | A grant covering `~/.ssh`, `~/.aws`, `/etc/shadow` — often without naming any of them, as `read=["/root"]` does |
| `interpreter-exec` | `exec=["/usr/bin/python3"]` — the allowlist governs which *file* runs, and an interpreter runs whatever it is handed |
| `hijack` | Write access somewhere programs get found and loaded |
| `evidence` | The log written somewhere the agent can also write, so it can edit the record of what it did |
| `widened` | A path named in the file that a broader one already covers, so the kernel never sees it |

This is analysis, not proof — direct checks against the policy's own resolved
grants, with no solver, because the policy model is small enough that a solver
would be answering a question you can look up. It can tell you a grant is there
and what it makes possible. It cannot tell you whether it is justified.

## Accepting a risk

A finding that cannot be waived gets the whole check switched off, so waiving
is what keeps it on. What matters is that the decision is recorded:

```toml
[[accepted]]
finding = "interpreter-exec:/usr/bin/python3"
reason  = "the agent is a Python coding assistant; running Python is the job"
by      = "karan@hlyn.dev"
until   = "2026-12-31"
```

```bash
hlyn audit -f policy.toml -a risks.toml
```

That file is a risk register, and it is the artifact SOC 2 and ISO 27001 ask
for — produced as a side effect of a check that runs on every build rather than
a spreadsheet someone remembers to update. Three rules, each because the
alternative rots quietly:

- **`until` is required.** A waiver with no end date is how a temporary
  exception becomes permanent without anyone deciding it should. An expired one
  stops waiving and becomes a finding.
- **A waiver matching nothing is reported as stale.** The policy moved on; left
  in place, it would silently waive the next real occurrence.
- **Every field is required.** An acceptance with an empty reason records that
  someone wanted the build to pass, not that anyone decided anything.

Add `--ocsf` to emit findings as OCSF v1.7.0 Compliance Findings, so a SIEM
ingests them with no parser written for us.

## Attesting a run

```bash
hlyn run --attest run.json -f policy.toml -- python agent.py
hlyn verify run.json
```

hlyn refuses to seal when the kernel would apply less than the whole policy —
which is what makes a record worth keeping. A seal that happened is one that
happened *in full*, so the record says which policy was **enforced**, not which
was requested. It carries the policy as written, the grants as resolved, the
kernel, the backend, and the ABI level.

Worth being exact about what that buys, since attestation is a word that gets
oversold. The record is tamper-**evident**: it carries a digest over its own
contents, and an HMAC too when `HLYN_ATTEST_KEY` names a key file. It is **not**
proof against the confined process itself — a process holding the signing key
can sign what it likes, and no cryptography inside a machine settles a question
about that machine. Real non-repudiation needs a signer the agent cannot reach.
That is a deliberate hole: this package has no network component and does not
pretend to be its own trust root.

## The record

One JSON object per line, to stderr by default or to a file when the policy
names one. The `seal` record states the boundary that was applied, and is the
one record that always matters.

Repeats are collapsed. A tight policy refuses the same thing over and over —
the same missing config file, on every retry, in every worker — and written out
in full that is hundreds of identical lines burying the three that differ. A
record is written on the 1st, 2nd, 4th, 8th, 16th … occurrence, carrying its
running total as `seen`, and counted silently in between. Nothing waits for
process exit to be flushed, because a process refused by seccomp is killed
rather than exited.

What the log does **not** see is worth stating: kernel refusals as they happen.
When Landlock denies a read, the agent gets `EACCES` straight from the syscall
and no userspace code is consulted — which is exactly why the boundary is cheap
and cannot be talked out of.

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
produces the numbers above. `tools/sbom.sh` writes a CycloneDX SBOM of what
ships: twelve components, all of them the Rust shim's, since the Python package
has no runtime dependencies at all. The fuzzing harness is excluded on purpose
— its lockfile is about twice the size of the shipped one and appears in no
build that leaves this repository.

## Licence

Apache-2.0.
