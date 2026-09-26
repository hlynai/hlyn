# hlyn

**A kernel-enforced sandbox for AI agents.** You list what an agent may read, write, run and reach. The operating system enforces it, and everything else is denied.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)

```python
import hlyn

hlyn.on(read=["./data"], write=["./out"], net=[443])

# From here on, this process can read ./data, write ./out, and open TCP
# connections on port 443. Nothing else. Not ~/.ssh, not your .env, not
# port 22. This cannot be undone for the life of the process.
```

Or leave your code alone and wrap the command:

```bash
hlyn run --read ./data --write ./out --net 443 -- python agent.py
```

---

## Contents

- [Why hlyn](#why-hlyn)
- [Install](#install)
- [Quick start](#quick-start)
- [The policy](#the-policy)
- [Presets](#presets)
- [When something is blocked](#when-something-is-blocked)
- [Writing your first policy](#writing-your-first-policy)
- [Command line](#command-line)
- [Python API](#python-api)
- [What is enforced, per platform](#what-is-enforced-per-platform)
- [Performance](#performance)
- [The log](#the-log)
- [Known limits](#known-limits)
- [FAQ](#faq)

---

## Why hlyn

Prompt injection, poisoned tools and malicious documents will get through sooner or later, because detection eventually misses something. hlyn is built on a different question: **once an attacker controls your agent, what can they actually do?**

With hlyn, the answer is "only what you wrote down."

| | Without hlyn | With hlyn |
|---|---|---|
| Agent reads `~/.ssh/id_ed25519` | Works | `PermissionError`, unless you granted it |
| Agent sends data to a server | Works | Refused while the network is off (the default). Once you open a port, see the note below. |
| Agent runs `curl … \| sh` | Works | Refused unless you allowed that program |
| Agent reads `OPENAI_API_KEY` from its environment | Works | Removed before it starts, unless you kept it |
| You grant a folder that holds a `.env`, with the network open | Nothing tells you | hlyn warns before it starts, and says how to fix it |
| Agent tries to turn the sandbox off | No sandbox to turn off | There is no off switch, not even for hlyn itself |

> **The honest caveat.** `net` filters **ports, not hosts**. If you open port 443 so the agent can call an API, a compromised agent can use port 443 to reach *any* host. So the rule that matters most is: **don't let the agent read what it shouldn't send.** Grant narrow folders, pass API keys with `--env` rather than a readable `.env`, and let hlyn's [secret warning](#secrets-in-granted-folders) catch the rest. Host allowlists are on the roadmap.

**What makes it different:**

- **Enforced by the kernel.** Linux uses Landlock and seccomp; macOS uses Seatbelt. The rules are not a Python wrapper the agent could monkey-patch or talk its way around.
- **Deny by default.** An empty policy grants nothing except the files Python itself needs to run.
- **One line to start.** `hlyn.on()` or `hlyn run -- cmd`. Every extra permission is one more obvious argument.
- **No proxy, no daemon, no container.** Nothing sits between the agent and the kernel, so it adds almost no latency (see [Performance](#performance)). It works inside Docker too.
- **Refuses rather than pretends.** If the machine cannot enforce your whole policy, hlyn raises an error instead of quietly enforcing part of it.
- **Zero runtime dependencies.**

---

## Install

```bash
pip install hlyn
```

Then check that this machine can enforce:

```bash
hlyn probe
```

```
ok  hlyn can confine programs on this machine (Linux 6.12.76-linuxkit)
    yes files and programs
    yes network ports
    yes isolation between agents on this machine
    yes listing what was blocked, after hlyn run
```

### Requirements

| Platform | Needs | Notes |
|---|---|---|
| **Linux** | Kernel **6.12+** with Landlock enabled, plus `libseccomp` | x86_64 and aarch64, any glibc 2.28+ distribution (Debian 10+, Ubuntu 20.04+, RHEL 8+). Works inside Docker. Alpine (musl) is not supported. |
| **macOS** | Any current macOS | Nothing to build or install beyond Python. |
| **Python** | 3.10 or newer | Reading TOML policies on 3.10 needs `tomli`; YAML needs `pyyaml`. JSON always works. |
| Anything else | Not supported | hlyn refuses to run rather than pretend to protect you. |

> **Why such a new kernel?** Linux 6.12 is the first with Landlock ABI 6, which is what stops one agent signalling or connecting to another. Rather than enforce a weaker boundary than you asked for, hlyn refuses to run on older kernels. `hlyn probe` tells you exactly where a given machine stands.

---

## Quick start

There are three ways in, and each one builds on the last.

### 1. One line: the strictest default

```python
import hlyn; hlyn.on()
```

The process can still run Python and import the standard library and your installed packages. It cannot read your files, write anywhere except a private scratch folder, start programs, use the network, or see secret environment variables.

### 2. Two lines: a preset

```python
import hlyn
hlyn.on("coder")   # read and write the current folder, run programs
```

### 3. Full control

```python
import hlyn

hlyn.on(
    read=["./src", "./docs"],
    write=["./out"],
    exec=["/usr/bin/git"],
    net=[443],
    env=["OPENAI_API_KEY"],
)
```

### Or: don't touch the code at all

```bash
hlyn run -p coder -- python agent.py
hlyn run --read ./src --net 443 --env OPENAI_API_KEY -- python agent.py
hlyn run -f policy.toml -- ./my-agent
```

`hlyn run` confines the command and everything it starts, whatever language it is written in.

### Confine one risky step, not the whole program

```python
import hlyn

def summarise(path):
    return open(path).read()[:200]

# Runs in a confined child process. The parent keeps all its permissions.
text = hlyn.run(lambda: summarise("/tmp/upload.txt"), read=["/tmp/upload.txt"])
```

---

## The policy

A policy has seven fields. Each one answers a single question.

| Field | Question | Default |
|---|---|---|
| `read` | Which paths can it read? | Nothing but Python's own files |
| `write` | Which paths can it write? | Nothing |
| `exec` | Which programs can it start? | None |
| `net` | Which TCP ports can it connect to? | None, and no network at all |
| `env` | Which environment variables survive? | Only a safe list (`PATH`, `HOME`, `LANG`, `TZ`, …) |
| `tmp` | Does it get a private scratch folder? | Yes, a fresh empty one |
| `log` | Where does the record of what happened go? | stderr |

Every field takes one of the same three shapes:

| Value | Means | Example |
|---|---|---|
| `False` | Nothing | `net=False` |
| `True` | Everything | `exec=True` |
| a list | Exactly these | `read=["./src", "/etc/app.conf"]` |

A few rules worth knowing:

- **A folder grant covers everything inside it.** `read=["./src"]` includes `./src/app/main.py`.
- **Writing implies reading what you wrote.** A path in `write` can also be read back.
- **Paths must exist.** A typo such as `read=["./scr"]` is an error, not a grant that silently matches nothing.
- **`net` takes ports, not host names.** `net=["api.openai.com"]` is refused with an explanation; the kernel filters ports, not hosts. Use `net=[443]`.
- **Allowing any network also allows what the network needs.** DNS configuration and TLS certificate stores become readable automatically, so `net=[443]` really can make HTTPS requests. Private key folders such as `/etc/ssl/private` are never included.

### Secrets in granted folders

A folder grant includes everything inside it, and the kernel can't exclude one file from a granted folder. So `read=["."]` in a project also grants its `.env`. With the network closed that's harmless, because the secret has nowhere to go. With the network open, hlyn warns **before** the agent starts:

```
$ hlyn run -p coder --net 443 -- python agent.py
hlyn: warning: the agent can read 1 secret file and reach the network, so it could send it out:
  ./.env
  Grant only the folders it needs (e.g. --read ./src instead of the whole project),
  pass a key it needs as a variable instead (--env NAME), or move the secrets out.
  Meant it? Run with PYTHONWARNINGS=ignore::hlyn.Exposed to stop this warning.
```

| Detail | Behaviour |
|---|---|
| What counts as a secret | `.env` and `.env.*` (except `.example`, `.sample`, `.template`), private SSH keys, `*.pem`, `*.key`, `*.p12`, `credentials.json`, service-account JSON, `~/.aws`, `~/.ssh`, `~/.kube`, … |
| When it warns | Only when a secret is readable **through a folder** **and** the network is open |
| Granting a secret file on its own | No warning. Naming it is a decision. |
| Where it looks | Up to 4 folders deep, skipping `.git`, `node_modules`, `.venv` and build output |
| In Python | Raised as a `hlyn.Exposed` warning, so the standard filters apply (e.g. make it an error in your tests) |
| Check a policy yourself | `hlyn.exposed(policy)` returns the list |

### Policy files

Keep the policy next to your agent and review it like code. TOML, JSON and YAML all work:

```toml
# policy.toml
read  = ["src", "prompts"]   # relative paths resolve next to this file
write = ["out"]
exec  = false
net   = [443]
env   = ["OPENAI_API_KEY"]
```

```bash
hlyn run -f policy.toml -- python agent.py
```

```python
hlyn.on("policy.toml")
```

- **An unknown field is an error.** `reed = [...]` is refused, never ignored.
- **Flags add to a file; they never replace it.** `hlyn run -f policy.toml --net 5432` keeps the file's 443 and adds 5432.

---

## Presets

| Preset | Grants | Good for |
|---|---|---|
| `strict` | Nothing beyond the Python runtime, and no scratch folder | Pure computation on inputs you pass in |
| `data` | Read and write the current folder | Data processing, notebooks |
| `coder` | Read and write the current folder, run any program | Coding agents |
| `web` | Any network | Agents that only browse or call APIs |
| `debug` | Everything | Finding out what your agent touches. **This is not protection.** |

```bash
hlyn presets     # list them, with what each grants
```

You can add your own:

```python
hlyn.register("reviewer", lambda: hlyn.Policy(read=["./src"], net=[443]))
hlyn.on("reviewer")
```

---

## When something is blocked

When the kernel refuses a call, the program only sees `Operation not permitted`. If it swallows the error or quietly falls back, you are left with an agent that behaves oddly for no visible reason.

So `hlyn run` listens while the command runs, and when it ends it tells you **what was blocked and exactly which flag would allow it**:

```
$ hlyn run --read ./agent.py -- python agent.py
hlyn: the command exited with code 1. hlyn blocked 4 things:
  read   ~/.ssh/id_ed25519      a credential: not suggested. Grant it yourself only if the agent should have it
  read   /data/customers.csv    allow with --read /data/customers.csv
  write  /data/report.txt       allow with --write /data
  net    TCP 5432 (10.0.0.7)    allow with --net 5432
  to allow all of these: --read /data/customers.csv --write /data --net 5432
hlyn: removed 12 environment variables (including OPENAI_API_KEY, GITHUB_TOKEN).
      Keep one with --env NAME, e.g. --env OPENAI_API_KEY
```

| Refused | Suggested flag |
|---|---|
| Reading a file or folder | `--read PATH` |
| Writing an existing file | `--write FILE` |
| Creating, deleting or renaming a file | `--write FOLDER` (the folder that holds it) |
| Running a program, even from a child process | `--exec /full/path/to/program` |
| Connecting to a TCP port | `--net PORT` |
| Any network while the network is off | `--net-any`, or `--net PORT` for just the port it needs |
| Listening on a port | `--net-any` |
| A credential (`~/.ssh`, `~/.aws`, `.env`, `*.pem`, …) | **None.** It is named, never suggested. |

Some details:

- **Successful runs are reported too**, if something was refused along the way. A program that worked around a refusal is not behaving the way it did when you tested it.
- **Retries are counted, not repeated.** A loop that fails 5,000 times is one line: `[5000+ times]`.
- **Refusals from child processes are included**, labelled with the process name: `[by git]`.
- **Environment variables are named, never their values.**
- `--json` prints the same report as JSON on stderr for CI; `--no-report` turns it off.
- `hlyn probe` tells you whether reporting is available on the machine.

How it hears the refusals, and what it can miss:

| | Linux | macOS |
|---|---|---|
| Source | A tiny library preloaded into the command and its children | The sandbox's own reports, from the system log |
| Cost | Nothing measurable on calls that succeed | About 50 ms per run |
| Misses | Statically linked programs (most Go binaries; hlyn says so), and programs started through `system()` / `popen()` | A few percent of reports under heavy system load |

---

## Writing your first policy

Deny-by-default is easy to enforce; the hard part is knowing what to allow. The workflow is **watch → trim → run**:

**1. Watch one unconfined run** and let hlyn draft the policy (Python programs only):

```bash
hlyn watch -- python agent.py > policy.toml
```

```toml
# a draft to cut down, not a policy to trust
read = [
  "/home/me/project/agent.py",
  "/home/me/project/prompts",
]
write = [
  "/home/me/project/out",
]
exec = false
net = [
  443,
]
env = false
tmp = true
log = true
```

**2. Read it and cut it down.** Anything your agent doesn't strictly need should go.

**3. Run confined.** If something was missed, the [report](#when-something-is-blocked) tells you which flag to add.

```bash
hlyn run -f policy.toml -- python agent.py
```

Already have a set of flags that works? Turn them into a file:

```bash
hlyn show --intent --read ./src --net 443 > policy.toml
```

---

## Command line

| Command | What it does |
|---|---|
| `hlyn run [flags] -- CMD` | Runs `CMD` confined, passes on its exit code, and lists what was blocked |
| `hlyn watch -- CMD` | Runs a Python program **unconfined** and prints the policy it would need |
| `hlyn show [flags]` | Prints the full list of paths and ports a set of flags would grant |
| `hlyn show --intent [flags]` | Prints the flags as a policy file you can check in |
| `hlyn presets` | Lists the presets and what each grants |
| `hlyn probe` | Says what this machine can enforce; exits non-zero if it can't |
| `hlyn --version` | Prints the version |

Flags for `run` and `show`:

| Flag | Grants |
|---|---|
| `-p, --preset NAME` | Start from a preset |
| `-f, --policy FILE` | Start from a `.toml`, `.json` or `.yaml` file |
| `--read PATH` | Read a path (repeatable) |
| `--write PATH` | Write a path (repeatable) |
| `--exec PATH` | Run a program (repeatable) |
| `--exec-any` | Run any program |
| `--net PORT` | Connect to a TCP port (repeatable) |
| `--net-any` | Use any network |
| `--env NAME` | Keep an environment variable (repeatable) |
| `--env-any` | Keep the whole environment, secrets included |
| `--no-tmp` | No private scratch folder |
| `--log PATH` / `--no-log` | Write the log to a file, or nowhere |

Only on `run`:

| Flag | Does |
|---|---|
| `--no-report` | Don't list what was blocked |
| `--json` | Print the report as JSON (on stderr) |

Every command that prints data prints plain text by default, and JSON with `--json`.

---

## Python API

| Call | What it does |
|---|---|
| `hlyn.on(policy=None, **fields)` | Confines **this process**, permanently. Returns what was applied. |
| `hlyn.run(fn, policy=None, **fields)` | Runs `fn()` in a confined child process and returns its result (or re-raises its exception). The caller stays unconfined. |
| `hlyn.spawn(cmd, policy=None, **fields)` | Confines this process, then replaces it with `cmd`. Does not return. |
| `hlyn.probe()` | Reports what this machine can enforce, as a dict. Changes nothing. |
| `hlyn.exposed(policy)` | Lists secret files the policy lets the agent read while the network is open. |
| `hlyn.sealed()` | `True` once this process is confined. |
| `hlyn.load(path)` | Reads a policy file into a `Policy`. |
| `hlyn.Policy(...)` | An immutable policy object with the seven fields above. |
| `hlyn.preset(name)` / `hlyn.presets` / `hlyn.register(name, make)` | Look up, list and add presets. |

Anywhere a policy is expected, you can pass any of these:

```python
hlyn.on()                                      # nothing: the strictest default
hlyn.on("coder")                               # a preset name
hlyn.on("policy.toml")                         # a policy file
hlyn.on(hlyn.Policy(read=["./src"]))           # a Policy object
hlyn.on(read=["./src"], net=[443])             # keyword arguments
hlyn.on("coder", net=[443])                    # a preset, plus changes
```

`hlyn.Policy` is frozen. Use `.with_(...)` to derive a new one:

```python
base = hlyn.Policy(read=["./src"])
wider = base.with_(net=[443])
```

### Errors

Every error inherits from `hlyn.Error`, so one `except` catches them all. `hlyn.Exposed` is a warning, not an error: it never stops the run.

| Error | Raised when | The process is |
|---|---|---|
| `hlyn.Invalid` | The policy is malformed: a typo, a missing path, a host name in `net` | Untouched |
| `hlyn.Unsupported` | This machine can't enforce the policy (old kernel, unsupported OS) | Untouched |
| `hlyn.Failed` | The kernel refused to apply the boundary | **Not** confined, so don't continue |
| `hlyn.Sealed` | You called `on()` twice. The boundary can't be changed once applied. | Already confined |

Messages say what to do next, naming the field or flag that would change the outcome.

### Things to know

- **`on()` is one-way.** There is no `off()` and no context manager that pretends to restore anything, because the kernel can't undo it.
- **Call `on()` before starting threads.** On Linux, a thread that is already running would keep its old access, so hlyn refuses to seal a process with more than one thread. Put `on()` at the top of your program, or use `hlyn.run(fn)`, which forks a clean child.

---

## What is enforced, per platform

| | Linux | macOS |
|---|---|---|
| Engine | Landlock + seccomp (via libseccomp) | Seatbelt |
| Files: read, write, create, delete | ✅ | ✅ |
| Starting programs | ✅ | ✅ |
| TCP ports | ✅ | ✅ |
| All network off (TCP and UDP) | ✅ | ✅ |
| Isolation between agents (signals, abstract sockets) | ✅ | ❌ No equivalent exists |
| Dangerous syscalls blocked (`io_uring`, `ptrace`, `mount`, namespaces, kernel modules, `bpf`, …) | ✅ | n/a |
| Secret environment variables removed | ✅ | ✅ |
| Report of what was blocked | ✅ | ✅ Best-effort |

`io_uring` is worth calling out: it can perform file operations without making the system calls a filter watches, so on Linux it is always blocked, whatever the policy says.

---

## Performance

Nothing sits between the agent and the kernel, so there's nothing in the path to slow it down. Measured on Linux 6.12 (aarch64) inside Docker on an Apple Silicon laptop. That's one virtualised machine, so treat the numbers as indicative rather than a benchmark:

**Once, at startup:**

| Step | Time |
|---|---|
| `hlyn.on()` with a small policy | ~2 ms |
| `hlyn.on()` naming 64 paths | ~3 ms |

**Per call, afterwards:**

| Call | Added |
|---|---|
| `open` | ~90 ns |
| `bind` | ~0.5 µs |
| `connect` | Lost in its own variance (a few hundred ns at most) |
| `read`, `write`, `stat` on files already open | Nothing measurable |

Files and connections that are already open are never re-checked, so throughput is unaffected. A proxy-based sandbox, by contrast, adds a TCP handshake and often a TLS round-trip **per connection**.

**Reporting under `hlyn run`:** nothing measurable on successful calls and under 0.1 µs per refused call on Linux; about 50 ms per run on macOS.

---

## The log

hlyn writes one JSON object per line, to stderr by default (or `--log FILE` / `log="file.jsonl"`).

```json
{"t": 1790338793.51, "kind": "seal", "pid": 4120, "backend": "linux", "level": 6, "read": ["/srv/data"], "write": [], "exec": false, "net": [443], "env": false, "tmp": "/tmp/hlyn-k2j3"}
{"t": 1790338793.52, "kind": "deny", "pid": 4121, "what": "read", "target": "/etc/shadow", "allow": null, "credential": true, "by": "cat", "op": "open", "count": 1, "source": "program"}
```

| Record | Written when |
|---|---|
| `seal` | The boundary was applied, with exactly what it grants |
| `deny` | Under `hlyn run`: something was refused, written as it happens |

Repeats are collapsed. The same refusal is written on its 1st, 2nd, 4th, 8th… occurrence with a running count, so a retry loop can't bury the lines that matter. `deny` records are written by `hlyn run`'s own unconfined process, never by the agent.

---

## Known limits

A sandbox that oversells itself is worse than one that doesn't, so here is exactly what hlyn does **not** do:

| Limit | What it means | What to do |
|---|---|---|
| **No host names** | `net` filters ports, not domains, so an open port reaches any host. | Keep secrets unreadable (see [Secrets in granted folders](#secrets-in-granted-folders)). Host allowlists are planned. |
| **Named ports are TCP only** | `net=[443]` leaves UDP open, so DNS and QUIC can still leave. | Use `net=False` when nothing may leave. |
| **Seal before threads** | A thread started before `on()` would keep its access, so hlyn refuses to seal. | Call `on()` first, or use `hlyn.run(fn)`. |
| **A granted socket grants its service** | The service behind a socket you allow (e.g. `docker.sock`) can hand the agent anything it can open. | Treat a socket grant like `exec` on that service. |
| **Writable folders others execute** | Writing into a folder that cron, git hooks or CI later runs is running code outside the sandbox. | Don't grant write to folders something else executes from. |
| **Hardlinks** | A hardlink planted inside a granted folder beforehand reaches the file it points at. | Don't share granted folders with untrusted writers, and don't run as root. |
| **GPU workloads** | CUDA writes under `/proc`, which is closed by default because it exposes the environment. | Grant `write=["/proc"]` and remove secrets at the source. |
| **macOS isolation between agents** | Seatbelt has no way to stop one agent signalling another. | Use Linux where cross-agent isolation matters. |
| **Reports are not complete** | Linux can't see inside static binaries; macOS drops a few percent of reports. | Neither affects enforcement, only the explanation. |

---

## FAQ

**Why not just use Docker?**
Docker packages and deploys software; it wasn't built to contain a compromised process, and a container often still sees secrets, mounted volumes and the network. hlyn enforces a layer below that, and it works *inside* your container too.

**Can the agent turn it off?**
No. The boundary lives in the kernel, not in Python. Once applied, it lasts for the life of the process and is inherited by everything it starts. hlyn has no off switch either.

**Does it slow the agent down?**
Not measurably. See [Performance](#performance).

**Does it work with LangChain / CrewAI / AutoGen / my own framework?**
Yes. hlyn confines a process, not a framework. Call `hlyn.on()` at startup, wrap the command with `hlyn run`, or put a single risky tool call inside `hlyn.run(fn)`.

**My agent broke under hlyn. How do I find out why?**
Run it with `hlyn run`, and the [report](#when-something-is-blocked) lists what was blocked and the flag to allow it. For Python agents, `hlyn watch` drafts a whole policy from one run.

**What happens on Windows?**
hlyn raises `hlyn.Unsupported` rather than running unprotected.

---

## Developing hlyn

```bash
tools/check.sh      # ruff, mypy --strict, clippy, cargo-audit, cargo-deny
docker build -t hlyn-test tools/ && docker run --rm -v "$PWD":/work -w /work hlyn-test python -m pytest tests -q
```

The Linux tests need a real Linux kernel, which is why they run in Docker. Most of the suite consists of escape attempts, each of which fails the build if the escape succeeds.

## License

Apache-2.0
