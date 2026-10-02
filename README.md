# hlyn

**A kernel-enforced environment for AI agents.** You list what an agent may read, write, run and reach. The operating system enforces it, and everything else is denied.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)

```python
import hlyn

hlyn.on(read=["./data"], write=["./out"], net=["api.openai.com"])

# From here on, this process can read ./data, write ./out, and reach
# api.openai.com over HTTPS. Nothing else: not ~/.ssh, not your .env, not
# any other host. This cannot be undone for the life of the process.
```

Or leave your code alone and wrap the command:

```bash
hlyn run --read ./data --write ./out --net api.openai.com -- python agent.py
```

---

## Contents

- [Why hlyn](#why-hlyn)
- [Features](#features)
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
| Agent sends data to a server | Works | Refused unless it is a host you listed. The network is off by default. |
| Agent runs `curl … \| sh` | Works | Refused unless you allowed that program |
| Agent reads `OPENAI_API_KEY` from its environment | Works | Removed before it starts, unless you kept it |
| You grant a folder that holds a `.env`, with the network open | Nothing tells you | hlyn warns before it starts, and says how to fix it |
| Agent tries to turn the environment off | No environment to turn off | There is no off switch, not even for hlyn itself |

> **The honest caveat.** Naming hosts stops the agent reaching any other host. It can't stop the agent sending data *to* a host you listed: a prompt to `api.openai.com` or a gist on `github.com` looks like normal traffic. So the rule that matters most is still: **don't let the agent read what it shouldn't send.** Grant narrow folders, pass API keys with `--env` rather than a readable `.env`, and let hlyn's [secret warning](#secrets-in-granted-folders) catch the rest. A bare port (`net=[443]`) is weaker again: it reaches every host on that port. [What naming hosts does not stop](#what-naming-hosts-does-not-stop) lists the rest.

**What makes it different:**

- **Enforced by the kernel.** Linux uses Landlock and seccomp; macOS uses Seatbelt. The rules are not a Python wrapper the agent could monkey-patch or talk its way around.
- **Deny by default.** An empty policy grants nothing except the files Python itself needs to run.
- **One line to start.** `hlyn.on()` or `hlyn run -- cmd`. Every extra permission is one more obvious argument.
- **No daemon, no container.** Ports and file rules are the kernel's own checks, so they add almost no latency. Naming hosts adds two helper processes for the run: a local proxy that checks each host, and on Linux a gate that makes the proxy the only way out. On Linux before 7.1 the gate also runs with ports or no network, because only it can keep programs away from local sockets such as `docker.sock` there (see [Performance](#performance)). It works inside Docker too.
- **Refuses rather than pretends.** If the machine cannot enforce your whole policy, hlyn raises an error instead of quietly enforcing part of it.
- **Zero runtime dependencies.**

---

## Features

| Feature | What it does, simply | How to use it |
|---|---|---|
| **File access** | The agent can read and write only the files and folders you name. Everything else, like your SSH keys or `.env`, is off limits. | `read=[...]`, `write=[...]` / `--read`, `--write` |
| **Program control** | The agent can start only the programs you allow, so it can't run `curl`, `bash` or anything it downloaded. | `exec=[...]` / `--exec` |
| **Network off by default** | No network at all unless you ask for it. | the default |
| **Allow only certain websites** | Name the hosts the agent may reach (`api.openai.com`); every other host, and DNS, UDP and direct IP tricks, is blocked. | `net=["api.openai.com"]` / `--net api.openai.com` |
| **Allow by port** | A simpler, looser option: allow a port (like 443) on any host. | `net=[443]` / `--net 443` |
| **Secrets removed** | API keys and other secret environment variables are deleted before the agent starts, unless you keep one on purpose. | `env=[...]` / `--env NAME` |
| **Secret-file warning** | Warns you before the run if the agent could read a secret file (like `.env`) *and* reach the network. | automatic |
| **Private scratch folder** | The agent gets its own fresh, empty temp folder for the run. | automatic (`--no-tmp` to turn off) |
| **Blocked-list report** | After `hlyn run`, lists what was blocked and the exact flag that would allow each one. | automatic with `hlyn run` (`--json` for machines) |
| **Watch mode** | Runs your agent once, unconfined, and writes a starter policy from what it actually used. | `hlyn watch -- cmd > policy.toml` |
| **Policy files** | Keep the rules in a TOML, JSON or YAML file next to your code and review them like code. | `hlyn run -f policy.toml` / `hlyn.on("policy.toml")` |
| **Presets** | Ready-made policies for common jobs: `strict`, `data`, `coder`, `web`, `debug`. | `hlyn.on("coder")` / `-p coder` |
| **Four ways in** | Lock the current process, run one function in a locked child, replace the process with a locked command, or wrap any command from the terminal. | `hlyn.on()`, `hlyn.run(fn)`, `hlyn.spawn(cmd)`, `hlyn run -- cmd` |
| **Claude Code in one command** | Claude Code confined to the project folder and Anthropic's API, with git working. | `hlyn claude` |
| **Agent isolation** | On Linux, one agent can't signal or connect to another agent on the same machine, or reach any program's SysV shared memory or message queues. | automatic (Linux) |
| **Dangerous system calls blocked** | Kernel tricks like `io_uring`, `ptrace`, mounting and loading kernel modules are always refused. | automatic (Linux) |
| **Machine check** | Tells you what this computer can enforce, and why not when it can't. | `hlyn probe` |
| **Log** | A JSON record of what was sealed and what was blocked, for audits and CI. | stderr by default, `--log FILE` |
| **No off switch** | Once applied, the lock lasts for the life of the process and everything it starts. Nothing, hlyn included, can remove it. | automatic |

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
ok  hlyn can confine programs on this machine (Linux 6.18.44)
    yes files and programs
    yes network ports
    yes host names in net (api.openai.com)
    yes isolation between agents on this machine
    yes local sockets only in write-granted folders, checked by hlyn's gate (Linux 7.1 or newer checks them in the kernel)
    yes listing what was blocked, after hlyn run
```

### Requirements

| Platform | Needs | Notes |
|---|---|---|
| **Linux** | Kernel **6.12+** with Landlock enabled, plus `libseccomp` (**2.5.0+** to name hosts in `net`) | x86_64 and aarch64, any glibc 2.28+ distribution (Debian 10+, Ubuntu 20.04+, RHEL 8+). Works inside Docker. Alpine (musl) is not supported. |
| **macOS** | Any current macOS | Nothing to build or install beyond Python. |
| **Python** | 3.10 or newer | Reading TOML policies on 3.10 needs `tomli`; YAML needs `pyyaml`. JSON always works. |
| Anything else | Not supported | hlyn refuses to run rather than pretend to protect you. |

> **Why such a new kernel?** Linux 6.12 is the first with Landlock ABI 6, which is what stops one agent signalling or connecting to another. Rather than enforce a weaker boundary than you asked for, hlyn refuses to run on older kernels. `hlyn probe` tells you exactly where a given machine stands.

> **Naming hosts on Linux** also needs hlyn's gate to read the address each connection dials. With `kernel.yama.ptrace_scope` at 0 or 1 (the usual setting) that works, except for programs started by a process that called `hlyn.on()`, which need 0. At 2 or 3, hlyn runs in *reduced mode*: programs that use `HTTPS_PROXY` still reach listed hosts, but address, `localhost` and local-socket entries don't. `hlyn probe` says which applies.

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

`hlyn run` confines the command and everything it starts, whatever language it is written in. The command itself is always allowed to run, and so is the script it is asked to run: `python agent.py` may read `agent.py`, and `./tool` may start the interpreter its `#!` line names. Nothing beside them is.

**Any Python works**, not just the one hlyn is installed in: a project venv, Homebrew's, pyenv's, `uv`'s, or Apple's `/usr/bin/python3`. Before sealing, hlyn asks that interpreter (itself confined: no writing, no network) where its standard library and packages are, and grants reading them. Launchers such as pyenv shims are followed to the real interpreter.

### Claude Code, confined

```bash
hlyn claude                      # Claude Code in this folder
hlyn claude --read ~/docs        # plus one more folder to read
hlyn claude -- --resume          # arguments after -- go to claude
```

At a terminal, `hlyn claude` first shows what Claude Code will get as a table (✓ it can, ✗ it can't, ! to watch: what, where, access) and asks before starting. When it ends, one more table lists what it was refused, each with the flag that would allow it, and a `next time:` line to copy; macOS's and Claude Code's own probes (the keychain, `/dev`) are left out of the screen and kept in the record. Type `y` to start, `n` to stop, or more access (`--read ~/docs --net pypi.org`) to add it and see the list again. Enter alone does nothing, so a stray key never starts it. `-y` skips the question; scripts are never asked. The record of what was refused goes to `~/Library/Logs/hlyn/claude.jsonl` (macOS) or `~/.local/state/hlyn/claude.jsonl`, not the screen.

Claude Code can read and write this folder, write its own state (`~/.claude`), read `~/.claude.json`, run any program, and reach Anthropic's API (`api.anthropic.com`, or the host in `ANTHROPIC_BASE_URL`) and the sign-in refresh (`platform.claude.com`). Nothing else: not `~/.ssh`, not your other projects, not any other host. git works, with your `~/.gitconfig`; `~/.git-credentials` stays closed. Flags add to this, as for `hlyn run`.

- **Sign-in on macOS:** run `hlyn claude --login` once. It runs `claude setup-token` (a browser sign-in), asks you to paste the token, and keeps it in your keychain as "hlyn: Claude Code sign-in". Each `hlyn claude` reads it from outside the environment and gives it to Claude Code alone; the keychain itself stays closed to the agent, and Claude Code keeps the token out of the commands its Bash tool runs (an `ANTHROPIC_API_KEY`, by contrast, reaches them). A variable you set (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, Bedrock, Vertex) always wins. `hlyn claude --logout` removes it. On Linux nothing is needed: the sign-in file in `~/.claude` works as it is.
- **`~/.claude.json` is read-only:** it lists the MCP servers Claude Code starts outside any environment, so the agent can't add one. Saving it needs write access to your whole home folder (Claude Code writes it through a temporary file beside it), so settings it would save there during the run aren't kept — including "don't ask me again" answers, so other first-run answers may not be kept (hlyn stops the "fullscreen renderer" question coming back: it sets `CLAUDE_CODE_NO_FLICKER=0` unless you've set it or chosen with `/tui`). Set `CLAUDE_CONFIG_DIR` to keep that file inside the state folder instead, where it saves.
- **`~/.claude` is writable**, settings and hooks included, and a hook runs unconfined the next time you start `claude` without hlyn. Start it with `hlyn claude` each time. Inside your project, hlyn names `.git/hooks`, `.claude/settings.json` and `.mcp.json` before the run if they exist ([Files that run later](#files-that-run-later)).
- **`--resume`, MCP servers and plugins:** `--resume` works (the session is kept in the state folder). An MCP server that runs as a program starts confined and needs nothing more. One on the network is a host: the end report names it, says which server or plugin reached for it, and gives the flag (`--net mcp.example.com`). One on this machine needs its port (`--net localhost:PORT`). A plugin folder outside the project needs `--read THAT_FOLDER`.
- **Bedrock, Vertex and Foundry:** hlyn allows only Anthropic's hosts, so on a cloud provider the session ends with its host in the report (`--net bedrock-runtime.us-east-1.amazonaws.com`). Variables that aren't `ANTHROPIC_*` or `CLAUDE_*` are removed unless you pass them, so a region in `AWS_REGION` or `CLOUD_ML_REGION` needs `--env AWS_REGION`, or the default region's host is the one named. With no AWS keys passed, Claude Code asks the cloud's credentials address (`169.254.169.254`): hlyn never offers to allow that, since it would hand the agent the machine's own role, and says to pass your keys instead (`--env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY`). A real session with credentials was not run *(unverified)*.
- **Interactive mode works** (keystrokes reach the full-screen session), as does `claude -p`. A program Claude Code's Bash tool starts is confined too, so a few things the agent might run don't work: Python's `multiprocessing` needs `--shm`. On Linux every program Claude Code starts (its Bash tool, `node`, a nested `claude`) reads its own `/proc/self`, in a process view that holds only the agent's own processes; programs it leaves running end with the session. The session itself is unaffected.

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
| `net` | Which hosts (or TCP ports) can it connect to? | None, and no network at all |
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
- **`net` holds hosts or ports, never both.** A port reaches every host on it, so mixing them would make the hosts meaningless; hlyn refuses and names both fixes. See [Hosts in `net`](#hosts-in-net).
- **Allowing any network also allows what the network needs.** DNS configuration and TLS certificate stores become readable automatically, so `net=["api.openai.com"]` really can make HTTPS requests. Private key folders such as `/etc/ssl/private` are never included.

### Hosts in `net`

Name hosts, and the agent reaches those hosts and no others: no other host on the same port, no UDP, no DNS of its own.

| Entry | Means |
|---|---|
| `api.openai.com` | That host, port 443 |
| `api.openai.com:8443` | That host, that port. Repeat the entry for more ports. |
| `*.example.com` | Any subdomain at any depth, port 443. **Not** `example.com` itself: list it separately. |
| `localhost:5432` | A service on this machine (127.0.0.1 and ::1) |
| `10.0.0.5:5432`, `[2001:db8::10]:8443` | That address and port |
| `10.20.0.0/16:8080` | An address range and port |

Anything hlyn couldn't enforce exactly is refused, with the fix:

```
$ hlyn run --net https://api.openai.com/v1 -- python agent.py
hlyn: net: 'https://api.openai.com/v1' is a URL. Give the host name: --net api.openai.com
```

The same goes for `*` alone or `*.com`, a name that isn't ASCII (write its `xn--` form), IPv4 in octal or hex, and port ranges.

**How it works.** hlyn starts a small proxy for the run and points the agent at it with `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and friends (plus the settings npm, Node and the JVM read). The proxy checks each host and makes the connection itself. Nothing else can leave: on Linux a gate process answers every `connect()` by handing over a connection to the proxy, or refusing; on macOS the environment allows only the proxy's port.

Worth knowing:

- **Names are looked up by the proxy, on every connection**, and the connection uses the address that was checked. A name that resolves to a private, loopback or cloud-metadata address is refused (DNS rebinding). Reach private services by address (`--net 10.0.0.5:5432`) or as `localhost:PORT`.
- **A program that ignores `HTTPS_PROXY`** can't look names up. The report says so, and names the client setting that fixes it (aiohttp: `trust_env=True`; urllib3: `ProxyManager`). Address and `localhost` entries are also reachable directly (on macOS, only `localhost` entries).
- **The TLS name must match the host.** A connection that asks the proxy for one host and then names another in TLS is closed.
- **Local sockets need `--write` on their folder.** The resolver, D-Bus and container-runtime sockets (`docker.sock` and the like) are refused whatever you grant, by what they are, not their name: a link to one is refused too.
- **Naming hosts narrows an open network.** `--preset web --net api.openai.com` means that host only, and hlyn says so.
- **Behind a corporate proxy** (`HTTPS_PROXY` set when hlyn starts), hlyn's proxy forwards through it. The private-address check is then skipped, because the corporate proxy resolves the names.
- **`hlyn.on()` with hosts** sets the proxy variables in `os.environ`. A client created before the call (`httpx.Client`, an aiohttp session) misses them: create it after.

When a host is blocked, the agent gets `403 hlyn: evil.com:443 is not in --net (allow with --net evil.com)` from the proxy; a direct connection to an address not listed gets `Permission denied`.

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
| What counts as a secret | `.env`, `.env.*` (not `.example`/`.sample`/`.template`), `.envrc`, `.npmrc`, `.netrc`, private SSH keys, `secrets.toml`/`.yaml`, `credentials.json`, service-account JSON, Terraform state, `~/.aws`, `~/.ssh`, `~/.kube`, … A `.key` or `.pem` file counts only if it holds a private key, so Keynote files and public certificates don't. |
| When it warns | Only when a secret is readable **through a folder** **and** the network is open |
| Granting a secret file on its own | No warning. Naming it is a decision. |
| Where it looks | Up to 4 folders deep, for at most half a second, skipping `.git`, `node_modules`, `.venv` and build output. Links are followed only as far as the kernel would. Files that live only in iCloud/Dropbox are never downloaded to be checked. |
| In Python | Raised as a `hlyn.Exposed` warning, so the standard filters apply |
| Make it an error | `PYTHONWARNINGS=error::hlyn.Exposed` refuses the run (exit 2), which keeps leaky policies out of CI. In Python, `warnings.simplefilter("error", hlyn.Exposed)` raises before anything is sealed. With hlyn installed from PyPI, Python first prints `Invalid -W option ignored: invalid module name: 'hlyn'`, because it reads the setting before it can import hlyn; hlyn applies it anyway. |
| Check a policy yourself | `hlyn.exposed(policy)` returns the list |

### Files that run later

A write grant can reach files **other programs run**: a git hook, Claude Code's own settings, `.mcp.json`, `.envrc`. hlyn refuses none of them, because they sit in a folder you granted on purpose, and neither kernel can grant a folder minus one file. So it names them before the run:

```
$ hlyn run --write . -- python agent.py
hlyn: warning: the agent can write 1 file that runs later, outside this environment:
  ./.git/hooks
  Whatever it writes there runs unconfined the next time you (or git, or CI) start that program.
  Grant a narrower folder (e.g. --write ./out instead of the whole project), or check these files before you run them again.
  Meant it? Run with PYTHONWARNINGS=ignore::hlyn.Runs to stop this warning.
```

| Detail | Behaviour |
|---|---|
| What counts | `.git/hooks`, `.githooks`, `.claude/settings.json`, `.claude/{hooks,agents,commands,skills,plugins}`, `.mcp.json`, `.envrc` in any granted folder; and in the home folder shell start-up files, `~/.gitconfig`, `~/.ssh/config`, `~/.claude.json`, `LaunchAgents`, `autostart`, `systemd/user`, `~/bin`, `~/.local/bin`; and `/etc/cron.d`, `/etc/profile.d`, `/etc/systemd/system`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` |
| What doesn't | `Makefile`, `package.json`, `pyproject.toml`, `Dockerfile`, `conftest.py`, `CLAUDE.md` and the like. Editing those is the agent's job, and a warning on every run would train you to ignore it. They are the [Writable folders others execute](#known-limits) limit instead. |
| When it warns | Only for paths that **already exist** and are writable under the policy. A name the agent could create is not named: every writable folder has infinitely many. |
| `hlyn claude` | Says nothing about Claude Code's own `~/.claude`, which it grants on purpose and explains [above](#claude-code-confined). It still names the project's hooks and `.mcp.json`. |
| Where it looks | The granted folders only, bounded: at most 2000 folders, skipping `node_modules`, `.venv`, `target` and build output. Links are followed only as far as the kernel would. At most 12 paths are named. |
| In Python | Raised as a `hlyn.Runs` warning, before anything is sealed, so the standard filters apply |
| Make it an error | `PYTHONWARNINGS=error::hlyn.Runs` refuses the run (exit 2). In Python, `warnings.simplefilter("error", hlyn.Runs)` raises before the seal, so the process is left untouched. |
| Check a policy yourself | `hlyn.later.found(policy)` returns the list |

### Policy files

Keep the policy next to your agent and review it like code. TOML, JSON and YAML all work:

```toml
# policy.toml
read  = ["src", "prompts"]   # relative paths resolve next to this file
write = ["out"]
exec  = false
net   = ["api.openai.com", "localhost:5432"]
env   = ["OPENAI_API_KEY"]
```

```bash
hlyn run -f policy.toml -- python agent.py
```

```python
hlyn.on("policy.toml")
```

- **An unknown field is an error.** `reed = [...]` is refused, never ignored.
- **Flags add to a file; they never replace it.** `hlyn run -f policy.toml --net pypi.org` keeps the file's hosts and adds pypi.org. The one exception is an open network: naming a host or port narrows it, and hlyn says so.

---

## Presets

| Preset | Grants | Good for |
|---|---|---|
| `strict` | Nothing beyond the Python runtime, and no scratch folder | Pure computation on inputs you pass in |
| `data` | Read and write the current folder | Data processing, notebooks |
| `coder` | Read and write the current folder, run any program | Coding agents |
| `web` | Any network | Agents that only browse. To call one API, name it instead: `--net api.openai.com` (with a preset, it narrows the preset's open network to that host) |
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
| Reaching a host that isn't listed | `--net HOST` |
| Connecting directly to an address, ignoring the proxy | `--net ADDRESS` (the report also names the client setting that makes it use the proxy) |
| Looking up a name itself, ignoring the proxy | None: a client setting (the report names it) |
| A local socket (whenever the network isn't open) | `--write FOLDER` (the folder that holds it) |
| Any network while the network is off | `--net-any`, or `--net PORT` for just the port it needs |
| Listening on a port | `--net-any` |
| A credential (`~/.ssh`, `~/.aws`, `.env`, `*.pem`, …) | **None.** It is named, never suggested. |

With hosts, a run that tried somewhere else looks like this:

```
$ hlyn run --read agent.py --net pypi.org -- python agent.py
https://pypi.org/simple/ -> 200
https://api.github.com/ -> <urlopen error Tunnel connection failed: 403 hlyn: api.github.com:443 is not in --net (allow with --net api.github.com)>
hlyn: the command finished, but hlyn blocked 1 thing it may have worked around:
  net    api.github.com:443  allow with --net api.github.com
  Only allow hosts you recognise: an injected agent chooses where it tries to go.
```

Some details:

- **Successful runs are reported too**, if something was refused along the way. A program that worked around a refusal is not behaving the way it did when you tested it.
- **Retries are counted, not repeated.** A loop that fails 5,000 times is one line: `[5000+ times]`.
- **Refusals from child processes are included**, labelled with the process name: `[by git]`.
- **Environment variables are named, never their values.**
- The agent can read the list too, while it runs: `$HLYN_BLOCKED` names a short file in its scratch folder with one line per refusal and the flag that would allow it (a credential is marked closed, with no flag). It can't change anything from inside; it tells you the flag. `hlyn claude` points Claude Code at it.
- `--json` prints the same report as JSON on stderr for CI; `--no-report` turns the list off (a command that failed still gets its exit code and the one-line hint).
- `hlyn probe` tells you whether reporting is available on the machine.

How it hears the refusals, and what it can miss:

| | Linux | macOS |
|---|---|---|
| Source | A tiny library preloaded into the command and its children | The environment's own reports, from the system log |
| Cost | Nothing measurable on calls that succeed | About 50 ms per run |
| Misses | Statically linked programs (most Go binaries; hlyn says so), and children of a program that clears its own environment | A few percent of reports under heavy system load |
| With hosts | The proxy and the gate report network refusals from outside the environment, whatever the program, static binaries included. Past 1,000 different ones, the rest are counted, not listed | The proxy's refusals, as on Linux; direct connections come from the system log as above |

---

## Writing your first policy

Deny-by-default is easy to enforce; the hard part is knowing what to allow. The workflow is **watch → trim → run**:

**1. Watch one unconfined run** and let hlyn draft the policy. On Linux it sees any program, and everything it starts; on macOS, Python programs:

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
  "api.openai.com:443",
  "pypi.org:443",
]
env = false
tmp = true
log = true
```

`net` lists the hosts the program reached. Python's own lookups and connections are recorded directly; anything that uses `HTTPS_PROXY` (requests, httpx, curl, git, pip, npm, Node, Go), in Python or not, goes through hlyn's proxy in a recording mode that lets everything through and notes where each connection went. It chains through your own proxy if you have one.

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
| `hlyn claude [flags] [-- ARGS]` | Runs Claude Code confined to this folder ([Claude Code, confined](#claude-code-confined)); flags add to what it gets |
| `hlyn claude --login` / `--logout` | macOS: keep a Claude Code sign-in in your keychain for `hlyn claude`, or remove it |
| `hlyn watch -- CMD` | Runs a program **unconfined** and prints the policy it would need (on macOS, Python programs) |
| `hlyn show [flags]` | Prints the full list of paths, hosts and ports a set of flags would grant |
| `hlyn show --intent [flags]` | Prints the flags as a policy file you can check in |
| `hlyn presets` | Lists the presets and what each grants |
| `hlyn probe` | Says what this machine can enforce; exits non-zero if it can't |
| `hlyn --version` | Prints the version |

Flags for `run`, `claude` (all but `-p` and `-f`) and `show`:

| Flag | Grants |
|---|---|
| `-p, --preset NAME` | Start from a preset |
| `-f, --policy FILE` | Start from a `.toml`, `.json` or `.yaml` file |
| `--read PATH` | Read a path (repeatable) |
| `--write PATH` | Write a path (repeatable) |
| `--exec PATH` | Run a program (repeatable) |
| `--exec-any` | Run any program |
| `--net HOST` | Reach a host: `api.openai.com`, `*.example.com`, `localhost:5432`, `10.0.0.5:5432` (repeatable) |
| `--net PORT` | Connect to a TCP port on any host (repeatable; not together with hosts) |
| `--net-any` | Use any network |
| `--env NAME` | Keep an environment variable (repeatable) |
| `--env-any` | Keep the whole environment, secrets included |
| `--no-tmp` | No private scratch folder |
| `--log PATH` / `--no-log` | Write the log to a file, or nowhere |

Only on `run` and `claude`:

| Flag | Does |
|---|---|
| `--no-report` | Don't list what was blocked |
| `--shm` | POSIX shared memory and semaphores, for Python `multiprocessing` (`Lock`, `Queue`, `Pool`, `shared_memory`). Linux: opens `/dev/shm`, so also your other programs' segments there. macOS: only the names Python makes (`/mp-*`, `/psm_*`). Off by default |
| `--keep-fd N` | Pass on open descriptor N (3 or more; repeatable). Every other descriptor above 2 the launcher left open is closed before the run |
| `--json` | Print the report as JSON (on stderr) |

Every command that prints data prints plain text by default, and JSON with `--json`.

---

## Python API

| Call | What it does |
|---|---|
| `hlyn.on(policy=None, **fields)` | Confines **this process**, permanently. Returns what was applied. |
| `hlyn.run(fn, policy=None, **fields)` | Runs `fn()` in a confined child process and returns its result (or re-raises its exception). The caller stays unconfined. |
| `hlyn.spawn(cmd, policy=None, **fields)` | Confines this process, then replaces it with `cmd`. Does not return. With hosts, this process stays as `cmd`'s gate instead: same PID, signals passed on, `cmd`'s exit status. |
| `hlyn.probe()` | Reports what this machine can enforce, as a dict. Changes nothing. |
| `hlyn.exposed(policy)` | Lists secret files the policy lets the agent read while the network is open. |
| `hlyn.sealed()` | `True` once this process is confined. |
| `hlyn.load(path)` | Reads a policy file into a `Policy`. |
| `hlyn.Policy(...)` | An immutable policy object with the seven fields above. |
| `hlyn.helper()` | In a frozen app (PyInstaller and the like), call it first, like `multiprocessing.freeze_support()`: it lets hlyn start its helpers when `net` names hosts. |
| `hlyn.preset(name)` / `hlyn.presets` / `hlyn.register(name, make)` | Look up, list and add presets. |

Anywhere a policy is expected, you can pass any of these:

```python
hlyn.on()                                      # nothing: the strictest default
hlyn.on("coder")                               # a preset name
hlyn.on("policy.toml")                         # a policy file
hlyn.on(hlyn.Policy(read=["./src"]))           # a Policy object
hlyn.on(read=["./src"], net=["api.openai.com"])  # keyword arguments
hlyn.on("coder", net=["api.openai.com"])         # a preset, plus changes
```

`hlyn.Policy` is frozen. Use `.with_(...)` to derive a new one:

```python
base = hlyn.Policy(read=["./src"])
wider = base.with_(net=["api.openai.com"])
```

### Errors

Every error inherits from `hlyn.Error`, so one `except` catches them all. `hlyn.Exposed` is a warning, not an error: it never stops the run.

| Error | Raised when | The process is |
|---|---|---|
| `hlyn.Invalid` | The policy is malformed: a typo, a missing path, a malformed host in `net`, ports and hosts mixed | Untouched |
| `hlyn.Unsupported` | This machine can't enforce the policy (old kernel, unsupported OS), or can't enforce host names here (libseccomp older than 2.5.0, or already inside another environment that filters connections) | Untouched |
| `hlyn.Failed` | The kernel refused to apply the boundary | **Not** confined, so don't continue |
| `hlyn.Sealed` | You called `on()` twice. The boundary can't be changed once applied. | Already confined |

Messages say what to do next, naming the field or flag that would change the outcome.

### Things to know

- **`on()` is one-way.** There is no `off()` and no context manager that pretends to restore anything, because the kernel can't undo it.
- **Call `on()` before starting threads.** On Linux, a thread that is already running would keep its old access, so hlyn refuses to seal a process with more than one thread. Put `on()` at the top of your program, or use `hlyn.run(fn)`, which forks a clean child.
- **With hosts, `on()` starts two helpers** before it seals: the proxy, and on Linux the gate. They live as long as your process, and the seal record names them. With ports or no network, `on()` starts the gate alone on Linux before 7.1, to check local sockets, and nothing on newer kernels or macOS.
- **With hosts, `hlyn.run(fn)` shares one proxy** between every call with the same hosts, for the life of the caller. Each call still gets its own gate.

---

## What is enforced, per platform

| | Linux | macOS |
|---|---|---|
| Engine | Landlock + seccomp (via libseccomp) | Seatbelt |
| Files: read, write, create, delete | ✅ | ✅ |
| Starting programs | ✅ | ✅ |
| TCP ports | ✅ | ✅ |
| Host names in `net` | ✅ Proxy, plus a gate that answers every `connect()` | ✅ Proxy, plus a profile that allows only its port |
| Direct connections to address entries (`10.0.0.5:5432`) | ✅ | ❌ Only through the proxy. `localhost:PORT` entries work directly |
| Local sockets only in write-granted folders | ✅ Whenever the network isn't open: by the kernel from Linux 7.1, before that by the gate, which connects the socket it checked itself | ✅ |
| All network off (TCP and UDP) | ✅ | ✅ |
| Isolation between agents (signals, abstract sockets, SysV shared memory and message queues) | ✅ | ✅ Signals and SysV IPC, as on Linux (macOS has no abstract sockets), and only measured system services: the pasteboard and notifications are refused. With an open network every service is allowed |
| Dangerous syscalls blocked (`io_uring`, `ptrace`, `mount`, namespaces, kernel modules, `bpf`, …) | ✅ | n/a |
| Secret environment variables removed | ✅ | ✅ |
| Report of what was blocked | ✅ | ✅ Best-effort |

`io_uring` is worth calling out: it can perform file operations without making the system calls a filter watches, so on Linux it is always blocked, whatever the policy says.

---

## Performance

Files and ports are the kernel's own checks, so nothing sits in their path. Measured on Linux 6.12 (aarch64) inside Docker on an Apple Silicon laptop. That's one virtualised machine, so treat the numbers as indicative rather than a benchmark:

**Once, at startup:**

| Step | Time |
|---|---|
| Landlock and seccomp themselves, small policy / 64 paths | ~1.5 ms / ~2 ms |
| `hlyn.on()` in all, network off or ports, Linux 7.1+ | ~10 ms |
| `hlyn.on()` in all, network off or ports, Linux before 7.1 | ~15 ms: it starts the gate that checks local sockets |

**Per call, afterwards:**

| Call | Added |
|---|---|
| `open` | ~90 ns |
| `bind` | ~0.5 µs |
| `connect` over TCP, Linux 7.1+ | Lost in its own variance (a few hundred ns at most) |
| `connect`, Linux before 7.1 | ~90 µs: the gate looks at each one to find the local sockets |
| `read`, `write`, `stat` on files already open | Nothing measurable |

Files and connections that are already open are never re-checked, so throughput is unaffected.

**With hosts**, connections go through the proxy, so each new one costs a loopback hop and the proxy's own connect. Measured on an x86_64 cloud VM (Linux 6.18):

| Measure | Without hosts | With hosts |
|---|---|---|
| `hlyn run -- true` | 95 ms | 135 ms: +41 ms. The proxy's own start overlaps the command's (its sockets are bound first and handed over) |
| `connect()` to the proxy (Linux), median / p99 | 18-21 µs / 68-77 µs, unconfined | 234-239 µs / 565-619 µs, through the gate |
| One connection's throughput (512 MB over loopback) | 2,717 MB/s, unconfined | 502 MB/s |
| `hlyn.run(fn)` per call, after the first | — | +1-6 ms (+46-49 ms if the caller has threads) |

**On macOS** (Apple Silicon, macOS 27; `tools/bench.py`, `tools/hostbench.py`):

| Measure | Without hosts | With hosts |
|---|---|---|
| `hlyn.on()`, small policy / 64 paths | ~11 ms / ~16 ms (Seatbelt compiles the profile) | — |
| `open` / `stat`, per call | +0.2-0.3 µs / +0.2 µs (Seatbelt also checks `stat`) | — |
| `connect` to a listed port, per call | +1.5-2.6 µs | — |
| `hlyn run -- true` | 82 ms, 90 ms with a port | 143 ms |
| `connect()` to a local service, median / p99 | 48 µs / 190 µs, same as unconfined | 507 µs / 712 µs through the proxy (the CONNECT round trip included) |
| One connection's throughput (512 MB over loopback) | 13,800 MB/s (15,200 unconfined) | 445 MB/s through the proxy |
| `hlyn.run(fn)` per call | 13 ms, 20 ms with a port | 23 ms |

On macOS, `localhost:PORT` entries are reached directly, not through the proxy, so a local service costs nothing extra; hosts go through it.

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
| `deny` | Under `hlyn run`: something was refused, written as it happens. With hosts, network refusals are written from every entry point, by the proxy and the gate |

With hosts, the seal record also names them, the proxy's address and the helpers' process IDs:

```json
{"t": 1790529261.533, "kind": "seal", "pid": 4703, "backend": "linux", "level": 7, "read": [], "write": [], "exec": ["/usr/bin/true"], "net": ["api.openai.com:443", "localhost:5432"], "env": false, "tmp": "/tmp/hlyn-cga5azni", "proxy": "127.0.0.1:38483", "helpers": [4702, 4700], "closed": 0}
```

Repeats are collapsed. The same refusal is written on its 1st, 2nd, 4th, 8th… occurrence with a running count, so a retry loop can't bury the lines that matter. `deny` records are written from outside the environment (by `hlyn run`'s own process, or by the proxy and the gate), never by the agent.

---

## Known limits

An environment that oversells itself is worse than one that doesn't, so here is exactly what hlyn does **not** do:

| Limit | What it means | What to do |
|---|---|---|
| **Data sent to a host you allowed** | A listed host can receive anything the agent can read. | Keep secrets unreadable (see [Secrets in granted folders](#secrets-in-granted-folders)). |
| **Named ports are TCP only, and reach every host** | `net=[443]` leaves UDP open, so DNS and QUIC can still leave, and reaches any host on 443. On macOS it also grants the system resolver, which looks up any name it is asked, so data can leave one DNS label at a time. | Name hosts instead, which closes all three (the proxy looks names up; the agent can't), or use `net=False` when nothing may leave. |
| **Host names on Linux are new** | Tested on x86_64 without Yama so far. aarch64, and kernels with Yama, are designed for but not yet run. | `hlyn probe` says what this machine can do. |
| **Seal before threads** | A thread started before `on()` would keep its access, so hlyn refuses to seal. | Call `on()` first, or use `hlyn.run(fn)`. |
| **A granted socket grants its service** | The service behind a socket you allow (e.g. `docker.sock`) can hand the agent anything it can open. | Treat a socket grant like `exec` on that service. |
| **Writable folders others execute** | Writing into a folder that cron, git hooks or CI later runs is running code outside the environment. hlyn names the ones it finds before the run (see [Files that run later](#files-that-run-later)), but it can only refuse the whole folder, not one file in it. | Don't grant write to folders something else executes from. |
| **Hardlinks** | A hardlink planted inside a granted folder beforehand reaches the file it points at. | Don't share granted folders with untrusted writers, and don't run as root. |
| **GPU workloads** | CUDA writes under `/proc`, which is closed by default because it exposes the environment. | Grant `write=["/proc"]` and remove secrets at the source. |
| **Python `multiprocessing`** | `Lock`, `Queue`, `Pool` and shared memory need POSIX shared memory, refused by default. | Add `--shm` (`shm=True`). On Linux that also exposes your other programs' segments in `/dev/shm`. Threads and `subprocess` need nothing. |
| **macOS: system services with an open network** | Unless the network is open, only measured system services are allowed (no pasteboard, no notifications, the keychain only with a readable keychain file). With `--net-any` every service is, so two agents can pass data through the pasteboard, and an agent can read or replace what you copied. | Name hosts or ports instead of `--net-any`. |
| **macOS: the start folder's names** | macOS reports a folder's path only to a program that may read the folder, so hlyn lets a program read the folder it starts in: its path and the names in it, not the files or anything below. On Linux the names stay hidden. | Start the agent in a folder whose names you don't mind it seeing. |
| **macOS: browsers, Electron and `open`** | Chromium registers system services and sandbox extensions of its own, which hlyn's environment refuses, so Chrome, Electron apps and browser automation built on them don't run under hlyn on macOS. `open` can't start apps or open URLs in any mode (the app would run outside the environment). | Run them outside hlyn. |
| **Programs that outlive the command** | A program the command starts and detaches (a double fork with `setsid`) keeps running, and writing inside its grants, after `hlyn run` returns. It stays confined exactly as it was, and hlyn does not wait for it or stop it. | Look for leftover processes after a run, and don't grant write to anything the agent shouldn't touch once you've stopped watching. |
| **`hlyn.on()` and open descriptors** | A file or socket the caller already has open keeps working after `on()`, even outside the grants: the kernel checks opening, not using. `on()` warns (`hlyn.Inherited`) about files outside the grants and connected unix sockets; `-W error::hlyn.Inherited` refuses. | Use `hlyn run` or `hlyn.run(fn)`, which close them, or close them before `on()`. |
| **Reports are not complete** | Linux can't see inside static binaries; macOS drops a few percent of reports. | Neither affects enforcement, only the explanation. |

### What naming hosts stops, and what it doesn't

This is the threat model from the [design](DESIGN-host-allowlisting.md), in the same words; section numbers refer to it. [SECURITY.md](SECURITY.md) has it too.

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

---

## FAQ

**Why not just use Docker?**
Docker packages and deploys software; it wasn't built to contain a compromised process, and a container often still sees secrets, mounted volumes and the network. hlyn enforces a layer below that, and it works *inside* your container too.

**Can the agent turn it off?**
No. The boundary lives in the kernel, not in Python. Once applied, it lasts for the life of the process and is inherited by everything it starts. hlyn has no off switch either.

**Does it slow the agent down?**
Not measurably with ports. Naming hosts adds about 0.2 ms to each new connection and 40 ms to starting `hlyn run`. See [Performance](#performance).

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

Releases are built by `.github/workflows/release.yml` on a `v*` tag: manylinux_2_28 wheels for x86_64 and aarch64 (built in PyPA's image, checked with `auditwheel`), a macOS wheel and the sdist, each with build provenance, published to PyPI by trusted publishing, which signs every file with Sigstore. Every action is pinned to a commit.

## License

Apache-2.0
