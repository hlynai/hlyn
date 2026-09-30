# hlyn

Kernel-enforced environment for AI agents: Landlock + seccomp + a user-notify gate on Linux, Seatbelt on macOS, a proxy for hostnames.
- Code: `src/hlyn/` (OS layers in `core/`), `native/` (Rust), `tests/`, `tools/`.
- Docs: `DESIGN-host-allowlisting.md` (the contract), `RESEARCH-…` (evidence), `FINDINGS.md` (verified memory), `REMAINING.md` (what's left).

## Battle-tested first
Security bugs hide in code only we have run. Before building anything non-trivial, look for a kernel facility, standard or widely used library. If one exists, **use it as it is**: don't rewrite, port or duplicate it. Custom code only fills the gap it leaves, built on top of it. Record why in the design doc or commit ("easier to write our own" isn't a reason). When unsure, ask the user.

## Product rules
- One line (`hlyn.on()` / `hlyn run -- cmd`) gives a safe, working minimum; each extra need is one obvious argument.
- Names are plain English, one word where possible.
- Every message says what to do next: a refusal names the flag or field that changes the outcome.
- Human output by default, `--json` on every command that prints data.
- **Say "environment", never "sandbox"** (adjective: "confined"), everywhere. Exceptions, kept exact: `sandbox_init`, `sandbox-exec`, `(target same-sandbox)`, the log sender `Sandbox`, other products' names, URLs, verbatim quotes.

## Evidence
- **Done means shown running:** the real command or call, full output next to the test log. Read or unit-tested only is not done.
- **Tests:** `pytest -vv -rA`, output shown in full. Tests print what they observed. A pass showing wrong behaviour is a failure.
- **Triple-check every test** before counting it:
  1. It can fail: plant the bug in a copy, watch it fail, remove it, watch it pass (`tools/fuzzcheck.sh` for fuzz targets).
  2. Nothing passes vacuously: `all()` over an empty list, a limit inputs never reach, a check the types guarantee, a runner watching one failure mode.
  3. Real thing, real scale: exact values, bounded memory.

  A weak test gets fixed and re-run; its old results aren't reported.
- **Where:** Linux via `tools/linuxtest.sh -vv -rA` (Docker Desktop must be running); macOS via `python3 -m pytest -vv -rA`; x86_64 and Linux 7.x on the Kali VM.
- **No user-global state:** experiments touch only what they create (a test once locked the real login keychain).
- **Git:** commit locally; never push without asking.

## FINDINGS.md
- Before changing or debugging an area, `grep -n -i <area> FINDINGS.md` and read the entry. Listed dead ends stay dead unless their premise changed.
- Add an entry, before the commit, for: debugging that took more than one try, a measurement or research that decided something, a test found weak. Shape:
  `## <Area>: <what happened> (<fixed|measured|found> YYYY-MM-DD)`, then Symptom, Root cause, Didn't work (and why), Fix, Where measured (OS, kernel, arch), Verify (command + expected output).
- Only what was run is fact; mark the rest *(unverified)*. Exact numbers with scale. Strike stale entries, never delete.

## Agents
Defaults, not limits; the user can change them.
- Use agents for independent parts (broad searches, separate research questions, parallel measurements). Small or connected work stays in the lead session.
- Agents research; the lead writes code. If an agent does write code, it gets its own worktree and disjoint files. Only the lead edits FINDINGS, TODO, REMAINING and the design doc.
- About five at a time, one distinct question each.
- The brief carries everything the agent needs: goal, what's known and dead ends, files in scope, "all CLAUDE.md rules apply", what to return (full command output, sources as URL or `file:line`, each claim marked measured or read, what failed), when to stop.
- A report is a claim until checked: re-run its commands, read every diff line, triple-check its tests. When sources disagree, measure; don't vote.
