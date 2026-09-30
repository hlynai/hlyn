# hlyn

A kernel-enforced environment for AI agents: Landlock, seccomp and a user-notify gate on Linux; Seatbelt on macOS; a proxy that checks hostnames. Everything not allowed is refused, and a report names the flag that would allow it.
- Code: `src/hlyn/` (OS layers in `core/`), `native/` (Rust), `tests/`, `tools/`.
- Docs: `DESIGN-host-allowlisting.md` (the contract), `RESEARCH-…` (evidence behind decisions), `FINDINGS.md` (verified memory), `REMAINING.md` (what's left).

## Battle-tested first
hlyn is security software, and bugs hide in code only we have run. A kernel facility, standard or widely used library has been attacked and debugged by thousands; our own copy by nobody.
- Before building anything non-trivial, search for a proven, maintained solution. For security code this is required.
- If one exists, **use it as it is**. Don't rewrite, port or duplicate it; copy its pattern only if it truly can't be used directly.
- Custom code only fills the gap it leaves, small and built on top of it.
- Record in the design doc or commit what was considered and why it didn't fit. "Easier to write our own" isn't a reason. When unsure, ask the user.

## Product rules
- One line (`hlyn.on()` / `hlyn run -- cmd`) gives a safe, working minimum with strict defaults; each extra need is one obvious argument.
- Names are plain English, one word where possible: guessable from the name alone.
- Every message says what to do next: a refusal names the flag or field that changes the outcome.
- Human output by default, `--json` on every command that prints data.
- **Say "environment", never "sandbox"**, in code, comments, docs, messages, tests and commits: "the agent's environment", "outside the environment", "confined" for the adjective. Exceptions, kept exact: `sandbox_init`, `sandbox-exec`, `(target same-sandbox)`, the macOS log sender `Sandbox`, other products' names (Docker Sandboxes, sandbox-runtime), URLs, verbatim quotes, and the PyPI search keyword in `pyproject.toml`.

## Evidence
- **Done means shown running.** Run the real thing (CLI command, library call, the FINDINGS reproduction) and show its full output next to the test log. Code only read or unit-tested is not done; never claim "fixed" from reading code.
- **Tests show behaviour, in full.** Run `pytest -vv -rA` (the config adds `-q`) and paste the output. Tests print what they observed: the confined program's output, the report text, the errno. A pass showing the wrong behaviour is a failure; a count of passes is not evidence.
- **Triple-check every test, fuzz target and harness** before counting it. A weak test that passes is worse than none: it gets quoted as proof.
  1. It can fail: plant the bug in a copy, watch it fail, remove it, watch it pass (`tools/fuzzcheck.sh` does this for fuzz targets).
  2. Nothing passes vacuously: `all()` over a possibly empty list, a limit inputs never reach, a check the types already guarantee, a runner watching only one failure mode.
  3. It measures the real thing at real scale: exact values from the input, not a plausible range; long runs bounded in memory.

  Do this when writing a test, reviewing one, and before quoting numbers. A weak test gets fixed and re-run; its old results aren't reported.
- **Where tests run:** Linux via `tools/linuxtest.sh -vv -rA` (Docker Desktop's 6.12 kernel; Docker must be running); macOS via `python3 -m pytest -vv -rA`; real x86_64 and Linux 7.x on the Kali VM.
- **No user-global state.** Experiments touch only what they create (a test once locked the real login keychain).
- **Git:** commit locally as checkpoints; never push without asking.

## FINDINGS.md
The project's memory of what has been *proven*, including dead ends. Sessions and agents start cold; a lesson left only in a chat is lost and paid for again.
- **Read first.** Before changing or debugging an area, `grep -n -i <area> FINDINGS.md` and read the entry. Listed dead ends stay dead unless their premise changed; say which.
- **Write an entry**, before the commit, when you learned what the code doesn't show: debugging that took more than one try, a measurement or research that decided something, a test found weak. A first-try fix goes in the commit message instead.
- **Shape:**
  ```
  ## <Area>: <what happened> (<fixed|measured|found> YYYY-MM-DD; REMAINING #n)
  - **Symptom:** exact error, errno or output.
  - **Root cause:** the mechanism, with file/function or kernel feature.
  - **Didn't work:** each attempt and why. The most valuable part.
  - **Fix:** what changed, where.
  - **Where measured:** OS, kernel, architecture, machine.
  - **Verify:** a pasteable command, the output that proves it, the test that pins it.
  ```
- **Trustworthy:** only what was run is fact; mark the rest *(unverified)*. Exact numbers with scale, never "works now". Link entries that revise each other; strike stale ones with a note, never delete.

## Agents
Defaults, not limits; the user can change them for any task.
- **When:** independent parts — broad searches, separate research questions, parallel measurements. Small or connected work stays in the lead session.
- **Code:** agents research; the lead writes code, so one session sees the whole diff. If an agent does write code, it gets its own worktree and disjoint files. Only the lead edits FINDINGS, TODO, REMAINING and the design doc, from text agents return.
- **How many:** about five at a time, each with a distinct question.
- **The brief** carries everything, since the agent knows nothing of this conversation:
  1. Goal, and why it matters.
  2. What's known: FINDINGS and design sections to read, dead ends not to retry.
  3. Scope: files it owns or may read.
  4. All CLAUDE.md rules apply to it.
  5. What to return: full command output, sources as URL or `file:line`, each claim marked *measured* or *read*, what failed, open questions.
  6. When to stop and report instead of guessing.
- **Checking:** a report is a claim until the lead re-runs its commands, reads every diff line and triple-checks its tests. Look for skipped or weakened tests, checks that can't fail, conclusions without output. When sources disagree, measure; don't vote.
