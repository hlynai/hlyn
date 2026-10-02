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
- **Understood at a glance.** Anything a person reads (a screen, a report, an error, a prompt) is designed to be taken in in one look: a table or short rows with a mark, never paragraphs; the answer first, detail after; examples drawn from the person's own situation; nothing repeated on screen that hasn't changed. Check it by looking at the real output at 60 and 100 columns, not by reading the code.
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

### Orchestration: agents that write code
When the user asks the lead to orchestrate (the lead plans and checks; agents write the code). Proven over two rounds on 2026-10-02.
- **Models:** the lead runs on Opus 5.5 (`claude-opus-5-5`); every agent runs on Sonnet 5.5 (`model: "sonnet"`). If the session isn't on Opus 5.5, say so before starting and ask the user to switch (`/model claude-opus-5-5`).
1. **Pick the work first.** Read REMAINING, FINDINGS and the code yourself; choose essential, quick items first, about three at a time, distinct enough that each agent owns its own files. Related items (e.g. two changes to one module) go to one agent.
2. **Pin the base.** Worktrees can start from `origin/main`, which may be far behind local `main` (it was, once: false failures, and a fix that missed code it never saw). Commit any pending work, then start every brief with "`git reset --hard <hash>`; confirm `git log --oneline -1`".
3. **Brief precisely, not rigidly.** Goal and why; the FINDINGS entries and design sections to read and the dead ends; a plan to follow "unless you find something clearly better, and say why"; the exact files and functions it may edit, and what a neighbouring agent is editing; tests with an unconfined control and a planted bug; both suites with the expected baseline counts; what to return (commit hash, measured vs read, ready-to-paste FINDINGS/README/REMAINING text). Name when to stop and ask: anything that widens what hlyn allows, writes user-global state, or breaks documented behaviour. Time-box investigations.
4. **Agents don't edit the docs.** FINDINGS, REMAINING, README, PROGRESS, BRAG and the design doc are the lead's; agents return the text.
5. **Run in the background, `model: "sonnet"` (Sonnet 5.5), `isolation: "worktree"`.** Tell the user what each is doing and the guardrails, then wait for the notifications; never predict results.
6. **Check each before merging:** read the whole diff; rebase onto current `main` and resolve conflicts by hand; re-run its tests; re-plant one bug yourself and watch it fail; look at any test it changed (stronger or weaker?) and anything outside its scope. A report's "N failures, pre-existing" is a claim: check what base it ran on.
7. **Merge one at a time** (`git merge --ff-only` after the rebase), then run both full suites on the merged `main`, sequentially, not while agents load the machine (timing numbers taken under load are re-measured on a quiet machine before they are quoted).
8. **Then the lead writes the docs** from the agents' text, verified: FINDINGS (including what the lead caught), REMAINING, README, PROGRESS, and BRAG.md for measured claims only (strike any line not measured). Commit, remove the worktrees and their branches, and report to the user in a table: what each delivered, what the lead caught, and the decisions still theirs.
