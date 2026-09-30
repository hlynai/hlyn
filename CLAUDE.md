## Product rules
- **Names are plain English, one word where possible.** Commands, flags, fields, functions: a developer should guess what it does from the name alone.
- **Usable without reading docs.** One line (`hlyn.on()` / `hlyn run -- cmd`) must give a safe, working minimum. Defaults stay strict and sensible; every extra need is one more simple, obvious argument. Easy by default, fully configurable when wanted.
- **Every message tells the user what to do next.** Errors and refusals name the flag or field that would change the outcome.
- **Human output by default, `--json` for machines**, on every command that prints data.
- **Never say "sandbox"; say "environment".** In code, comments, docs, messages, tests, commits and anything written about hlyn, what hlyn creates is an *environment*: "the agent's environment", "outside the environment", "confined" for the adjective (never "sandboxed"). The only exceptions are names that belong to someone else and must match exactly: Apple's API and profile syntax (`sandbox_init`, `sandbox-exec`, `(target same-sandbox)`), the macOS log sender `Sandbox`, other products' names (Docker Sandboxes, Anthropic's sandbox-runtime), URLs and verbatim quotes.
- **Prefer battle-tested over custom.** Before building anything non-trivial, and always for anything security-critical, look for a proven, maintained solution: a kernel facility, a standard, a widely deployed library or tool. Use it, or follow its pattern. Write custom code only for the gap it leaves, and record in the design doc or commit why the proven option didn't fit.

## Findings (engineering memory)
[FINDINGS.md](file://<repo>/FINDINGS.md) records what has been *verified* about how this codebase behaves: root causes, dead ends, and how to measure each fix.
- Before touching an area it covers, read that section. Listed dead ends are not to be retried unless the premise has changed.
- After any debugging that took more than one attempt, append an entry *before* committing: symptom → root cause → what didn't work and why → what worked → how to verify. Mark anything not measured as *(unverified)*.
- A fix is not done until its "verify" step has been run. Never claim "fixed" from reading code alone.
- Keep it factual and terse. Retire stale entries with a strike-through and a note; don't silently delete.

## Working with agents
These apply to the lead session and to every agent it starts.
- **One orchestrator, at most five agents at a time.** When work is split across agents, the lead plans, briefs, reviews and merges. It writes code itself only when an agent is blocked (for example by a safety filter) or the change is too small to be worth a brief. Every brief names the files the agent owns, the docs and FINDINGS.md sections to read, and the evidence to bring back. Agents working at the same time get separate git worktrees and disjoint files; shared docs (FINDINGS.md, TODO.md, the design doc) are edited by the lead, from text the agents return.
- **Test output is shown in full, never as pass/fail alone.** Run tests with `pytest -vv -rA` (the project config adds `-q`, so a single `-v` only cancels it), so every test's name, result and captured output appear, and paste that output when reporting. Tests print what they observed (the confined program's output, the report text, the errno) so the log shows the behaviour, not just a verdict. A pass whose output shows the wrong behaviour is a failure; a count of passes is not evidence.
- **The lead checks every agent's work by hand before merging.** Read the whole diff, re-run the tests and the demonstration, and look for corner cutting: skipped or weakened tests, checks that can't fail, claims without output behind them, TODOs left in place of work, anything short of the design doc. Work that isn't state of the art goes back to the agent, or gets fixed, before it is merged.
- **Done means shown running.** Before calling work finished, run the real thing (the CLI command, the library call, the reproduction from FINDINGS.md) and show its full output next to the test log. Code that was only read, or only unit-tested, is not done.
- **Triple-check every test before trusting it.** A weak test that passes is worse than no test: it gets reported as proof. Before counting any test, fuzz target or harness as evidence, check it three ways:
  1. **It can fail.** Plant the bug it is meant to catch, in a copy, and watch it fail. Then remove the bug and watch it pass. `tools/fuzzcheck.sh` does this for the fuzz targets.
  2. **No check passes without testing anything.** Look for:
     - `all(...)` over a list that can be empty;
     - a check the input can never reach (a limit larger than the inputs ever get);
     - a check the types already guarantee (a 16-bit port "within 0-65535");
     - a runner that watches only one way of failing.
  3. **It measures the real thing, at the real scale.** It checks exact values against the input, not just a plausible range. Long runs are bounded in memory. The logged output shows the behaviour itself.

  Do this when writing a test, when reviewing an agent's test, and before quoting a run's numbers. A weak test found this way gets fixed, and its earlier results are re-run rather than reported.
- **Linux runs use `tools/linuxtest.sh`** (Docker Desktop's 6.12 kernel; builds both native crates, then runs pytest with the arguments given). macOS runs use the host's `python3 -m pytest`.
