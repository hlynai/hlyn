# hlyn

hlyn confines an AI agent to what it was allowed: files it may read or write, programs it may run, hosts it may reach. The kernel enforces it:
- **Linux:** Landlock, seccomp, and a user-notify gate for connections.
- **macOS:** Seatbelt.

A proxy checks hostnames. Everything not allowed is refused, and a report says what was refused and which flag would allow it.

Where things are:
- `src/hlyn/`: the library and CLI. The OS layers are in `core/` (`linux.py`, `landlock.py`, `seccomp.py`, `notify.py`, `mac.py`).
- `native/`: Rust crates, including the `LD_PRELOAD` reporter.
- `tests/`: pytest. `tools/`: test runners, fuzzing and race harnesses (`tools/hostlab/`).
- `DESIGN-host-allowlisting.md` is the design and the contract. `RESEARCH-…` holds the evidence behind decisions.
- `FINDINGS.md` is the verified engineering memory. `REMAINING.md` lists what's left.

## Use what's battle-tested; don't rebuild it

This rule comes before the others. hlyn is security software, and bugs hide in code that only we have run. A kernel facility, a standard or a widely deployed library has been attacked, fuzzed and debugged by thousands of people in production. A copy we write ourselves has been tested by nobody.

- **Search first.** Before building anything non-trivial, look for a proven, maintained solution: a kernel facility, a standard, or a widely used library or tool. For anything security-critical, this search is required.
- **If one exists, use it as it is.** Don't rewrite it, don't port it, and don't rebuild "the same thing, but ours". Copying its pattern is only the fallback when it truly can't be used directly.
- **Write custom code only for the gap it leaves.** Keep that code small, and build it on top of the proven piece, not beside it.
- **Record why.** Put in the design doc or the commit what was considered and why it didn't fit. "It was easier to write our own" is not a reason.
- **When in doubt, ask the user** before building instead of reusing.

## What the product must feel like

1. **One line gives a safe minimum.** `hlyn.on()` or `hlyn run -- cmd` works with no docs and strict defaults. Each further need is one more obvious argument.
2. **Names are plain English**, one word where possible. A developer should guess what a command, flag, field or function does from its name.
3. **Every message says what to do next.** A refusal names the flag or field that would change the outcome. A bare "no" is a bug.
4. **Humans by default, `--json` for machines**, on every command that prints data.
5. **It's an "environment", never a "sandbox".** This applies everywhere: code, comments, docs, messages, tests, commits.
   - What hlyn creates is "the agent's environment". Things are "inside" or "outside the environment".
   - The adjective is "confined", not "sandboxed".
   - Keep other people's names exactly as they are: Apple's `sandbox_init`, `sandbox-exec`, `(target same-sandbox)`, the macOS log sender `Sandbox`, Docker Sandboxes, Anthropic's sandbox-runtime, URLs, and verbatim quotes.

## How I work here

**Evidence over claims.** Nothing is "done" or "fixed" until it has been shown running:
- the real CLI command or library call, or the FINDINGS.md reproduction;
- its full output shown next to the test log.

Code that was only read, or only unit-tested, doesn't count.

**Tests print what they saw, and I show all of it:**
- Run `pytest -vv -rA`. The project config adds `-q`, so one `-v` only cancels it.
- Tests print what they observed: the confined program's output, the report text, the errno.
- A pass whose output shows the wrong behaviour is a failure. A count of passes is not evidence.

**Before trusting any test, fuzz target or harness, I check it three ways.** A weak test that passes is worse than none, because it gets quoted as proof.
1. **It can fail.** Plant the bug it's meant to catch, in a copy, and watch it fail. Remove the bug and watch it pass. `tools/fuzzcheck.sh` does this for the fuzz targets.
2. **Nothing passes without testing anything.** Look for:
   - `all(...)` over a list that may be empty;
   - a limit the inputs never reach;
   - a check the types already guarantee;
   - a runner that watches only one way of failing.
3. **It measures the real thing, at the real scale.** It checks exact values derived from the input, not a plausible range. Long runs stay bounded in memory.

I do this when writing a test, when reviewing one, and before quoting a run's numbers. If a test turns out weak, I fix it and re-run it. I don't report its old results.

**Where tests run:**
- **Linux:** `tools/linuxtest.sh -vv -rA`, on Docker Desktop's 6.12 kernel. It builds both native crates first, and Docker Desktop must be running.
- **macOS:** `python3 -m pytest -vv -rA` on the host.
- **Real x86_64 and Linux 7.x:** these wait for the Kali VM, and the REMAINING.md items say what to run there.

**Experiments never touch the user's global state.** Tests act only on objects they create: their own files, keychains, sockets and processes. This rule exists because a test once locked the real login keychain.

**Git:** I commit locally as checkpoints and never push without asking. Commit messages say what changed and why.

## FINDINGS.md: memory that has been measured

FINDINGS.md is where this project remembers what it has *proven*, and the dead ends too. Sessions and agents start cold. A lesson that lives only in a chat transcript is lost, and the next session pays for it again.

**Read before you act.**
- Before changing an area, or debugging anything, search FINDINGS.md for it (`grep -n -i <area> FINDINGS.md`) and read the whole entry.
- A listed dead end stays dead unless its premise has changed. If you retry one, say which premise changed.

**Write an entry when you learned something the code doesn't show:**
- debugging that took more than one attempt;
- a measurement that decided something, such as a benchmark, a kernel behaviour or a race count;
- research that changed a decision, especially one that overturned an earlier belief;
- a test or harness that turned out weak, and what exposed it.

Write it before the commit that it explains. A first-try fix belongs in the commit message, not here.

**Use this shape**, matching the existing entries:
```
## <Area>: <what went wrong or was measured, in plain words> (<fixed|measured|found> YYYY-MM-DD; REMAINING #n if any)
- **Symptom:** what was seen, with the exact error, errno or output.
- **Root cause:** the mechanism, not a guess. Name the file and function, or the kernel feature.
- **Didn't work:** each attempt, and why it failed. This is the most valuable part; keep it.
- **Fix:** what changed, and where.
- **Where measured:** OS, kernel, architecture and machine (for example Docker Desktop 6.12.76 aarch64). Results differ between them.
- **Verify:** a command someone can paste, and the output that proves it. Name the test that pins it.
```

**Keep it trustworthy:**
- Only what was run goes in as fact. Mark anything read, inferred or reported by someone else *(unverified)*. Replace the mark once it's measured.
- Give exact numbers and outputs, not "works now" or "much faster". Include the scale ("0 of 10,000,000 tries").
- If a later entry changes an earlier one, link them both ways.
- When a finding stops being true, strike it through and say what changed and when. Never delete it silently; the history is part of the lesson.
- Leave out anything the code, git history or design doc already says.

## Agents

These are defaults, not fixed limits. The user can change them for any task, and a task that clearly needs more can ask for it.

**When to use them.** Use agents for work that splits into independent parts:
- broad searches across the codebase or the web;
- research questions that don't depend on each other;
- long measurements that can run in parallel.

Do small or tightly connected work in the lead session. A brief that costs more than the work is waste.

**Who writes the code.**
- By default, agents research and the lead writes the code, so one session sees and checks the whole diff.
- When an agent does write code (the user asked, or the work splits cleanly), it gets its own git worktree and files no other agent touches.
- The lead edits the shared docs (FINDINGS.md, TODO.md, REMAINING.md, the design doc) from text the agents return.

**How many.** About five at a time is the usual ceiling. Go above it when the user says so. Give each agent a separate question; two agents answering the same one is duplicate spend unless the aim is an independent check.

**The brief.** An agent knows nothing about this conversation, so the brief carries everything:
1. **Goal:** the one question to answer, or the change to make, and why it matters.
2. **What's already known:** the FINDINGS.md sections, design-doc sections and files to read first, and the dead ends not to retry.
3. **Scope:** the files the agent owns or may read, and what is out of bounds.
4. **Rules it inherits:** every rule in this file applies to agents too. That includes environment, not sandbox; battle-tested first; no user-global state; no pushing; tests with `-vv -rA` and triple-checked.
5. **What to bring back:**
   - commands with their full output;
   - sources with a URL or `file:line`;
   - each claim marked as *measured* or *read*;
   - what was tried and failed;
   - open questions.

   A summary on its own isn't evidence.
6. **When to stop:** what counts as done, and when to come back and report instead of guessing.

**Checking the result.** An agent's report is a claim until the lead has checked it:
- Re-run its key commands.
- Read every line of any diff.
- Triple-check its tests.
- Look for shortcuts: skipped or weakened tests, checks that can't fail, conclusions with no output behind them, TODOs left where work should be.

When agents or sources disagree, measure; don't vote. The unix datagram decision is an example: most of the research said "document the gap", and one measurement showed its main premise was false.
