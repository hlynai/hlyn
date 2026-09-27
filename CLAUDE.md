## Product rules
- **Names are plain English, one word where possible.** Commands, flags, fields, functions: a developer should guess what it does from the name alone.
- **Usable without reading docs.** One line (`hlyn.on()` / `hlyn run -- cmd`) must give a safe, working minimum. Defaults stay strict and sensible; every extra need is one more simple, obvious argument. Easy by default, fully configurable when wanted.
- **Every message tells the user what to do next.** Errors and refusals name the flag or field that would change the outcome.
- **Human output by default, `--json` for machines**, on every command that prints data.
- **Prefer battle-tested over custom.** Before building anything non-trivial, and always for anything security-critical, look for a proven, maintained solution: a kernel facility, a standard, a widely deployed library or tool. Use it, or follow its pattern. Write custom code only for the gap it leaves, and record in the design doc or commit why the proven option didn't fit.

## Findings (engineering memory)
[FINDINGS.md](file://<repo>/FINDINGS.md) records what has been *verified* about how this codebase behaves: root causes, dead ends, and how to measure each fix.
- Before touching an area it covers, read that section. Listed dead ends are not to be retried unless the premise has changed.
- After any debugging that took more than one attempt, append an entry *before* committing: symptom → root cause → what didn't work and why → what worked → how to verify. Mark anything not measured as *(unverified)*.
- A fix is not done until its "verify" step has been run. Never claim "fixed" from reading code alone.
- Keep it factual and terse. Retire stale entries with a strike-through and a note; don't silently delete.
