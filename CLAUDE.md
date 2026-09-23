## Findings (engineering memory)
[FINDINGS.md](file://<repo>/FINDINGS.md) records what has been *verified* about how this codebase behaves: root causes, dead ends, and how to measure each fix.
- Before touching an area it covers, read that section. Listed dead ends are not to be retried unless the premise has changed.
- After any debugging that took more than one attempt, append an entry *before* committing: symptom → root cause → what didn't work and why → what worked → how to verify. Mark anything not measured as *(unverified)*.
- A fix is not done until its "verify" step has been run. Never claim "fixed" from reading code alone.
- Keep it factual and terse. Retire stale entries with a strike-through and a note; don't silently delete.
