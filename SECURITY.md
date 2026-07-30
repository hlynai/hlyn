# Security

hlyn is a containment layer. A defect in it is not a crash — it is a boundary
that is quietly wider than the person who configured it believes. Please treat
findings accordingly.

## Reporting a vulnerability

Email **security@hlyn.dev** with:

- what the boundary was configured to be,
- what you were able to do anyway,
- the kernel version and `hlyn probe` output from the machine.

Please do not open a public issue for a working escape.

We will acknowledge within 3 working days and aim to have a fix or a clear
explanation within 30 days. Credit is given to reporters who want it.

## What counts as a vulnerability

Anything that lets a confined process reach past its policy:

- reading, writing, or executing a path the policy did not grant,
- reaching a TCP port the policy did not name,
- reaching another agent's process, memory, signals, or descriptors when the
  policy did not allow it,
- removing, weakening, or escaping the confinement after it has been applied,
- `seal` returning success when the kernel applied less than the whole policy.

That last one matters as much as the rest. Reporting a boundary that is not
there is the single worst outcome this project can produce, so a silent
downgrade is a vulnerability even if nothing escaped.

## What does not

These are documented limits, not defects. They are in the README, in the API
docstrings, and in the error messages:

- **Host names are not enforced.** `net=["example.com"]` is refused rather than
  accepted. Landlock filters ports; seccomp cannot read the `sockaddr`.
- **Named ports restrict TCP only.** `net=[443]` leaves UDP reachable. Use
  `net=False` to close the network entirely.
- **macOS has no isolation between agents.** Seatbelt has no equivalent of
  Landlock's scoping. `hlyn probe` reports this.
- **A kernel below Landlock ABI 6 cannot be used.** hlyn refuses to seal rather
  than enforcing part of the policy.
- **A policy that grants something dangerous is doing as it was told.**
  Granting write and exec on the same directory lets the agent write a program
  and run it; that is the policy's meaning, not an escape.

If you think one of these limits is worse than we have described, that is worth
an email too.

## Scope

The library, the CLI, the native shim, and the framework adapters in this
repository. The kernel facilities underneath — Landlock, seccomp, Seatbelt —
belong to their own projects; report kernel bugs upstream, though we would like
to know so we can work around them.
