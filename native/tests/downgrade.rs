// SPDX-License-Identifier: Apache-2.0
//! Proof that partial enforcement is real, and that we do not produce it.
//!
//! On a kernel older than the rules being applied, `BestEffort` applies what
//! that kernel understands and drops the rest. The process is left confined
//! less than the caller asked for, and nothing about it looks wrong: every
//! syscall afterwards behaves normally. `restrict_self` reporting
//! `PartiallyEnforced` is the only signal there is, and the whole refusal path
//! in `seal` and in `landlock.load` is built on it.
//!
//! So it is worth knowing two things, on whatever kernel this is running on:
//! that the signal fires when the kernel really does drop rights, and that our
//! own ruleset does not trip it. The second is why `WANT` is `V6` and not the
//! newest ABI the crate knows -- naming a newer one would report partial
//! enforcement on every current kernel and turn the honesty check into noise.
//!
//! What this does not do is run on an old kernel. It forces the downgrade by
//! asking for rights no current kernel has, which exercises the same code the
//! same way, but a machine actually running Linux 5.13 would also be exercising
//! its own Landlock implementation and ours against it. That remains untested,
//! and needs a virtual machine rather than a container -- containers share the
//! host kernel, so no base image can supply an older one.
//!
//! Its own test binary because it is one-way: applying a ruleset confines this
//! process, so nothing may run after it. Cargo gives each file in tests/ a
//! process of its own, which is exactly that guarantee.

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus, ABI,
};

/// The ABI the shim is written against. Kept in step with `WANT` in lib.rs.
const OURS: ABI = ABI::V6;

/// Newer than any kernel this is expected to meet, so the crate asks for
/// rights that get dropped.
const NEWER: ABI = ABI::V9;

fn supports(abi: ABI) -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.create())
        .is_ok()
}

fn apply(abi: ABI) -> RulesetStatus {
    Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .expect("handling filesystem access")
        .create()
        .expect("creating the ruleset")
        .restrict_self()
        .expect("applying the ruleset")
        .ruleset
}

#[test]
fn partial_enforcement_is_reachable_but_not_by_us() {
    assert!(hlyn::hlyn_abi() > 0, "no Landlock on this kernel");
    assert!(supports(OURS), "this kernel is older than the ABI the shim targets");

    // Ours first: this is the one that must come back clean. Applying it
    // confines this process to nothing, which is fine -- neither step below
    // opens a path.
    assert_eq!(
        apply(OURS),
        RulesetStatus::FullyEnforced,
        "our own ruleset does not fully apply on this kernel, so every seal \
         would be refused as under-enforced"
    );

    if supports(NEWER) {
        // A kernel newer than the crate's newest known ABI. Nothing is dropped,
        // so there is no downgrade to observe and nothing to assert.
        return;
    }

    // Rights this kernel does not have, applied best-effort. The kernel takes
    // what it knows and says so.
    assert_eq!(
        apply(NEWER),
        RulesetStatus::PartiallyEnforced,
        "the kernel dropped rights without reporting it, which would leave \
         under-enforcement undetectable"
    );
}
