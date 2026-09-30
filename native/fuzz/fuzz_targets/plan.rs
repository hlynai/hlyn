// SPDX-License-Identifier: Apache-2.0
//! Fuzz everything `seal` does before the point of no return.
//!
//! Reads the caller's arrays, opens every path, assembles the ruleset, and
//! stops. The last step is left out because it cannot be taken twice: one
//! successful `restrict_self` would confine the fuzzer, and every input after
//! it would be measuring the environment instead of the code.
//!
//! Arbitrary bytes almost never name a path that exists, so paths are drawn
//! from a table of real ones as well. Without that the fuzzer spends its whole
//! budget failing at the first `open` and never reaches the rule building.

#![no_main]

use arbitrary::Arbitrary;
use hlyn::{hlyn_build_only, Plan};
use libfuzzer_sys::fuzz_target;
use std::ffi::c_char;

/// Paths that exist on any Linux box, chosen to hit the cases the rights
/// pickers branch on: directories, plain files, symlinks, device nodes, and
/// the ones a policy is most likely to name.
const REAL: &[&str] = &[
    "/",
    "/tmp",
    "/etc",
    "/etc/hosts",
    "/dev/null",
    "/dev/urandom",
    "/usr",
    "/usr/bin",
    "/usr/bin/env",
    "/proc/self",
    "/proc/self/environ",
    "/nonexistent",
];

#[derive(Arbitrary, Debug)]
enum Item {
    /// A path that is probably real, so the fuzzer can get past `open`.
    Known(u8),
    /// Whatever the fuzzer wants, including bytes that are not text.
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    reads: Vec<Item>,
    writes: Vec<Item>,
    execs: Vec<Item>,
    binds: Vec<u16>,
    connects: Vec<u16>,
    flags: u32,
    /// Claim an array is there when it is not.
    drop_reads: bool,
}

/// NUL-terminated bytes for one item, kept alive by the caller.
fn bytes(item: &Item) -> Vec<u8> {
    let mut out: Vec<u8> = match item {
        Item::Known(n) => REAL[*n as usize % REAL.len()].as_bytes().to_vec(),
        Item::Raw(raw) => raw.iter().copied().filter(|&b| b != 0).collect(),
    };
    out.push(0);
    out
}

fn array(items: &[Item]) -> (Vec<Vec<u8>>, Vec<*const c_char>) {
    let owned: Vec<Vec<u8>> = items.iter().map(bytes).collect();
    let pointers = owned.iter().map(|b| b.as_ptr() as *const c_char).collect();
    (owned, pointers)
}

fuzz_target!(|input: Input| {
    let (_r, reads) = array(&input.reads);
    let (_w, writes) = array(&input.writes);
    let (_e, execs) = array(&input.execs);

    let plan = Plan {
        reads: if input.drop_reads {
            std::ptr::null()
        } else {
            reads.as_ptr()
        },
        nreads: reads.len(),
        writes: writes.as_ptr(),
        nwrites: writes.len(),
        execs: execs.as_ptr(),
        nexecs: execs.len(),
        binds: input.binds.as_ptr(),
        nbinds: input.binds.len(),
        connects: input.connects.as_ptr(),
        nconnects: input.connects.len(),
        flags: input.flags,
    };

    // The only contract: it answers, in range, without reading memory it was
    // not given. Which answer is right for a given plan is what the unit tests
    // and the kernel tests are for.
    let got = unsafe { hlyn_build_only(&plan) };
    assert!((-4..=2).contains(&got), "answer outside the documented range: {got}");

    // A null array that was promised entries is refused, never read.
    if input.drop_reads && !input.reads.is_empty() {
        assert_eq!(got, -1, "a null array with entries promised must be refused");
    }
});
