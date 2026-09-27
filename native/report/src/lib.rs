// SPDX-License-Identifier: Apache-2.0
//! Tells `hlyn run` which calls the boundary refused.
//!
//! When Landlock or seccomp refuses a call, the program gets `EACCES` or
//! `EPERM` straight from the kernel and nothing else hears about it. If the
//! program swallows the error, falls back, or retries, the person running it
//! sees an agent behaving oddly and no reason why. Landlock's own records need
//! kernel audit, which needs root; a seccomp supervisor would sit on every
//! `open`. So instead this library is preloaded into every program the agent
//! starts, wraps the C library calls the boundary can refuse, and -- only when
//! one fails with `EACCES` or `EPERM` -- writes one line describing it to a
//! pipe that `hlyn run` owns.
//!
//! Rules this file keeps, because it runs inside programs nobody here wrote:
//!
//! - **Never change what the program sees.** Every wrapper calls the real
//!   function and returns its result and `errno` untouched. Reporting happens
//!   after, and only on failure, so a working call costs one comparison.
//! - **Never allocate, lock, or call back into the C library** while
//!   reporting. Everything goes through raw syscalls on stack buffers, which is
//!   what keeps it safe in a signal handler, in a `vfork` child, and in a
//!   thread that was interrupted holding the allocator's lock.
//! - **Never block.** The pipe is opened non-blocking; a full pipe or a gone
//!   reader loses the record rather than stalling the program.
//! - **Never panic.** A panic here aborts someone else's program. Every buffer
//!   access below is bounded by construction, not by a check that could fail.
//!
//! What it cannot do, stated so nobody relies on it: statically linked
//! programs (most Go binaries) never load it, a program that clears its own
//! environment stops passing it to children, and what it reports comes from
//! inside the confined program -- which can therefore write anything to the
//! pipe. `hlyn run` treats every line as untrusted input and checks each one
//! against the policy before believing it.

#![cfg_attr(not(test), no_std)]

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!(
    "the reporter is for Linux on x86_64 and aarch64: its `open` wrapper reads the \
     optional mode argument the way those two calling conventions pass it"
);

// The wrappers, and what they need, are left out of the test build: a test
// binary that exported `open` would route its own harness through them.
#[cfg(not(test))]
mod hooks;
mod line;
#[cfg(not(test))]
mod real;
mod seen;
#[cfg(not(test))]
mod send;

/// Runs when the library is loaded, before the program's `main`.
///
/// Resolving every real function here rather than on first use keeps the
/// dynamic loader's lock out of the wrappers: a first call made in a forked
/// child, whose parent had another thread inside the loader at the moment of
/// the fork, would otherwise wait on a lock nobody will ever release.
#[cfg(not(test))]
extern "C" fn init() {
    send::load();
    real::load();
}

#[cfg(not(test))]
#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = init;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Unreachable by design (see the rules above). If it is ever reached,
    // stopping is safer than continuing inside a program in an unknown state.
    unsafe { libc::abort() }
}
