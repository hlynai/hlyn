//! A thin C ABI over the upstream Landlock crate.
//!
//! Deliberately dumb. Every decision that could be got wrong -- which ABI the
//! running kernel speaks, how wide each struct is, which access bits are legal
//! at that ABI -- is answered by the crate, which is maintained by Landlock's
//! kernel author. This file only marshals arguments and reports honestly what
//! the kernel agreed to enforce.
//!
//! The one rule that matters here: never report success for a restriction the
//! kernel did not apply. `seal` returns the enforcement level so the caller can
//! refuse to continue.

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use std::ffi::{c_char, CStr};

/// What a caller asks for. Arrays are borrowed for the duration of the call.
#[repr(C)]
pub struct Plan {
    reads: *const *const c_char,
    nreads: usize,
    writes: *const *const c_char,
    nwrites: usize,
    execs: *const *const c_char,
    nexecs: usize,
    binds: *const u16,
    nbinds: usize,
    connects: *const u16,
    nconnects: usize,
    flags: u32,
}

// flags
const SIGNAL: u32 = 1 << 0; // confine signals to this agent
const UNIX: u32 = 1 << 1; // confine abstract unix sockets to this agent
const NET: u32 = 1 << 2; // enforce ports; without it Landlock ignores the network

// return codes
const NOT: i32 = 0; // nothing was enforced
const SOME: i32 = 1; // enforced, but the kernel dropped part of the request
const FULL: i32 = 2; // enforced exactly as asked
const EARGS: i32 = -1;
const EBUILD: i32 = -2;
const ERULE: i32 = -3;
const ESEAL: i32 = -4;

/// Which rights to grant, chosen by what the path actually is.
///
/// Directory-only rights are meaningless on a regular file, and asking for
/// them anyway makes the kernel drop them and the ruleset report itself only
/// partially enforced. Since a correct policy always names some plain files --
/// `/dev/null` and the loader cache, at minimum -- getting this wrong would
/// downgrade every single ruleset we ever build.
type Pick = fn(bool) -> BitFlags<AccessFs>;

fn readable(dir: bool) -> BitFlags<AccessFs> {
    if dir {
        AccessFs::ReadFile | AccessFs::ReadDir
    } else {
        AccessFs::ReadFile.into()
    }
}

/// `Refer` is included for directories because atomic writes rename a
/// temporary file into place, which crosses directories and is refused
/// without it. Device and block node creation are deliberately absent:
/// nothing an agent legitimately does requires minting a device.
fn writable(dir: bool) -> BitFlags<AccessFs> {
    let file = AccessFs::WriteFile | AccessFs::ReadFile | AccessFs::Truncate;
    if !dir {
        return file;
    }
    file | AccessFs::ReadDir
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeSym
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::Refer
}

/// A program must be readable to run. Both rights apply to files and to the
/// files beneath a directory, so this does not vary.
fn runnable(_dir: bool) -> BitFlags<AccessFs> {
    AccessFs::Execute | AccessFs::ReadFile
}

/// Borrow a C string array as paths.
unsafe fn list(items: *const *const c_char, count: usize) -> Option<Vec<&'static str>> {
    if count == 0 {
        return Some(Vec::new());
    }
    if items.is_null() {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let item = *items.add(i);
        if item.is_null() {
            return None;
        }
        match CStr::from_ptr(item).to_str() {
            Ok(text) => out.push(text),
            Err(_) => return None,
        }
    }
    Some(out)
}

unsafe fn numbers(items: *const u16, count: usize) -> Option<Vec<u16>> {
    if count == 0 {
        return Some(Vec::new());
    }
    if items.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(items, count).to_vec())
}

/// The ABI this shim is written against.
///
/// The crate's guidance is to name the version whose features you actually use
/// and let `BestEffort` handle older kernels. V6 is exactly our ceiling: V4
/// brought network ports and V6 brought scoping, which is what confines signals
/// and abstract sockets between agents. Naming a newer ABI would request rights
/// we never use and report `PartiallyEnforced` on a current kernel, turning our
/// own honesty check into noise.
const WANT: ABI = ABI::V6;

/// The Landlock ABI the running kernel speaks. Zero means no Landlock.
///
/// A read-only version query, used only for reporting what a machine can do.
/// No enforcement decision depends on it: what is actually enforced comes back
/// from `restrict_self` in `seal` below.
#[no_mangle]
pub extern "C" fn hlyn_abi() -> i32 {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
    // Syscall 444 on every architecture: Landlock was added to the generic
    // syscall table, so the number does not vary the way seccomp's does.
    let out = unsafe { libc::syscall(444, 0, 0, 1) };
    if out < 0 {
        0
    } else {
        out as i32
    }
}

/// Apply `plan` to the calling process. One-way, and irreversible.
///
/// Returns FULL, SOME, or NOT for enforcement level, or a negative code. The
/// caller is expected to treat anything below FULL as a failure unless it has
/// explicitly opted into weaker enforcement.
///
/// # Safety
/// Every pointer in `plan` must be valid for its stated length.
#[no_mangle]
pub unsafe extern "C" fn hlyn_seal(plan: *const Plan) -> i32 {
    if plan.is_null() {
        return EARGS;
    }
    let plan = &*plan;

    let (reads, writes, execs) = match (
        list(plan.reads, plan.nreads),
        list(plan.writes, plan.nwrites),
        list(plan.execs, plan.nexecs),
    ) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return EARGS,
    };
    let (binds, connects) = match (
        numbers(plan.binds, plan.nbinds),
        numbers(plan.connects, plan.nconnects),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => return EARGS,
    };

    let abi = WANT;

    // Handle every right the running kernel understands. Anything handled and
    // not granted is denied, so this is what makes the ruleset deny-by-default
    // rather than an advisory list.
    let mut ruleset = match Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
    {
        Ok(value) => value,
        Err(_) => return EBUILD,
    };

    if plan.flags & NET != 0 {
        ruleset = match ruleset.handle_access(AccessNet::from_all(abi)) {
            Ok(value) => value,
            Err(_) => return EBUILD,
        };
    }

    let mut scope: BitFlags<Scope> = BitFlags::EMPTY;
    if plan.flags & SIGNAL != 0 {
        scope |= Scope::Signal;
    }
    if plan.flags & UNIX != 0 {
        scope |= Scope::AbstractUnixSocket;
    }
    if !scope.is_empty() {
        ruleset = match ruleset.scope(scope) {
            Ok(value) => value,
            Err(_) => return EBUILD,
        };
    }

    let mut made = match ruleset.create() {
        Ok(value) => value,
        Err(_) => return EBUILD,
    };

    for (paths, pick) in [
        (&reads, readable as Pick),
        (&writes, writable as Pick),
        (&execs, runnable as Pick),
    ] {
        for path in paths.iter() {
            let dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
            // O_PATH open; a path that cannot be opened cannot be granted.
            let fd = match PathFd::new(path) {
                Ok(value) => value,
                Err(_) => return ERULE,
            };
            made = match made.add_rule(PathBeneath::new(fd, pick(dir))) {
                Ok(value) => value,
                Err(_) => return ERULE,
            };
        }
    }

    if plan.flags & NET != 0 {
        for port in binds {
            made = match made.add_rule(NetPort::new(port, AccessNet::BindTcp)) {
                Ok(value) => value,
                Err(_) => return ERULE,
            };
        }
        for port in connects {
            made = match made.add_rule(NetPort::new(port, AccessNet::ConnectTcp)) {
                Ok(value) => value,
                Err(_) => return ERULE,
            };
        }
    }

    match made.restrict_self() {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => FULL,
            RulesetStatus::PartiallyEnforced => SOME,
            RulesetStatus::NotEnforced => NOT,
        },
        Err(_) => ESEAL,
    }
}
