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
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use std::ffi::{c_char, CStr};

/// What a caller asks for. Arrays are borrowed for the duration of the call.
///
/// The fields are public because this is a C ABI type: the layout is already
/// the contract, and the caller on the other side writes it directly.
#[repr(C)]
pub struct Plan {
    pub reads: *const *const c_char,
    pub nreads: usize,
    pub writes: *const *const c_char,
    pub nwrites: usize,
    pub execs: *const *const c_char,
    pub nexecs: usize,
    pub binds: *const u16,
    pub nbinds: usize,
    pub connects: *const u16,
    pub nconnects: usize,
    pub flags: u32,
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

/// The pointer marshalling, reachable by name for fuzzing.
///
/// Same functions the real path uses, not copies of them. Compiled only under
/// the `fuzz` feature.
#[cfg(feature = "fuzz")]
pub mod marshal {
    use super::{list, numbers};
    use std::ffi::c_char;

    /// # Safety
    /// `items` must be null or point to `count` valid C string pointers.
    pub unsafe fn strings(items: *const *const c_char, count: usize) -> Option<Vec<&'static str>> {
        list(items, count)
    }

    /// # Safety
    /// `items` must be null or point to `count` valid `u16`s.
    pub unsafe fn ports(items: *const u16, count: usize) -> Option<Vec<u16>> {
        numbers(items, count)
    }
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

/// Everything `seal` does except the one step that cannot be undone.
///
/// Split out so the irreversible call sits by itself and the rest -- reading
/// caller-supplied pointers, opening paths, assembling rules -- can be driven
/// by tests and by the fuzzer without confining the process doing the driving.
/// Keeping it as one function rather than a copy means what gets fuzzed is
/// what actually runs.
///
/// # Safety
/// Every pointer in `plan` must be valid for its stated length.
unsafe fn build(plan: &Plan) -> Result<RulesetCreated, i32> {
    let (reads, writes, execs) = match (
        list(plan.reads, plan.nreads),
        list(plan.writes, plan.nwrites),
        list(plan.execs, plan.nexecs),
    ) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err(EARGS),
    };
    let (binds, connects) = match (
        numbers(plan.binds, plan.nbinds),
        numbers(plan.connects, plan.nconnects),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(EARGS),
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
        Err(_) => return Err(EBUILD),
    };

    if plan.flags & NET != 0 {
        ruleset = match ruleset.handle_access(AccessNet::from_all(abi)) {
            Ok(value) => value,
            Err(_) => return Err(EBUILD),
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
            Err(_) => return Err(EBUILD),
        };
    }

    let mut made = match ruleset.create() {
        Ok(value) => value,
        Err(_) => return Err(EBUILD),
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
                Err(_) => return Err(ERULE),
            };
            made = match made.add_rule(PathBeneath::new(fd, pick(dir))) {
                Ok(value) => value,
                Err(_) => return Err(ERULE),
            };
        }
    }

    if plan.flags & NET != 0 {
        for port in binds {
            made = match made.add_rule(NetPort::new(port, AccessNet::BindTcp)) {
                Ok(value) => value,
                Err(_) => return Err(ERULE),
            };
        }
        for port in connects {
            made = match made.add_rule(NetPort::new(port, AccessNet::ConnectTcp)) {
                Ok(value) => value,
                Err(_) => return Err(ERULE),
            };
        }
    }

    Ok(made)
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
    let made = match build(&*plan) {
        Ok(value) => value,
        Err(code) => return code,
    };
    match made.restrict_self() {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => FULL,
            RulesetStatus::PartiallyEnforced => SOME,
            RulesetStatus::NotEnforced => NOT,
        },
        Err(_) => ESEAL,
    }
}

/// Assemble a ruleset from `plan` and throw it away without applying it.
///
/// The fuzz target for everything `seal` does before the point of no return.
/// Compiled only under the `fuzz` feature, so it is absent from the shipped
/// library; a build that could assemble a ruleset and not apply it is a build
/// with an off switch, which is the one thing this must not have.
///
/// # Safety
/// Every pointer in `plan` must be valid for its stated length.
#[cfg(feature = "fuzz")]
pub unsafe fn hlyn_build_only(plan: *const Plan) -> i32 {
    if plan.is_null() {
        return EARGS;
    }
    match build(&*plan) {
        Ok(_) => FULL,
        Err(code) => code,
    }
}

/// What can and cannot be tested here.
///
/// `hlyn_seal` is irreversible: a single successful call confines the test
/// binary itself, and every test after it would run inside that confinement.
/// So nothing below ever reaches `restrict_self`. What is covered is the part
/// that can be got wrong silently -- the pointer marshalling, which decides
/// whether a malformed request is refused or read out of bounds, and the
/// rights pickers, which decide what a granted path may actually do. The
/// enforcement path itself is proved from the Python suite, against a real
/// kernel, where a wrong answer shows up as a process that lived when it
/// should have died.
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Keeps the `CString`s alive for as long as the pointers are used.
    fn strings(items: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
        let owned: Vec<CString> = items.iter().map(|s| CString::new(*s).unwrap()).collect();
        let pointers = owned.iter().map(|s| s.as_ptr()).collect();
        (owned, pointers)
    }

    #[test]
    fn an_empty_list_needs_no_pointer() {
        // The count is checked before the pointer, so a caller passing no
        // paths may pass null. Python's ctypes does exactly this for an empty
        // array, and treating it as an error would refuse every empty policy.
        assert_eq!(unsafe { list(std::ptr::null(), 0) }, Some(Vec::new()));
    }

    #[test]
    fn a_null_array_with_a_nonzero_count_is_refused() {
        // The dangerous shape: a length that promises entries behind a pointer
        // that has none. Reading it would be out of bounds.
        assert_eq!(unsafe { list(std::ptr::null(), 1) }, None);
    }

    #[test]
    fn paths_are_borrowed_in_order() {
        let (_keep, pointers) = strings(&["/etc", "/srv/data", "/"]);
        let got = unsafe { list(pointers.as_ptr(), pointers.len()) };
        assert_eq!(got, Some(vec!["/etc", "/srv/data", "/"]));
    }

    #[test]
    fn a_null_entry_inside_the_array_is_refused() {
        let (_keep, mut pointers) = strings(&["/etc", "/srv"]);
        pointers[1] = std::ptr::null();
        assert_eq!(unsafe { list(pointers.as_ptr(), pointers.len()) }, None);
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        // Linux paths are bytes, so this is reachable from a caller that hands
        // us a raw filename. Refusing is the only honest answer: we cannot
        // grant a path we cannot represent, and silently skipping it would
        // hand back a ruleset narrower than the one the caller asked for
        // while reporting full enforcement.
        let bad = CString::new(vec![0x2fu8, 0xff, 0xfe]).unwrap();
        let pointers = [bad.as_ptr()];
        assert_eq!(unsafe { list(pointers.as_ptr(), pointers.len()) }, None);
    }

    #[test]
    fn a_count_shorter_than_the_array_borrows_only_that_many() {
        let (_keep, pointers) = strings(&["/a", "/b", "/c"]);
        assert_eq!(unsafe { list(pointers.as_ptr(), 2) }, Some(vec!["/a", "/b"]));
    }

    #[test]
    fn ports_follow_the_same_rules_as_paths() {
        assert_eq!(unsafe { numbers(std::ptr::null(), 0) }, Some(Vec::new()));
        assert_eq!(unsafe { numbers(std::ptr::null(), 1) }, None);

        let ports = [80u16, 443, 0, 65535];
        let got = unsafe { numbers(ports.as_ptr(), ports.len()) };
        assert_eq!(got, Some(vec![80, 443, 0, 65535]));
    }

    #[test]
    fn a_shorter_port_count_borrows_only_that_many() {
        let ports = [80u16, 443, 8080];
        assert_eq!(unsafe { numbers(ports.as_ptr(), 1) }, Some(vec![80]));
    }

    #[test]
    fn reading_a_file_does_not_require_directory_rights() {
        // ReadDir on a regular file is a right the kernel drops, which would
        // downgrade the whole ruleset to PartiallyEnforced and make our
        // honesty check fire on a correct policy.
        let file = readable(false);
        assert!(file.contains(AccessFs::ReadFile));
        assert!(!file.contains(AccessFs::ReadDir));

        let dir = readable(true);
        assert!(dir.contains(AccessFs::ReadFile));
        assert!(dir.contains(AccessFs::ReadDir));
    }

    #[test]
    fn reading_never_grants_writing() {
        for dir in [true, false] {
            let got = readable(dir);
            assert!(!got.contains(AccessFs::WriteFile));
            assert!(!got.contains(AccessFs::Truncate));
            assert!(!got.contains(AccessFs::MakeReg));
            assert!(!got.contains(AccessFs::RemoveFile));
            assert!(!got.contains(AccessFs::Execute));
        }
    }

    #[test]
    fn writing_a_file_grants_neither_creation_nor_removal() {
        let file = writable(false);
        assert!(file.contains(AccessFs::WriteFile));
        assert!(file.contains(AccessFs::ReadFile));
        assert!(file.contains(AccessFs::Truncate));
        for right in [
            AccessFs::MakeReg,
            AccessFs::MakeDir,
            AccessFs::RemoveFile,
            AccessFs::RemoveDir,
            AccessFs::Refer,
            AccessFs::ReadDir,
        ] {
            assert!(!file.contains(right), "{right:?} is meaningless on a file");
        }
    }

    #[test]
    fn writing_a_directory_grants_what_an_atomic_write_needs() {
        // Every editor, compiler, and package manager writes by renaming a
        // temporary file into place. Without Refer that rename is refused and
        // the sandbox looks broken rather than strict.
        let dir = writable(true);
        for right in [
            AccessFs::WriteFile,
            AccessFs::ReadFile,
            AccessFs::Truncate,
            AccessFs::ReadDir,
            AccessFs::MakeReg,
            AccessFs::MakeDir,
            AccessFs::RemoveFile,
            AccessFs::RemoveDir,
            AccessFs::MakeSym,
            AccessFs::MakeSock,
            AccessFs::MakeFifo,
            AccessFs::Refer,
        ] {
            assert!(dir.contains(right), "a writable directory needs {right:?}");
        }
    }

    #[test]
    fn writing_never_grants_a_device_node_or_execution() {
        // Minting a device is how a confined process reaches raw disk. Nothing
        // an agent legitimately does needs it, and no policy field asks for it,
        // so it must not arrive as a side effect of being granted write.
        for dir in [true, false] {
            let got = writable(dir);
            assert!(!got.contains(AccessFs::MakeChar));
            assert!(!got.contains(AccessFs::MakeBlock));
            assert!(!got.contains(AccessFs::Execute));
        }
    }

    #[test]
    fn execution_does_not_vary_with_the_kind_of_path() {
        // Both rights apply to a file and to the files beneath a directory,
        // so an exec grant is the same shape either way.
        assert_eq!(runnable(true), runnable(false));
        let got = runnable(false);
        assert!(got.contains(AccessFs::Execute));
        // A program must be readable to be run.
        assert!(got.contains(AccessFs::ReadFile));
        assert!(!got.contains(AccessFs::WriteFile));
    }

    #[test]
    fn the_three_pickers_are_distinct() {
        // A copy-paste that made two of these agree would hand out rights
        // nobody asked for, and no other test would notice.
        assert_ne!(readable(true), writable(true));
        assert_ne!(readable(true), runnable(true));
        assert_ne!(writable(true), runnable(true));
    }

    #[test]
    fn every_granted_right_is_one_the_target_abi_knows() {
        // A right outside the handled set is dropped by the kernel and drags
        // the ruleset down to PartiallyEnforced.
        let handled = AccessFs::from_all(WANT);
        for dir in [true, false] {
            assert!(handled.contains(readable(dir)));
            assert!(handled.contains(writable(dir)));
            assert!(handled.contains(runnable(dir)));
        }
    }

    #[test]
    fn every_flag_is_a_distinct_single_bit() {
        // A flag that came out as zero would not fail loudly. `flags & FLAG
        // != 0` would simply never fire, so the thing it gates -- signal
        // scoping, abstract-socket scoping, or the entire network layer --
        // would be quietly absent from every ruleset while `seal` went on
        // reporting full enforcement. Checking only that the bits do not
        // overlap does not catch that: zero overlaps with nothing.
        for (name, bit) in [("SIGNAL", SIGNAL), ("UNIX", UNIX), ("NET", NET)] {
            assert_ne!(bit, 0, "{name} is zero, so it would gate nothing");
            assert_eq!(bit.count_ones(), 1, "{name} must be exactly one bit");
        }
        assert_eq!(SIGNAL & UNIX, 0);
        assert_eq!(SIGNAL & NET, 0);
        assert_eq!(UNIX & NET, 0);
    }

    #[test]
    fn the_return_codes_are_all_different() {
        let codes = [NOT, SOME, FULL, EARGS, EBUILD, ERULE, ESEAL];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // The caller distinguishes "enforced less than asked" from "failed" by
        // sign, so the levels must not be negative and the errors must be.
        for level in [NOT, SOME, FULL] {
            assert!(level >= 0);
        }
        for error in [EARGS, EBUILD, ERULE, ESEAL] {
            assert!(error < 0);
        }
    }

    #[test]
    fn a_null_plan_is_refused_rather_than_dereferenced() {
        assert_eq!(unsafe { hlyn_seal(std::ptr::null()) }, EARGS);
    }

    #[test]
    fn a_malformed_plan_is_refused_before_anything_is_applied() {
        // Every one of these is rejected during marshalling, so no ruleset is
        // ever created and this test process is left unconfined. That is the
        // only reason `hlyn_seal` can be called here at all.
        let empty = || Plan {
            reads: std::ptr::null(),
            nreads: 0,
            writes: std::ptr::null(),
            nwrites: 0,
            execs: std::ptr::null(),
            nexecs: 0,
            binds: std::ptr::null(),
            nbinds: 0,
            connects: std::ptr::null(),
            nconnects: 0,
            flags: 0,
        };

        let mut plan = empty();
        plan.nreads = 1;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);

        let mut plan = empty();
        plan.nwrites = 2;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);

        let mut plan = empty();
        plan.nexecs = 1;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);

        let mut plan = empty();
        plan.nbinds = 1;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);

        let mut plan = empty();
        plan.nconnects = 1;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);

        // Flags do not rescue a malformed plan.
        let mut plan = empty();
        plan.nreads = 1;
        plan.flags = SIGNAL | UNIX | NET;
        assert_eq!(unsafe { hlyn_seal(&plan) }, EARGS);
    }

    #[test]
    fn the_abi_query_agrees_with_whether_landlock_actually_works() {
        // The contract is: zero when the kernel has no Landlock, the version
        // it speaks otherwise. Never a raw errno, which a caller comparing
        // `abi >= 4` would read as a very capable kernel.
        //
        // The independent check is whether a ruleset can be built at all.
        // `create` performs landlock_create_ruleset; only `restrict_self`
        // confines anything, so this is safe to run in the test process.
        // HardRequirement means a kernel without Landlock refuses rather than
        // quietly handing back an empty ruleset.
        let usable = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok();

        let abi = hlyn_abi();
        assert!(abi >= 0, "an errno leaked out as a version: {abi}");
        assert_eq!(
            abi > 0,
            usable,
            "reported ABI {abi} but Landlock is {}usable",
            if usable { "" } else { "un" }
        );
    }
}
