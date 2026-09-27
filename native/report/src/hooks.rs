// SPDX-License-Identifier: Apache-2.0
//! The wrapped calls.
//!
//! Each wrapper forwards to the C library's own function, returns exactly what
//! it returned, and only if that was a failure with `EACCES` or `EPERM` sends
//! one record describing it. The set is every C library entry point through
//! which a program opens, creates, removes or runs a path, or reaches the
//! network -- including the ones glibc routes around its own public symbols
//! (`fopen` and `opendir` call an internal `open`, `posix_spawn` an internal
//! `execve`), which is why they are wrapped separately.
//!
//! `stat`, `access`, `chmod` and friends are absent on purpose: Landlock does
//! not govern them, so they never fail because of the boundary.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::transmute;

use libc::{
    mode_t, msghdr, off64_t, off_t, pid_t, posix_spawn_file_actions_t, posix_spawnattr_t, size_t, sockaddr,
    socklen_t, ssize_t,
    AT_FDCWD, DIR, EACCES, ENOSYS, EPERM, FILE,
};

use crate::line::Line;
use crate::real::*;
use crate::{seen, send};

// What kind of access was refused. The names are the policy fields that would
// allow it, so the reader never has to translate.
const READ: &[u8] = b"read";
const WRITE: &[u8] = b"write";
const EXEC: &[u8] = b"exec";
const NET: &[u8] = b"net";
const LISTEN: &[u8] = b"bind";

/// What the refused call was aimed at.
#[derive(Clone, Copy)]
enum Target {
    /// A path, relative to a directory descriptor as the `*at` calls take it.
    Path(c_int, *const c_char),
    /// A program named for a `PATH` search. Sent as given; the reader resolves
    /// it, because only the last directory tried is visible here.
    Program(*const c_char),
    /// A socket address.
    Addr(*const sockaddr, socklen_t),
    /// A socket that could not be created at all, so no address exists yet.
    Family(c_int),
}

unsafe fn errno() -> c_int {
    *libc::__errno_location()
}

unsafe fn set_errno(value: c_int) {
    *libc::__errno_location() = value;
}

/// Reports the failure that just happened, if it was a refusal, then puts
/// `errno` back exactly as the program is about to read it.
unsafe fn refused(kind: &[u8], op: &[u8], target: Target) {
    let err = errno();
    if err == EACCES || err == EPERM {
        tell(err, kind, op, target);
    }
    set_errno(err);
}

/// For the calls that return an error number instead of setting `errno`.
unsafe fn refused_with(err: c_int, kind: &[u8], op: &[u8], target: Target) {
    if err == EACCES || err == EPERM {
        let saved = errno();
        tell(err, kind, op, target);
        set_errno(saved);
    }
}

/// Under `hlyn watch` (`send::all`), reports a call that was allowed, so the
/// draft policy can name what the program actually used. Otherwise nothing:
/// one load and one comparison.
unsafe fn used(kind: &[u8], op: &[u8], target: Target) {
    if send::all() {
        let saved = errno();
        tell(0, kind, op, target);
        set_errno(saved);
    }
}

unsafe fn tell(err: c_int, kind: &[u8], op: &[u8], target: Target) {
    if !send::ready() {
        return;
    }
    let mut line = Line::new();
    line.raw(b"hlyn1\t");
    line.raw(kind);
    line.tab();
    line.raw(op);
    line.tab();
    line.num(err as u32 as u64);
    line.tab();
    line.open();
    aim(&mut line, target);
    line.close();

    // Decided before asking who we are, so a retry loop that is not due to
    // be sent costs no further syscalls.
    let count = seen::bump(line.key(kind));
    // A use (`err` 0) is worth telling once: the draft needs to know it
    // happened, not how often. A refusal is told at 1, 2, 4, 8 ...
    if (err == 0 && count > 1) || (err != 0 && !seen::due(count)) {
        return;
    }
    line.tab();
    line.num(libc::syscall(libc::SYS_getpid) as u64);
    line.tab();
    let mut name = [0u8; 17]; // the kernel's 16, plus a terminator it may omit
    if libc::syscall(libc::SYS_prctl, libc::PR_GET_NAME as c_long, name.as_mut_ptr()) == 0 {
        line.cstr(name.as_ptr(), 16);
    } else {
        line.raw(b"?");
    }
    line.finish(count);
    send::send(line.bytes());
}

unsafe fn aim(line: &mut Line, target: Target) {
    match target {
        Target::Path(dirfd, path) => place(line, dirfd, path),
        Target::Program(name) => {
            if !name.is_null() && has_slash(name) {
                place(line, AT_FDCWD, name);
            } else {
                line.cstr(name.cast(), 4096);
            }
        }
        Target::Addr(addr, len) => address(line, addr, len),
        Target::Family(domain) => {
            line.raw(b"socket:");
            line.num(domain as u32 as u64);
        }
    }
}

unsafe fn has_slash(name: *const c_char) -> bool {
    let bytes = name.cast::<u8>();
    let mut n = 0;
    while n < 4096 && *bytes.add(n) != 0 {
        if *bytes.add(n) == b'/' {
            return true;
        }
        n += 1;
    }
    false
}

/// A path made absolute the way the kernel resolved it: relative paths are
/// joined to the working directory or to the directory descriptor given.
unsafe fn place(line: &mut Line, dirfd: c_int, path: *const c_char) {
    if path.is_null() {
        line.raw(b"?");
        return;
    }
    let bytes = path.cast::<u8>();
    if *bytes != b'/' {
        let mut base = [0u8; 4096];
        let found = if dirfd == AT_FDCWD { cwd(&mut base) } else { held(dirfd, &mut base) };
        match found {
            Some(n) => {
                line.text(&base[..n]);
                if base[n - 1] != b'/' {
                    line.raw(b"/");
                }
            }
            None => {
                line.raw(b"fd:");
                line.num(dirfd as u32 as u64);
                line.raw(b"/");
            }
        }
    }
    line.cstr(bytes, 4096);
}

/// The working directory, straight from the kernel.
unsafe fn cwd(buf: &mut [u8; 4096]) -> Option<usize> {
    let got = libc::syscall(libc::SYS_getcwd, buf.as_mut_ptr(), buf.len());
    // Success is the length including the terminator.
    if got > 1 && (got as usize) <= buf.len() {
        Some(got as usize - 1)
    } else {
        None
    }
}

/// The path a directory descriptor refers to. `readlink` is not something
/// Landlock governs, so this works inside the boundary.
unsafe fn held(fd: c_int, buf: &mut [u8; 4096]) -> Option<usize> {
    if fd < 0 {
        return None;
    }
    let mut link = [0u8; 32];
    let prefix = b"/proc/self/fd/";
    link[..prefix.len()].copy_from_slice(prefix);
    let mut n = prefix.len();
    let mut digits = [0u8; 10];
    let mut d = 0;
    let mut v = fd as u32;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 || d == digits.len() {
            break;
        }
    }
    while d > 0 && n < link.len() - 1 {
        d -= 1;
        link[n] = digits[d];
        n += 1;
    }
    link[n] = 0;
    let got = libc::syscall(
        libc::SYS_readlinkat,
        AT_FDCWD as c_long,
        link.as_ptr(),
        buf.as_mut_ptr(),
        buf.len(),
    );
    if got > 0 && (got as usize) < buf.len() {
        Some(got as usize)
    } else {
        None
    }
}

/// `PORT ADDRESS` for IP, `unix:PATH` or `unix:@NAME` for local sockets.
unsafe fn address(line: &mut Line, addr: *const sockaddr, len: socklen_t) {
    let len = len as usize;
    if addr.is_null() || len < 2 {
        line.raw(b"?");
        return;
    }
    // The kernel refuses an address longer than `sockaddr_storage` before any
    // policy is consulted, so a refused call's address is never longer.
    let raw = core::slice::from_raw_parts(addr.cast::<u8>(), len.min(128));
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as c_int;
    match family {
        libc::AF_INET if raw.len() >= 8 => {
            line.num(u16::from_be_bytes([raw[2], raw[3]]) as u64);
            line.raw(b" ");
            for (i, octet) in raw[4..8].iter().enumerate() {
                if i > 0 {
                    line.raw(b".");
                }
                line.num(*octet as u64);
            }
        }
        libc::AF_INET6 if raw.len() >= 24 => {
            line.num(u16::from_be_bytes([raw[2], raw[3]]) as u64);
            line.raw(b" ");
            for i in 0..8 {
                if i > 0 {
                    line.raw(b":");
                }
                line.hex(u16::from_be_bytes([raw[8 + 2 * i], raw[9 + 2 * i]]));
            }
        }
        libc::AF_UNIX => {
            line.raw(b"unix:");
            let path = &raw[2..];
            match path.first() {
                // Abstract: a name, not a path, and every byte of it counts.
                Some(0) => {
                    line.raw(b"@");
                    line.text(&path[1..]);
                }
                _ => {
                    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                    line.text(&path[..end]);
                }
            }
        }
        _ => {
            line.raw(b"family:");
            line.num(family as u32 as u64);
        }
    }
}

/// Whether `open`'s flags ask for anything beyond reading.
fn opened(flags: c_int) -> &'static [u8] {
    let writes = flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0
        || flags & libc::O_TMPFILE == libc::O_TMPFILE;
    if writes {
        WRITE
    } else {
        READ
    }
}

/// Whether an `fopen` mode string asks for anything beyond reading.
unsafe fn moded(mode: *const c_char) -> &'static [u8] {
    if mode.is_null() {
        return READ;
    }
    let bytes = mode.cast::<u8>();
    let mut n = 0;
    while n < 16 && *bytes.add(n) != 0 {
        if matches!(*bytes.add(n), b'w' | b'a' | b'+') {
            return WRITE;
        }
        n += 1;
    }
    READ
}

/// The real function as a callable, or the failure a missing one should give.
macro_rules! next {
    ($real:ident, fn($($arg:ty),*) -> $ret:ty, $fail:expr) => {{
        let found = $real.get();
        if found.is_null() {
            set_errno(ENOSYS);
            return $fail;
        }
        transmute::<*mut c_void, unsafe extern "C" fn($($arg),*) -> $ret>(found)
    }};
    // `open` and `openat` are variadic in C. Calling a variadic function
    // through a variadic pointer is ordinary stable Rust; only *defining* one
    // is not, which is what the wrappers below work around.
    ($real:ident, fn($($arg:ty),* ; ...) -> $ret:ty, $fail:expr) => {{
        let found = $real.get();
        if found.is_null() {
            set_errno(ENOSYS);
            return $fail;
        }
        transmute::<*mut c_void, unsafe extern "C" fn($($arg),* , ...) -> $ret>(found)
    }};
}

// -- opening --------------------------------------------------------------
//
// `open(path, flags, ...)` is variadic, and Rust cannot define a variadic
// function. It is defined here with the mode as a third ordinary argument
// instead. On x86_64 and aarch64 Linux -- the only targets this builds for --
// a variadic integer argument travels in the same register as the named one
// would, so the value is the same either way. When the caller passed no mode,
// the register holds whatever was there, and it is passed on to a C library
// that ignores it for exactly the same reason: no O_CREAT, no mode.

#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    let real = next!(OPEN, fn(*const c_char, c_int; ...) -> c_int, -1);
    let rc = real(path, flags, mode);
    if rc < 0 {
        refused(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    } else {
        used(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    let real = next!(OPEN64, fn(*const c_char, c_int; ...) -> c_int, -1);
    let rc = real(path, flags, mode);
    if rc < 0 {
        refused(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    } else {
        used(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    let real = next!(OPENAT, fn(c_int, *const c_char, c_int; ...) -> c_int, -1);
    let rc = real(dirfd, path, flags, mode);
    if rc < 0 {
        refused(opened(flags), b"openat", Target::Path(dirfd, path));
    } else {
        used(opened(flags), b"openat", Target::Path(dirfd, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn openat64(dirfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    let real = next!(OPENAT64, fn(c_int, *const c_char, c_int; ...) -> c_int, -1);
    let rc = real(dirfd, path, flags, mode);
    if rc < 0 {
        refused(opened(flags), b"openat", Target::Path(dirfd, path));
    } else {
        used(opened(flags), b"openat", Target::Path(dirfd, path));
    }
    rc
}

// What `open` becomes under _FORTIFY_SOURCE when the flags need no mode.

#[no_mangle]
pub unsafe extern "C" fn __open_2(path: *const c_char, flags: c_int) -> c_int {
    let real = next!(OPEN_2, fn(*const c_char, c_int) -> c_int, -1);
    let rc = real(path, flags);
    if rc < 0 {
        refused(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    } else {
        used(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn __open64_2(path: *const c_char, flags: c_int) -> c_int {
    let real = next!(OPEN64_2, fn(*const c_char, c_int) -> c_int, -1);
    let rc = real(path, flags);
    if rc < 0 {
        refused(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    } else {
        used(opened(flags), b"open", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    let real = next!(OPENAT_2, fn(c_int, *const c_char, c_int) -> c_int, -1);
    let rc = real(dirfd, path, flags);
    if rc < 0 {
        refused(opened(flags), b"openat", Target::Path(dirfd, path));
    } else {
        used(opened(flags), b"openat", Target::Path(dirfd, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    let real = next!(OPENAT64_2, fn(c_int, *const c_char, c_int) -> c_int, -1);
    let rc = real(dirfd, path, flags);
    if rc < 0 {
        refused(opened(flags), b"openat", Target::Path(dirfd, path));
    } else {
        used(opened(flags), b"openat", Target::Path(dirfd, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    let real = next!(CREAT, fn(*const c_char, mode_t) -> c_int, -1);
    let rc = real(path, mode);
    if rc < 0 {
        refused(WRITE, b"creat", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"creat", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    let real = next!(CREAT64, fn(*const c_char, mode_t) -> c_int, -1);
    let rc = real(path, mode);
    if rc < 0 {
        refused(WRITE, b"creat", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"creat", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    let real = next!(FOPEN, fn(*const c_char, *const c_char) -> *mut FILE, core::ptr::null_mut());
    let out = real(path, mode);
    if out.is_null() {
        refused(moded(mode), b"fopen", Target::Path(AT_FDCWD, path));
    } else {
        used(moded(mode), b"fopen", Target::Path(AT_FDCWD, path));
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn fopen64(path: *const c_char, mode: *const c_char) -> *mut FILE {
    let real = next!(FOPEN64, fn(*const c_char, *const c_char) -> *mut FILE, core::ptr::null_mut());
    let out = real(path, mode);
    if out.is_null() {
        refused(moded(mode), b"fopen", Target::Path(AT_FDCWD, path));
    } else {
        used(moded(mode), b"fopen", Target::Path(AT_FDCWD, path));
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn freopen(path: *const c_char, mode: *const c_char, stream: *mut FILE) -> *mut FILE {
    let real = next!(FREOPEN, fn(*const c_char, *const c_char, *mut FILE) -> *mut FILE, core::ptr::null_mut());
    let out = real(path, mode, stream);
    if out.is_null() && !path.is_null() {
        refused(moded(mode), b"freopen", Target::Path(AT_FDCWD, path));
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn freopen64(path: *const c_char, mode: *const c_char, stream: *mut FILE) -> *mut FILE {
    let real = next!(FREOPEN64, fn(*const c_char, *const c_char, *mut FILE) -> *mut FILE, core::ptr::null_mut());
    let out = real(path, mode, stream);
    if out.is_null() && !path.is_null() {
        refused(moded(mode), b"freopen", Target::Path(AT_FDCWD, path));
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut DIR {
    let real = next!(OPENDIR, fn(*const c_char) -> *mut DIR, core::ptr::null_mut());
    let out = real(path);
    if out.is_null() {
        refused(READ, b"opendir", Target::Path(AT_FDCWD, path));
    } else {
        used(READ, b"opendir", Target::Path(AT_FDCWD, path));
    }
    out
}

// -- changing the tree ----------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    let real = next!(MKDIR, fn(*const c_char, mode_t) -> c_int, -1);
    let rc = real(path, mode);
    if rc < 0 {
        refused(WRITE, b"mkdir", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"mkdir", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    let real = next!(MKDIRAT, fn(c_int, *const c_char, mode_t) -> c_int, -1);
    let rc = real(dirfd, path, mode);
    if rc < 0 {
        refused(WRITE, b"mkdir", Target::Path(dirfd, path));
    } else {
        used(WRITE, b"mkdir", Target::Path(dirfd, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    let real = next!(RMDIR, fn(*const c_char) -> c_int, -1);
    let rc = real(path);
    if rc < 0 {
        refused(WRITE, b"rmdir", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"rmdir", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    let real = next!(UNLINK, fn(*const c_char) -> c_int, -1);
    let rc = real(path);
    if rc < 0 {
        refused(WRITE, b"unlink", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"unlink", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    let real = next!(UNLINKAT, fn(c_int, *const c_char, c_int) -> c_int, -1);
    let rc = real(dirfd, path, flags);
    if rc < 0 {
        refused(WRITE, b"unlink", Target::Path(dirfd, path));
    } else {
        used(WRITE, b"unlink", Target::Path(dirfd, path));
    }
    rc
}

// A rename needs write on both ends, and the error does not say which one was
// refused, so both are reported.

#[no_mangle]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    let real = next!(RENAME, fn(*const c_char, *const c_char) -> c_int, -1);
    let rc = real(old, new);
    if rc < 0 {
        refused(WRITE, b"rename", Target::Path(AT_FDCWD, old));
        refused(WRITE, b"rename", Target::Path(AT_FDCWD, new));
    } else {
        used(WRITE, b"rename", Target::Path(AT_FDCWD, old));
        used(WRITE, b"rename", Target::Path(AT_FDCWD, new));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn renameat(olddir: c_int, old: *const c_char, newdir: c_int, new: *const c_char) -> c_int {
    let real = next!(RENAMEAT, fn(c_int, *const c_char, c_int, *const c_char) -> c_int, -1);
    let rc = real(olddir, old, newdir, new);
    if rc < 0 {
        refused(WRITE, b"rename", Target::Path(olddir, old));
        refused(WRITE, b"rename", Target::Path(newdir, new));
    } else {
        used(WRITE, b"rename", Target::Path(olddir, old));
        used(WRITE, b"rename", Target::Path(newdir, new));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn renameat2(
    olddir: c_int,
    old: *const c_char,
    newdir: c_int,
    new: *const c_char,
    flags: u32,
) -> c_int {
    let real = next!(RENAMEAT2, fn(c_int, *const c_char, c_int, *const c_char, u32) -> c_int, -1);
    let rc = real(olddir, old, newdir, new, flags);
    if rc < 0 {
        refused(WRITE, b"rename", Target::Path(olddir, old));
        refused(WRITE, b"rename", Target::Path(newdir, new));
    } else {
        used(WRITE, b"rename", Target::Path(olddir, old));
        used(WRITE, b"rename", Target::Path(newdir, new));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
    let real = next!(LINK, fn(*const c_char, *const c_char) -> c_int, -1);
    let rc = real(old, new);
    if rc < 0 {
        refused(WRITE, b"link", Target::Path(AT_FDCWD, new));
    } else {
        used(WRITE, b"link", Target::Path(AT_FDCWD, new));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn linkat(
    olddir: c_int,
    old: *const c_char,
    newdir: c_int,
    new: *const c_char,
    flags: c_int,
) -> c_int {
    let real = next!(LINKAT, fn(c_int, *const c_char, c_int, *const c_char, c_int) -> c_int, -1);
    let rc = real(olddir, old, newdir, new, flags);
    if rc < 0 {
        refused(WRITE, b"link", Target::Path(newdir, new));
    } else {
        used(WRITE, b"link", Target::Path(newdir, new));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn symlink(target: *const c_char, path: *const c_char) -> c_int {
    let real = next!(SYMLINK, fn(*const c_char, *const c_char) -> c_int, -1);
    let rc = real(target, path);
    if rc < 0 {
        refused(WRITE, b"symlink", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"symlink", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn symlinkat(target: *const c_char, dirfd: c_int, path: *const c_char) -> c_int {
    let real = next!(SYMLINKAT, fn(*const c_char, c_int, *const c_char) -> c_int, -1);
    let rc = real(target, dirfd, path);
    if rc < 0 {
        refused(WRITE, b"symlink", Target::Path(dirfd, path));
    } else {
        used(WRITE, b"symlink", Target::Path(dirfd, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn truncate(path: *const c_char, size: off_t) -> c_int {
    let real = next!(TRUNCATE, fn(*const c_char, off_t) -> c_int, -1);
    let rc = real(path, size);
    if rc < 0 {
        refused(WRITE, b"truncate", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"truncate", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn truncate64(path: *const c_char, size: off64_t) -> c_int {
    let real = next!(TRUNCATE64, fn(*const c_char, off64_t) -> c_int, -1);
    let rc = real(path, size);
    if rc < 0 {
        refused(WRITE, b"truncate", Target::Path(AT_FDCWD, path));
    } else {
        used(WRITE, b"truncate", Target::Path(AT_FDCWD, path));
    }
    rc
}

// -- running programs -----------------------------------------------------
//
// On success these never return, so everything after the call is the failure
// path. The variadic `execl` family is not wrapped: Rust cannot define a
// variadic function, and glibc builds those on its internal `execve`.

#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let real = next!(EXECVE, fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int, -1);
    used(EXEC, b"execve", Target::Path(AT_FDCWD, path)); // told first: a successful exec never returns
    let rc = real(path, argv, envp);
    refused(EXEC, b"execve", Target::Path(AT_FDCWD, path));
    rc
}

#[no_mangle]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    let real = next!(EXECV, fn(*const c_char, *const *const c_char) -> c_int, -1);
    used(EXEC, b"execv", Target::Path(AT_FDCWD, path)); // told first: a successful exec never returns
    let rc = real(path, argv);
    refused(EXEC, b"execv", Target::Path(AT_FDCWD, path));
    rc
}

#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    let real = next!(EXECVP, fn(*const c_char, *const *const c_char) -> c_int, -1);
    used(EXEC, b"execvp", Target::Program(file)); // told first: a successful exec never returns
    let rc = real(file, argv);
    refused(EXEC, b"execvp", Target::Program(file));
    rc
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let real = next!(EXECVPE, fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int, -1);
    used(EXEC, b"execvpe", Target::Program(file)); // told first: a successful exec never returns
    let rc = real(file, argv, envp);
    refused(EXEC, b"execvpe", Target::Program(file));
    rc
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut pid_t,
    path: *const c_char,
    actions: *const posix_spawn_file_actions_t,
    attrs: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let real = next!(
        POSIX_SPAWN,
        fn(
            *mut pid_t,
            *const c_char,
            *const posix_spawn_file_actions_t,
            *const posix_spawnattr_t,
            *const *mut c_char,
            *const *mut c_char
        ) -> c_int,
        ENOSYS
    );
    let rc = real(pid, path, actions, attrs, argv, envp);
    refused_with(rc, EXEC, b"posix_spawn", Target::Path(AT_FDCWD, path));
    if rc == 0 {
        used(EXEC, b"posix_spawn", Target::Path(AT_FDCWD, path));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut pid_t,
    file: *const c_char,
    actions: *const posix_spawn_file_actions_t,
    attrs: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    let real = next!(
        POSIX_SPAWNP,
        fn(
            *mut pid_t,
            *const c_char,
            *const posix_spawn_file_actions_t,
            *const posix_spawnattr_t,
            *const *mut c_char,
            *const *mut c_char
        ) -> c_int,
        ENOSYS
    );
    let rc = real(pid, file, actions, attrs, argv, envp);
    refused_with(rc, EXEC, b"posix_spawnp", Target::Program(file));
    if rc == 0 {
        used(EXEC, b"posix_spawnp", Target::Program(file));
    }
    rc
}

// -- the shell ------------------------------------------------------------
//
// glibc starts `/bin/sh` for these through its internal `posix_spawn`, which
// no wrapper above sees. Measured on glibc 2.39: when the shell may not run,
// `popen` returns NULL with `errno` EACCES, and `system` returns exit status
// 127 -- as for a command the shell can't find -- with `errno` EACCES. That
// `errno` is what tells the two apart, so `system` clears it first and puts
// the program's own value back if the call left it alone.

const SHELL: &[u8] = b"/bin/sh\0";

#[no_mangle]
pub unsafe extern "C" fn popen(command: *const c_char, mode: *const c_char) -> *mut FILE {
    let real = next!(POPEN, fn(*const c_char, *const c_char) -> *mut FILE, core::ptr::null_mut());
    let out = real(command, mode);
    if out.is_null() {
        refused(EXEC, b"popen", Target::Path(AT_FDCWD, SHELL.as_ptr().cast()));
    } else {
        used(EXEC, b"popen", Target::Path(AT_FDCWD, SHELL.as_ptr().cast()));
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    let real = next!(SYSTEM, fn(*const c_char) -> c_int, -1);
    let saved = errno();
    set_errno(0);
    let rc = real(command);
    let err = errno();
    if !command.is_null() && rc == 127 << 8 && (err == EACCES || err == EPERM) {
        refused(EXEC, b"system", Target::Path(AT_FDCWD, SHELL.as_ptr().cast()));
    } else if !command.is_null() && rc != -1 {
        used(EXEC, b"system", Target::Path(AT_FDCWD, SHELL.as_ptr().cast()));
    }
    if err == 0 {
        set_errno(saved); // untouched by the call: the program's own value
    }
    rc
}

// -- the network ----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    let real = next!(CONNECT, fn(c_int, *const sockaddr, socklen_t) -> c_int, -1);
    let rc = real(fd, addr, len);
    if rc < 0 {
        refused(NET, b"connect", Target::Addr(addr, len));
        if errno() == libc::EINPROGRESS {
            used(NET, b"connect", Target::Addr(addr, len)); // non-blocking, under way
        }
    } else {
        used(NET, b"connect", Target::Addr(addr, len));
    }
    rc
}

// Only a send that opens a connection (TCP Fast Open) can be a policy refusal.
// Every other send is left alone, errors included: its errno is the network's.
#[no_mangle]
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const sockaddr,
    alen: socklen_t,
) -> ssize_t {
    let real = next!(SENDTO, fn(c_int, *const c_void, size_t, c_int, *const sockaddr, socklen_t) -> ssize_t, -1);
    let rc = real(fd, buf, len, flags, addr, alen);
    if rc < 0 && flags & libc::MSG_FASTOPEN != 0 {
        refused(NET, b"sendto", Target::Addr(addr, alen));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    let real = next!(SENDMSG, fn(c_int, *const msghdr, c_int) -> ssize_t, -1);
    let rc = real(fd, msg, flags);
    if rc < 0 && flags & libc::MSG_FASTOPEN != 0 && !msg.is_null() {
        refused(NET, b"sendmsg", Target::Addr((*msg).msg_name as *const sockaddr, (*msg).msg_namelen));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    let real = next!(BIND, fn(c_int, *const sockaddr, socklen_t) -> c_int, -1);
    let rc = real(fd, addr, len);
    if rc < 0 {
        refused(LISTEN, b"bind", Target::Addr(addr, len));
    } else {
        used(LISTEN, b"bind", Target::Addr(addr, len));
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int {
    let real = next!(SOCKET, fn(c_int, c_int, c_int) -> c_int, -1);
    let rc = real(domain, kind, protocol);
    if rc < 0 {
        refused(NET, b"socket", Target::Family(domain));
    }
    rc
}
