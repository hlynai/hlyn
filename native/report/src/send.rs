//! The pipe back to `hlyn run`.
//!
//! A named pipe rather than an inherited descriptor, because descriptors do
//! not survive the way programs start each other: Python's `subprocess`
//! closes everything but stdio by default, so a descriptor would reach the
//! agent and none of the tools it runs. A path in the environment does.
//!
//! Opened per record and closed straight after. Refusals are rare, and a
//! cached descriptor could be closed behind our back and its number reused
//! for one of the program's own files, which would then receive our records.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Where the pipe is, named by `hlyn run` in the child's environment.
pub const VAR: &[u8] = b"HLYN_REPORT\0";

/// Set (to anything) by `hlyn watch`: tell calls that were allowed too, so
/// the draft policy can name what the program used (see `hooks::used`).
pub const ALL: &[u8] = b"HLYN_REPORT_ALL\0";

const MAX: usize = 4096;

struct Path(UnsafeCell<[u8; MAX]>);

// Written once, by `load`, before `LEN` is published; only read afterwards.
unsafe impl Sync for Path {}

static PATH: Path = Path(UnsafeCell::new([0; MAX]));
static LEN: AtomicUsize = AtomicUsize::new(0);
static EVERY: AtomicBool = AtomicBool::new(false);

/// Reads the pipe's path from the environment. Called once, at load.
pub fn load() {
    unsafe {
        if !libc::getenv(ALL.as_ptr().cast()).is_null() {
            EVERY.store(true, Ordering::Release);
        }
        let value = libc::getenv(VAR.as_ptr().cast());
        if value.is_null() {
            return;
        }
        let bytes = value.cast::<u8>();
        let mut n = 0;
        while n < MAX && *bytes.add(n) != 0 {
            n += 1;
        }
        // Absolute, and short enough to keep its terminator; anything else is
        // not a path `hlyn run` would have written, so it is ignored.
        if n == 0 || n >= MAX || *bytes != b'/' {
            return;
        }
        let dest = &mut *PATH.0.get();
        dest[..n].copy_from_slice(core::slice::from_raw_parts(bytes, n));
        dest[n] = 0;
        LEN.store(n, Ordering::Release);
    }
}

/// Whether there is anywhere to send to. Checked first, so a program started
/// outside `hlyn run` pays nothing to build a record nobody will read.
pub fn ready() -> bool {
    LEN.load(Ordering::Acquire) != 0
}

/// Whether allowed calls are told too (`hlyn watch`). Read once, at load.
pub fn all() -> bool {
    EVERY.load(Ordering::Acquire) && ready()
}

/// Writes one record. Loses it silently if the pipe is gone or full.
pub fn send(record: &[u8]) {
    if !ready() || record.is_empty() || record.len() > crate::line::CAP {
        return;
    }
    unsafe {
        let path = (*PATH.0.get()).as_ptr();
        let fd = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD as libc::c_long,
            path,
            (libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as libc::c_long,
            0 as libc::c_long,
        );
        if fd < 0 {
            return;
        }
        // Only ever a pipe. The variable is in the environment, so anything
        // the program runs can repoint it; pointed at a regular file, a write
        // here would overwrite the start of that file.
        let mut info: libc::stat = core::mem::zeroed();
        if libc::fstat(fd as libc::c_int, &mut info) == 0
            && info.st_mode & libc::S_IFMT == libc::S_IFIFO
        {
            libc::syscall(libc::SYS_write, fd, record.as_ptr(), record.len());
        }
        libc::syscall(libc::SYS_close, fd);
    }
}
