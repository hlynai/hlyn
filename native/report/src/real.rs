//! Finding the C library's own definition of each wrapped function.
//!
//! `dlsym(RTLD_NEXT, name)` returns the next definition after this library in
//! load order -- the C library's. It is the standard way an interposer reaches
//! the thing it wraps, and the reason this file contains no syscall numbers
//! for the calls it forwards: the program keeps getting the C library's
//! behaviour, cancellation points and all.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

pub struct Real {
    name: &'static [u8],
    ptr: AtomicPtr<c_void>,
}

impl Real {
    pub const fn new(name: &'static [u8]) -> Self {
        Real { name, ptr: AtomicPtr::new(ptr::null_mut()) }
    }

    /// The real function, or null if the C library does not have one.
    ///
    /// Normally already resolved by `load`. The lookup here covers the one
    /// case where it is not: another preloaded library's constructor running
    /// before ours and calling a wrapped function.
    pub fn get(&self) -> *mut c_void {
        let found = self.ptr.load(Ordering::Acquire);
        if !found.is_null() {
            return found;
        }
        let found = unsafe { libc::dlsym(libc::RTLD_NEXT, self.name.as_ptr().cast()) };
        self.ptr.store(found, Ordering::Release);
        found
    }
}

/// Declares the real functions and a list of all of them for `load`.
macro_rules! reals {
    ($($name:ident = $symbol:literal;)*) => {
        $(pub static $name: Real = Real::new(concat!($symbol, "\0").as_bytes());)*
        static ALL: &[&Real] = &[$(&$name),*];
    };
}

reals! {
    OPEN = "open";
    OPEN64 = "open64";
    OPENAT = "openat";
    OPENAT64 = "openat64";
    OPEN_2 = "__open_2";
    OPEN64_2 = "__open64_2";
    OPENAT_2 = "__openat_2";
    OPENAT64_2 = "__openat64_2";
    CREAT = "creat";
    CREAT64 = "creat64";
    FOPEN = "fopen";
    FOPEN64 = "fopen64";
    FREOPEN = "freopen";
    FREOPEN64 = "freopen64";
    OPENDIR = "opendir";
    MKDIR = "mkdir";
    MKDIRAT = "mkdirat";
    RMDIR = "rmdir";
    UNLINK = "unlink";
    UNLINKAT = "unlinkat";
    RENAME = "rename";
    RENAMEAT = "renameat";
    RENAMEAT2 = "renameat2";
    LINK = "link";
    LINKAT = "linkat";
    SYMLINK = "symlink";
    SYMLINKAT = "symlinkat";
    TRUNCATE = "truncate";
    TRUNCATE64 = "truncate64";
    EXECVE = "execve";
    EXECV = "execv";
    EXECVP = "execvp";
    EXECVPE = "execvpe";
    POSIX_SPAWN = "posix_spawn";
    POSIX_SPAWNP = "posix_spawnp";
    CONNECT = "connect";
    BIND = "bind";
    SOCKET = "socket";
    SENDTO = "sendto";
    SENDMSG = "sendmsg";
}

/// Resolves every real function up front. Called once, at load.
pub fn load() {
    for real in ALL {
        real.get();
    }
}
