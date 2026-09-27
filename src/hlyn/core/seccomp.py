"""Syscall filtering, via libseccomp.

We call into `libseccomp.so`, the audited C library maintained alongside the
kernel feature, and never assemble BPF ourselves. Everything here is argument
marshalling; the filter compiler, the architecture handling, and the BPF
generation all live in the library.

This layer is not where deny-by-default lives. Landlock supplies that for the
filesystem. seccomp's job is narrower and equally load-bearing: shut the doors
that would otherwise let a process step around Landlock entirely (io_uring),
read another agent's memory (ptrace), or rebuild its own world (mount,
namespaces, module loading).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import platform
from collections.abc import Iterable

from ..error import Failed, Unsupported
from ..policy import Policy
from . import notify  # at import time: after the seal nothing more may be loaded

__all__ = ["SHUT", "busy", "load", "ready", "why"]


# -- libseccomp constants ---------------------------------------------------

KILL = 0x80000000  # SCMP_ACT_KILL_PROCESS
ALLOW = 0x7FFF0000  # SCMP_ACT_ALLOW
ERROR = 0x00050000  # SCMP_ACT_ERRNO(x), errno in the low 16 bits
NOTIFY = 0x7FC00000  # SCMP_ACT_NOTIFY: ask the gate (host mode)
EPERM = 1
EBUSY = 16
ENOSYS = 38
EPROTONOSUPPORT = 93

NNP = 3  # SCMP_FLTATR_CTL_NNP
TSYNC = 4  # SCMP_FLTATR_CTL_TSYNC

NE = 1  # SCMP_CMP_NE
GE = 5  # SCMP_CMP_GE
EQ = 4  # SCMP_CMP_EQ
MASKED = 7  # SCMP_CMP_MASKED_EQ
LOW = 0xFFFFFFFF  # an int argument: the only bits the kernel reads

BAD = -1  # __NR_SCMP_ERROR: syscall unknown on this architecture

# socket(2) domains, as an allowlist. `net` describes reach over IP, so only
# the families it describes are allowed at all: unix (never leaves the
# machine; Landlock scoping confines it), IPv4 and IPv6 (refused too when the
# network is closed), and netlink (route only, below). Every other family --
# packet, RDS, TIPC, CAN, XDP, ALG, PF_KEY, VSOCK, Bluetooth and the rest --
# crosses a boundary `net` does not describe, and some carry traffic off the
# machine (RDS over TCP, VSOCK to the hypervisor). Refused whatever `net` says.
UNIX = 1
INET = 2
INET6 = 10
ALLOWED = (UNIX, INET, INET6, 16)  # 16 is NETLINK
# One past the highest family Linux defines (AF_MAX is 46 from 5.15 through
# 7.x). libseccomp can't put two comparisons on one argument (FINDINGS.md,
# "Host allowlisting groundwork"), so there is no range rule: one rule per
# refused value below this, and one for everything at or above it -- which
# also catches a value with garbage in the upper 32 bits, since the filter
# compares the whole register while the kernel reads only the low half.
FAMILIES = 46

# Netlink talks to kernel subsystems rather than to the network. Protocol 0 is
# NETLINK_ROUTE, which `getifaddrs(3)` needs -- Python, Node, Go and most HTTP
# clients call it while starting up, so refusing it breaks the agent before it
# runs. Writing through it still needs CAP_NET_ADMIN, which nothing here has.
NETLINK = 16
ROUTE = 0

# Host mode (DESIGN-host-allowlisting.md 5.3, layer 2): an IP socket must be
# TCP. The type's low four bits are the kind (the rest are SOCK_NONBLOCK and
# SOCK_CLOEXEC); only SOCK_STREAM passes, so UDP (DNS, QUIC), raw, RDM and
# seqpacket IP sockets are refused. The protocol must be 0 or TCP: SCTP (132)
# and MPTCP (262) are stream protocols Landlock's TCP rules don't cover, and
# they, like every other value, get the answer of a kernel without them, so
# clients fall back to TCP.
STREAM = 1
KINDS = 0xF
TCP = 6

# Two ways to open a TCP connection that Landlock's port rules do not see.
# Landlock checks connect(). TCP Fast Open connects from a send call instead,
# and Landlock only covers it from Linux 7.2 and 6.18.54 (commit 33cb713db016,
# "landlock: Fix TCP Fast Open connection bypass"); no 6.12 release has the
# fix. Measured on 6.12: with only port 443 allowed, a Fast Open send reached
# port 47002 and delivered its data. The same fix says MPTCP shares the flaw.
FASTOPEN = 0x20000000  # MSG_FASTOPEN
MPTCP = 262  # IPPROTO_MPTCP
# Where each send call keeps its flags: sendto(fd, buf, len, flags, ...),
# sendmsg(fd, msg, flags), sendmmsg(fd, vec, vlen, flags).
SENDS = {"sendto": 3, "sendmsg": 2, "sendmmsg": 3}

# execveat(2) flag. With it, the pathname may be empty and the program is taken
# from the descriptor alone -- so a program written into anonymous memory can be
# run without ever having a path. Landlock enforces an exec allowlist per path,
# and has nothing to match against when there is no path.
EMPTY = 0x1000  # AT_EMPTY_PATH

# clone(2) flags that build a new namespace. Each is refused individually
# because a masked comparison can only test for equality, not for "any of".
NEW = {
    "mount": 0x00020000,
    "cgroup": 0x02000000,
    "uts": 0x04000000,
    "ipc": 0x08000000,
    "user": 0x10000000,
    "pid": 0x20000000,
    "net": 0x40000000,
}


# Syscalls that are never legitimate for a confined agent, with the reason each
# one is here. The reasons are not decoration: they are what a reviewer needs to
# judge whether the list is right, and what the log prints when one is refused.
SHUT: dict[str, str] = {
    # The critical one. io_uring submits work through a shared ring buffer
    # instead of issuing syscalls, so a seccomp filter never observes it. Left
    # open, every other entry in this list is bypassable and the syscall
    # boundary is decorative.
    "io_uring_setup": "bypasses syscall filtering entirely",
    "io_uring_enter": "bypasses syscall filtering entirely",
    "io_uring_register": "bypasses syscall filtering entirely",
    # One agent reading or writing another agent's memory.
    "ptrace": "reads and writes another process's memory",
    "process_vm_readv": "reads another process's memory",
    "process_vm_writev": "writes another process's memory",
    # The same attack by a newer route, and the reason it is easy to miss:
    # Landlock governs *opening* a path, not *using* a descriptor that is
    # already open. `pidfd_getfd` lifts an open descriptor straight out of
    # another process, so a sibling holding a secret file open hands over the
    # whole filesystem boundary without a path ever being resolved.
    #
    # Its siblings `pidfd_open` and `pidfd_send_signal` are deliberately not
    # here. A handle by itself steals nothing, blocking it does not stop the
    # theft (a pidfd also arrives via clone(CLONE_PIDFD)), and signalling is
    # already handled correctly one layer down -- Landlock's signal scoping
    # allows it inside the agent's own domain and refuses it outside, which is
    # the behaviour we want and a blanket refusal here would destroy.
    "pidfd_getfd": "takes an open file descriptor from another process",
    # Loading code into the kernel.
    "init_module": "loads kernel code",
    "finit_module": "loads kernel code",
    "delete_module": "unloads kernel code",
    "kexec_load": "replaces the running kernel",
    "kexec_file_load": "replaces the running kernel",
    "bpf": "loads programs into the kernel",
    "perf_event_open": "observes the whole system",
    # Rebuilding the filesystem view Landlock was applied to.
    "mount": "rearranges the filesystem",
    "mount_setattr": "rearranges the filesystem",
    "move_mount": "rearranges the filesystem",
    "open_tree": "rearranges the filesystem",
    "fsopen": "rearranges the filesystem",
    "fsconfig": "rearranges the filesystem",
    "fsmount": "rearranges the filesystem",
    "umount2": "rearranges the filesystem",
    "pivot_root": "replaces the root filesystem",
    "chroot": "replaces the root filesystem",
    # Escaping into a fresh namespace.
    "unshare": "creates new namespaces",
    "setns": "joins another process's namespaces",
    # Handling faults in userspace is a well-worn primitive for winning races
    # against a checking kernel path.
    "userfaultfd": "enables time-of-check races",
    # Kernel keyrings hold credentials.
    "keyctl": "reaches the kernel keyring",
    "add_key": "reaches the kernel keyring",
    "request_key": "reaches the kernel keyring",
    # Opening a file by handle sidesteps path-based checks, which is exactly
    # what Landlock performs.
    "open_by_handle_at": "opens files without a path",
    "name_to_handle_at": "opens files without a path",
    # Assorted machine-wide controls.
    "personality": "changes the execution domain",
    "modify_ldt": "changes the descriptor table",
    "quotactl": "administers filesystem quotas",
    "swapon": "administers swap",
    "swapoff": "administers swap",
    "reboot": "reboots the machine",
    "settimeofday": "moves the system clock",
    "clock_settime": "moves the system clock",
    "clock_adjtime": "moves the system clock",
    "acct": "turns on process accounting",
    "syslog": "reads the kernel log",
}

# Deliberately empty, and this used to be
# ("connect", "sendto", "sendmsg", "sendmmsg", "bind", "listen").
#
# Those syscalls do not carry an address family. Refusing them by number to
# close the network also refused every one of them on AF_UNIX -- which the
# comment above INET claims is left alone, and which `multiprocessing`, a local
# database socket and `SysLogHandler` all need. `net=False` quietly broke local
# IPC while a test that only *created* an AF_UNIX socket kept passing.
#
# Removing them costs nothing, because each thing they blocked is blocked
# better elsewhere. Creating an INET socket is refused by family below, which
# is exact. TCP bind and connect on a socket that already exists -- an
# inherited one -- are refused by Landlock, which sees the address family the
# filter cannot. What is left is an inherited socket that is *already
# connected*, and the list never covered that anyway: `write` and `send` were
# not on it. `linux.wired` closes that hole properly by refusing to seal at
# all while such a descriptor is open.
WIRE: tuple[str, ...] = ()

# Creating a new program. Refused when exec is off entirely; when exec names
# specific paths, Landlock enforces per-path and these stay open.
BIRTH: tuple[str, ...] = ("execve", "execveat")


def why(name: str) -> str:
    """The reason a syscall is refused, for the log and for reviewers."""
    return SHUT.get(name, "not permitted by policy")


# -- the library ------------------------------------------------------------


class Arg(ctypes.Structure):
    """`struct scmp_arg_cmp`: one comparison against one syscall argument."""

    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("a", ctypes.c_uint64),
        ("b", ctypes.c_uint64),
    ]


_lib: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    """Load libseccomp once, or explain precisely why we cannot confine."""
    global _lib
    if _lib is not None:
        return _lib

    where = None
    for name in ("libseccomp.so.2", "libseccomp.so"):
        try:
            _lib = ctypes.CDLL(name, use_errno=True)
            where = name
            break
        except OSError:
            continue
    if _lib is None:
        found = ctypes.util.find_library("seccomp")
        if found:
            try:
                _lib = ctypes.CDLL(found, use_errno=True)
                where = found
            except OSError:
                _lib = None
    if _lib is None:
        raise Unsupported(
            "libseccomp is not installed, so syscall filtering cannot be applied. "
            "Install it (Debian/Ubuntu: libseccomp2, Fedora/RHEL: libseccomp, "
            "Alpine: libseccomp) and try again. Refusing to continue unconfined."
        )

    del where
    # seccomp_init returns an opaque context pointer, not an int; on 64-bit the
    # default int restype would truncate it and corrupt every later call.
    _lib.seccomp_init.argtypes = [ctypes.c_uint32]
    _lib.seccomp_init.restype = ctypes.c_void_p
    _lib.seccomp_release.argtypes = [ctypes.c_void_p]
    _lib.seccomp_release.restype = None
    _lib.seccomp_load.argtypes = [ctypes.c_void_p]
    _lib.seccomp_load.restype = ctypes.c_int
    _lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
    _lib.seccomp_attr_set.restype = ctypes.c_int
    _lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    _lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    _lib.seccomp_arch_resolve_name.argtypes = [ctypes.c_char_p]
    _lib.seccomp_arch_resolve_name.restype = ctypes.c_uint32
    _lib.seccomp_arch_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    _lib.seccomp_arch_add.restype = ctypes.c_int
    # The array form takes a pointer to the comparisons. The variadic
    # seccomp_rule_add passes structs by value, which ctypes cannot do
    # dependably across ABIs, so we never use it.
    _lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(Arg),
    ]
    _lib.seccomp_rule_add_array.restype = ctypes.c_int
    return _lib


def ready() -> bool:
    """True if syscall filtering can be applied here."""
    try:
        lib()
    except Unsupported:
        return False
    return True


# -- building the filter ----------------------------------------------------


def _nr(name: str) -> int:
    """Resolve a syscall name on this architecture, or BAD if it has none."""
    return int(lib().seccomp_syscall_resolve_name(name.encode()))


def _rule(ctx: int, action: int, name: str, args: Iterable[Arg] = ()) -> None:
    """Add one rule, tolerating syscalls this architecture does not define.

    A missing syscall is not a gap: if the architecture has no `modify_ldt`,
    nothing can call it. Silently skipping keeps one filter correct on both
    x86_64 and aarch64 without branching per architecture.
    """
    nr = _nr(name)
    if nr == BAD:
        return
    args = tuple(args)
    block = (Arg * len(args))(*args) if args else None
    rc = lib().seccomp_rule_add_array(ctx, action, nr, len(args), block)
    if rc != 0:
        # EDOM/EEXIST style failures mean the rule could not be expressed, which
        # would leave a hole we believe is closed.
        raise Failed(f"could not add a seccomp rule for {name!r}: error {-rc}")


# The refusal when this process is already inside a seccomp notifier (5.2).
BUSY = (
    "can't restrict hosts here: this process is already inside a sandbox that filters "
    "connections (a host-mode hlyn run, LXD, Sysbox, nono or Sandlock), and Linux allows "
    "only one. The outer sandbox's rules still apply. Use ports (--net 443) or net=False "
    "here, or run hlyn outside it."
)


def busy() -> bool:
    """Whether a filter with a notification listener would be refused here
    (`EBUSY`: the kernel allows one listener per filter chain).

    Asked in a forked child, which tries it for real and exits, so this
    process is never changed. Called before anything is sealed, so the
    refusal comes while the caller can still act on it.
    """
    import os
    import struct

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    number = _nr("seccomp")
    # One instruction: return ALLOW. struct sock_filter, then sock_fprog.
    code = ctypes.create_string_buffer(struct.pack("=HBBI", 0x06, 0, 0, ALLOW))
    prog = ctypes.create_string_buffer(struct.pack("=HxxxxxxQ", 1, ctypes.addressof(code)))
    pid = os.fork()
    if pid == 0:
        out = 1
        try:
            libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
            # SECCOMP_SET_MODE_FILTER (1), SECCOMP_FILTER_FLAG_NEW_LISTENER (8)
            rc = libc.syscall(ctypes.c_long(number), ctypes.c_long(1), ctypes.c_long(8), prog)
            out = 0 if rc >= 0 else (2 if ctypes.get_errno() == EBUSY else 3)
        finally:
            os._exit(out)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 2


def load(policy: Policy) -> int | None:
    """Compile and install the syscall filter for `policy`.

    One-way. Once loaded the filter applies to this process and every thread
    and child it has, and cannot be removed.

    Returns the notification descriptor when `net` names hosts: every
    `connect()` then waits for an answer on it, so it must be handed to the
    gate at once and this process's copy closed (5.2, step 5). Otherwise
    returns None.
    """
    named = bool(policy.hosts())
    api = lib()
    if named:
        notify._lib()  # raises, naming the fix, before anything is loaded
    ctx = api.seccomp_init(ALLOW)
    if not ctx:
        raise Failed("libseccomp could not create a filter context")

    try:
        # NO_NEW_PRIVS is mandatory for an unprivileged filter. libseccomp sets
        # it by default; we ask explicitly so the requirement is visible here
        # rather than inherited from a library default that could change.
        if api.seccomp_attr_set(ctx, NNP, 1) != 0:
            raise Failed("libseccomp refused to set NO_NEW_PRIVS")
        # Python has threads. Without TSYNC the filter binds to the calling
        # thread only and every other thread stays unconfined.
        if api.seccomp_attr_set(ctx, TSYNC, 1) != 0:
            raise Failed("libseccomp refused to synchronise the filter across threads")

        # On x86_64 a syscall number can carry the x32 bit. Adding the x32
        # architecture makes libseccomp emit each rule for that convention too,
        # instead of letting x32 numbers fall through to the default action.
        if platform.machine() in ("x86_64", "amd64"):
            x32 = api.seccomp_arch_resolve_name(b"x32")
            if x32:
                api.seccomp_arch_add(ctx, x32)

        for name in SHUT:
            _rule(ctx, KILL, name)

        # clone3 takes its flags in a struct, and seccomp cannot follow a
        # pointer. Reporting it missing makes glibc fall back to clone, whose
        # flags are a plain register we can inspect. This is the same approach
        # container runtimes take.
        _rule(ctx, ERROR | ENOSYS, "clone3")
        for flag in NEW.values():
            _rule(ctx, KILL, "clone", [Arg(0, MASKED, flag, flag)])

        # Running a program straight out of a descriptor, with no path for an
        # allowlist to match. The flag is a plain register here, unlike clone3's
        # struct, so the one dangerous form is refused and ordinary execveat
        # keeps working. `memfd_create` itself stays open: making anonymous
        # memory is not the dangerous step, and shared-memory users need it.
        _rule(ctx, KILL, "execveat", [Arg(4, MASKED, EMPTY, EMPTY)])

        # Socket families outside what `net` describes, whatever `net` says.
        for domain in range(FAMILIES):
            if domain not in ALLOWED:
                _rule(ctx, ERROR | EPERM, "socket", [Arg(0, EQ, domain, 0)])
        _rule(ctx, ERROR | EPERM, "socket", [Arg(0, GE, FAMILIES, 0)])
        _rule(ctx, ERROR | EPERM, "socket", [Arg(0, EQ, NETLINK, 0), Arg(2, NE, ROUTE, 0)])

        if policy.net is False:
            for domain in (INET, INET6):
                _rule(ctx, ERROR | EPERM, "socket", [Arg(0, EQ, domain, 0)])
            for name in WIRE:
                _rule(ctx, ERROR | EPERM, name)
        elif isinstance(policy.net, tuple) and not named:
            # Named ports: close the two routes around Landlock (see FASTOPEN).
            # Fast Open is refused outright. It is an optimisation every client
            # can do without, and its flag is a plain register, so the refusal
            # cannot be raced. An MPTCP socket gets the answer a kernel without
            # MPTCP gives, so clients fall back to plain TCP, which Landlock
            # checks.
            for name, arg in SENDS.items():
                _rule(ctx, ERROR | EPERM, name, [Arg(arg, MASKED, FASTOPEN, FASTOPEN)])
            # The protocol is an int, so only its low 32 bits reach the
            # kernel: compare those, or (1 << 32) | MPTCP walks past an EQ.
            for domain in (INET, INET6):
                _rule(ctx, ERROR | EPROTONOSUPPORT, "socket",
                      [Arg(0, EQ, domain, 0), Arg(2, MASKED, LOW, MPTCP)])
        elif named:
            # Host mode (5.3). Landlock handles TCP with no port allowed, so
            # a TCP connect the kernel runs is refused whatever its address;
            # these rules keep every other route shut and send the rest to
            # the gate. Measured: when a refusing rule and a notify rule both
            # match a call, the notify rule can win (FINDINGS.md, "Linux
            # gate primitives"). So every rule below that refuses is disjoint
            # from every rule that notifies.
            for name, arg in SENDS.items():
                _rule(ctx, ERROR | EPERM, name, [Arg(arg, MASKED, FASTOPEN, FASTOPEN)])
            for domain in (INET, INET6):
                for kind in range(KINDS + 1):
                    if kind != STREAM:
                        _rule(ctx, ERROR | EPERM, "socket",
                              [Arg(0, EQ, domain, 0), Arg(1, MASKED, KINDS, kind)])
                # The protocol as an allowlist of 0 and TCP. Compared whole:
                # a value with upper bits set is >= TCP + 1 and refused.
                for proto in range(1, TCP):
                    _rule(ctx, ERROR | EPROTONOSUPPORT, "socket",
                          [Arg(0, EQ, domain, 0), Arg(2, EQ, proto, 0)])
                _rule(ctx, ERROR | EPROTONOSUPPORT, "socket",
                      [Arg(0, EQ, domain, 0), Arg(2, GE, TCP + 1, 0)])
            # Every connect, of any family: the gate tells unix from TCP by
            # the socket, not by the address the agent wrote (5.3, layer 3).
            _rule(ctx, NOTIFY, "connect")
            # A send that names an address (an unconnected unix datagram
            # socket sending to a path never calls connect). A NULL address
            # never leaves the kernel. Disjoint from the Fast Open refusal.
            _rule(ctx, NOTIFY, "sendto", [Arg(4, NE, 0, 0), Arg(3, MASKED, FASTOPEN, 0)])

        if policy.exec is False:
            for name in BIRTH:
                _rule(ctx, ERROR | EPERM, name)

        ctypes.set_errno(0)
        rc = api.seccomp_load(ctx)
        if rc != 0:
            # libseccomp's rc can come from one of its earlier feature
            # probes (measured: -EFAULT when the kernel said EBUSY); errno
            # holds the kernel's answer to the load itself.
            code = ctypes.get_errno() or -rc
            if named and code == EBUSY:
                raise Unsupported(BUSY + " Nothing past the filesystem rules was applied.")
            raise Failed(
                f"the kernel refused the syscall filter (error {code}). "
                "The process is NOT confined."
            )
        if not named:
            return None
        fd = int(api.seccomp_notify_fd(ctx))
        if fd < 0:
            raise Failed(
                "the syscall filter loaded but gave no notification descriptor, so no "
                "connection could ever be answered. The network is closed; nothing reaches it."
            )
        return fd
    finally:
        api.seccomp_release(ctx)
