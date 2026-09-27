# SPDX-License-Identifier: Apache-2.0
"""Phase 4 groundwork: what the Linux gate's kernel primitives actually do here.

Each question runs a child that loads a seccomp filter with notify rules
(built with libseccomp, as core/seccomp.py will) and hands the notification
descriptor to this process over SCM_RIGHTS, which answers with core/notify.py.

    python3 tools/hostlab/notifylab.py        # every question
    python3 tools/hostlab/notifylab.py swap   # one

Questions:
  swap      Does ADDFD+SETFD put the gate's connected socket at the agent's
            descriptor, so the agent's bytes reach the gate's listener and
            not the address it dialled? (5.3's "swap")
  order     sendto with MSG_FASTOPEN *and* an address: the EPERM rule and the
            NOTIFY rule both match. Which wins?
  sendto    sendto with a NULL address is never notified; with an address it is.
  busy      A second filter with a listener on top of the first: EBUSY?
  threads   TSYNC plus a listener, loaded by a process that already has threads.
  hup       The descriptor polls POLLHUP once the child has exited.
  restart   A signal (SA_RESTART) arrives while connect() waits for the gate:
            is the old id dead, and is the call notified again?
  half      ADDFD succeeds, then a signal interrupts before SEND: after the
            restart, is the descriptor already the gate's socket?
"""
import ctypes, os, select, signal, socket, sys, threading, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from hlyn.core import notify, seccomp  # noqa: E402

NOTIFY = 0x7FC00000  # SCMP_ACT_NOTIFY
api = seccomp.lib()
notify._lib()


def filt(*, fastopen=True, extra_threads=0, second=False):
    """Load the host-mode trap rules in this process; return the listener fd."""
    ctx = api.seccomp_init(seccomp.ALLOW)
    api.seccomp_attr_set(ctx, seccomp.NNP, 1)
    api.seccomp_attr_set(ctx, seccomp.TSYNC, 1)
    api.seccomp_attr_set(ctx, 9, 1)  # SCMP_FLTATR_API_SYSRAWRC: raw kernel errno
    seccomp._rule(ctx, NOTIFY, "connect")
    seccomp._rule(ctx, NOTIFY, "sendto", [seccomp.Arg(4, seccomp.NE, 0, 0)])
    if fastopen:
        seccomp._rule(ctx, seccomp.ERROR | seccomp.EPERM, "sendto",
                      [seccomp.Arg(3, seccomp.MASKED, seccomp.FASTOPEN, seccomp.FASTOPEN)])
    ctypes.set_errno(0)
    rc = api.seccomp_load(ctx)
    err = ctypes.get_errno()
    fd = api.seccomp_notify_fd(ctx) if rc == 0 else -1
    api.seccomp_release(ctx)
    if rc != 0:
        # libseccomp's rc can come from an earlier feature probe (measured:
        # -EFAULT when the kernel said EBUSY); errno holds the load's answer.
        print(f"  seccomp_load: rc {rc}, errno {err} ({os.strerror(err)})", flush=True)
    return rc, fd


def child(body):
    """Fork; the child runs body(chan) and exits. Returns (pid, parent's chan)."""
    a, b = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        a.close()
        code = 0
        try:
            body(b)
        except BaseException as exc:  # noqa: BLE001
            print("child:", type(exc).__name__, exc, flush=True)
            code = 1
        os._exit(code)
    b.close()
    return pid, a


def seal_and_hand(chan, **kw):
    rc, fd = filt(**kw)
    if rc != 0:
        raise OSError(-rc, f"seccomp_load: {os.strerror(-rc)}")
    socket.send_fds(chan, [b"fd"], [fd])
    os.close(fd)
    assert chan.recv(1) == b"k"


def take(chan):
    _, fds, _, _ = socket.recv_fds(chan, 16, 1)
    chan.send(b"k")
    return fds[0]


def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    return s


def wait(pid):
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def q_swap():
    real, proxy = listener(), listener()
    rport, pport = real.getsockname()[1], proxy.getsockname()[1]

    def body(chan):
        seal_and_hand(chan)
        s = socket.socket()
        s.connect(("127.0.0.1", rport))
        print(f"  agent: connect() returned; peer is {s.getpeername()}", flush=True)
        s.sendall(b"agent-bytes")
        s.close()

    pid, chan = child(body)
    fd = take(chan)
    n = notify.Notice(fd)
    select.select([fd], [], [], 5)
    call = notify.receive(n)
    addr = notify.sockaddr(notify.read(call.pid, call.args[1], call.args[2]))
    ino = notify.inode(call.pid, call.args[0])
    flags = notify.fdflags(call.pid, call.args[0])
    print(f"  gate: nr {call.nr} fd {call.args[0]} inode {ino} flags {flags:o} dialled {addr.ip}:{addr.port}"
          f" valid {notify.valid(fd, call)}")
    mine = socket.create_connection(("127.0.0.1", pport))
    notify.addfd(fd, call, mine.fileno(), call.args[0], bool(flags & os.O_CLOEXEC))
    mine.close()
    print(f"  gate: answered {notify.answer(n, call, value=0)}")
    for name, lst in (("real", real), ("proxy", proxy)):
        lst.settimeout(2)
        try:
            conn, _ = lst.accept()
            conn.settimeout(2)
            print(f"  {name} listener got: {conn.recv(100)!r}")
        except OSError as exc:
            print(f"  {name} listener got nothing ({exc})")
    print(f"  child exit {wait(pid)}")


def q_order():
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.bind(("127.0.0.1", 0))
    peer.listen(1)
    port = peer.getsockname()[1]

    def body(chan):
        seal_and_hand(chan)
        s = socket.socket()
        try:
            s.sendto(b"x", 0x20000000, ("127.0.0.1", port))
            print("  agent: sendto(MSG_FASTOPEN, addr) returned", flush=True)
        except OSError as exc:
            print(f"  agent: sendto(MSG_FASTOPEN, addr) -> {exc}", flush=True)

    pid, chan = child(body)
    fd = take(chan)
    ready, _, _ = select.select([fd], [], [], 2)
    print(f"  gate: notified: {bool(ready)}")
    if ready:
        n = notify.Notice(fd)
        call = notify.receive(n)
        notify.answer(n, call, error=13)
    print(f"  child exit {wait(pid)}")


def q_sendto():
    def body(chan):
        seal_and_hand(chan)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        a.send(b"no address")  # send() is sendto(..., NULL, 0)
        print("  agent: send() without an address returned", flush=True)
        d = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            d.sendto(b"x", "/tmp/hlyn-notifylab-nowhere")
        except OSError as exc:
            print(f"  agent: sendto(path) -> {exc}", flush=True)

    pid, chan = child(body)
    fd = take(chan)
    n = notify.Notice(fd)
    ready, _, _ = select.select([fd], [], [], 3)
    if ready:
        call = notify.receive(n)
        addr = notify.sockaddr(notify.read(call.pid, call.args[4], call.args[5]))
        print(f"  gate: notified nr {call.nr} (sendto is {seccomp._nr('sendto')}), path {addr.path!r}")
        notify.answer(n, call, error=13)
    else:
        print("  gate: nothing notified")
    print(f"  child exit {wait(pid)}")


def q_busy():
    def body(chan):
        seal_and_hand(chan)
        rc, fd = filt()
        print(f"  agent, same process: second listener filter: rc {rc} ({os.strerror(-rc) if rc else 'ok'})"
              f", notify fd {fd}", flush=True)
        # libseccomp asks for a listener once per process, so ask from a
        # fresh interpreter, as a nested hlyn run would.
        import subprocess
        code = ("import sys; sys.path.insert(0, %r); sys.argv=['x']; import notifylab as n; "
                "rc, fd = n.filt(); import os; print('  agent, fresh interpreter: rc', rc, "
                "os.strerror(-rc) if rc else 'ok', flush=True)" % os.path.dirname(os.path.abspath(__file__)))
        subprocess.run([sys.executable, "-c", code], check=False)

    pid, chan = child(body)
    take(chan)
    print(f"  child exit {wait(pid)}")


def q_threads():
    def body(chan):
        stop = threading.Event()
        workers = [threading.Thread(target=stop.wait) for _ in range(3)]
        for w in workers:
            w.start()
        print(f"  agent: {len(os.listdir('/proc/self/task'))} threads before the filter", flush=True)
        seal_and_hand(chan)
        got = []

        def dial():
            try:
                socket.create_connection(("127.0.0.1", 9), timeout=2)
            except OSError as exc:
                got.append(exc)
        t = threading.Thread(target=dial)
        t.start()
        t.join()
        print(f"  agent: a connect from a thread started *before* the seal: {got[0]!r}", flush=True)
        stop.set()

    pid, chan = child(body)
    fd = take(chan)
    n = notify.Notice(fd)
    ready, _, _ = select.select([fd], [], [], 3)
    if ready:
        call = notify.receive(n)
        print(f"  gate: notified by thread {call.pid} (child pid {pid})")
        notify.answer(n, call, error=13)
    else:
        print("  gate: nothing notified")
    print(f"  child exit {wait(pid)}")


def q_hup():
    def body(chan):
        seal_and_hand(chan)
        time.sleep(0.2)

    pid, chan = child(body)
    fd = take(chan)
    p = select.poll()
    p.register(fd, select.POLLIN)
    began = time.monotonic()
    events = p.poll(3000)
    print(f"  gate: poll -> {[(f, hex(e)) for f, e in events]} after {time.monotonic() - began:.2f} s"
          f" (POLLHUP is {hex(select.POLLHUP)})")
    print(f"  child exit {wait(pid)}")


def q_restart():
    def body(chan):
        signal.signal(signal.SIGALRM, lambda *_: print("  agent: SIGALRM handled", flush=True))
        signal.siginterrupt(signal.SIGALRM, False)  # SA_RESTART
        seal_and_hand(chan)
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        s = socket.socket()
        try:
            s.connect(("127.0.0.1", 9))
            print("  agent: connect returned 0", flush=True)
        except OSError as exc:
            print(f"  agent: connect -> {exc}", flush=True)

    pid, chan = child(body)
    fd = take(chan)
    n = notify.Notice(fd)
    select.select([fd], [], [], 3)
    first = notify.receive(n)
    time.sleep(0.6)
    print(f"  gate: first id valid after the signal: {notify.valid(fd, first)};"
          f" answering it -> {notify.answer(n, first, error=13)}")
    ready, _, _ = select.select([fd], [], [], 3)
    if ready:
        again = notify.receive(n)
        print(f"  gate: notified again: nr {again.nr} fd {again.args[0]} (first fd {first.args[0]}), "
              f"new id {again.id != first.id}")
        notify.answer(n, again, error=111)
    print(f"  child exit {wait(pid)}")


def q_half():
    proxy = listener()
    pport = proxy.getsockname()[1]

    def body(chan):
        signal.signal(signal.SIGUSR1, lambda *_: print("  agent: SIGUSR1 handled", flush=True))
        signal.siginterrupt(signal.SIGUSR1, False)
        seal_and_hand(chan)
        s = socket.socket()
        try:
            s.connect(("127.0.0.1", 9))
            print(f"  agent: connect returned 0; peer {s.getpeername()}", flush=True)
        except OSError as exc:
            print(f"  agent: connect -> {exc}", flush=True)

    pid, chan = child(body)
    fd = take(chan)
    n = notify.Notice(fd)
    select.select([fd], [], [], 3)
    first = notify.receive(n)
    ino = notify.inode(first.pid, first.args[0])
    mine = socket.create_connection(("127.0.0.1", pport))
    notify.addfd(fd, first, mine.fileno(), first.args[0], False)
    after = notify.inode(first.pid, first.args[0])
    print(f"  gate: ADDFD done; agent fd {first.args[0]} inode {ino} -> {after}")
    os.kill(pid, signal.SIGUSR1)
    time.sleep(0.3)
    print(f"  gate: answering the first id after the signal -> {notify.answer(n, first, value=0)}")
    ready, _, _ = select.select([fd], [], [], 3)
    if ready:
        again = notify.receive(n)
        print(f"  gate: restarted call: fd {again.args[0]} inode {notify.inode(again.pid, again.args[0])}"
              f" (installed {after})")
        notify.answer(n, again, value=0)
    else:
        print("  gate: not notified again")
    print(f"  child exit {wait(pid)}")


QUESTIONS = {name[2:]: fn for name, fn in globals().items() if name.startswith("q_")}

if __name__ == "__main__":
    api.seccomp_version.restype = ctypes.POINTER(ctypes.c_uint * 3)
    print(f"== kernel {os.uname().release} {os.uname().machine}, libseccomp "
          f"{'.'.join(map(str, api.seccomp_version().contents))}")
    for name in sys.argv[1:] or QUESTIONS:
        print(f"-- {name}: {QUESTIONS[name].__doc__ or ''}".rstrip())
        QUESTIONS[name]()
