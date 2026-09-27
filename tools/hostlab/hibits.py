# A socket() domain with garbage in the upper 32 bits. The seccomp filter
# compares the whole register; the kernel reads only the low 32 bits. Run as
# `python3 hibits.py` on Linux with hlyn importable (tools/linuxtest.sh --sh).
import ctypes, os, socket, time
libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0)); uport = udp.getsockname()[1]
pid = os.fork()
if pid == 0:
    srv.close(); udp.close()
    import hlyn; from hlyn.core import seccomp
    nr = seccomp._nr("socket")
    hlyn.on()  # the default policy: net=False
    try:
        socket.socket(); print("agent: plain socket(): CREATED", flush=True)
    except OSError as e:
        print("agent: plain socket():", e, flush=True)
    fd = libc.syscall(ctypes.c_long(nr), ctypes.c_long((1 << 32) | socket.AF_INET),
                      ctypes.c_long(socket.SOCK_STREAM), ctypes.c_long(0))
    print("agent: socket((1<<32)|AF_INET):", fd if fd >= 0 else os.strerror(ctypes.get_errno()), flush=True)
    if fd >= 0:
        s = socket.socket(fileno=fd)
        try:
            s.connect(("127.0.0.1", port)); s.sendall(b"leak-under-net-False")
            print("agent: connected and sent", flush=True)
        except OSError as e:
            print("agent: connect:", e, flush=True)
    fd = libc.syscall(ctypes.c_long(nr), ctypes.c_long((1 << 32) | socket.AF_INET),
                      ctypes.c_long(socket.SOCK_DGRAM), ctypes.c_long(0))
    print("agent: UDP socket((1<<32)|AF_INET):", fd if fd >= 0 else os.strerror(ctypes.get_errno()), flush=True)
    if fd >= 0:
        u = socket.socket(fileno=fd)
        try:
            u.sendto(b"leak-over-udp-under-net-False", ("127.0.0.1", uport)); print("agent: UDP sent", flush=True)
        except OSError as e:
            print("agent: UDP sendto:", e, flush=True)
    os._exit(0)
srv.settimeout(3)
try:
    c, _ = srv.accept(); print("LISTENER GOT:", c.recv(100))
except socket.timeout:
    print("listener: nothing arrived")
udp.settimeout(3)
try:
    print("UDP LISTENER GOT:", udp.recv(100))
except socket.timeout:
    print("udp listener: nothing arrived")
os.waitpid(pid, 0)
