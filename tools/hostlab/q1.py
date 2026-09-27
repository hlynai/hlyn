# Q1: does /proc/<pid>/net/unix list unbound unix sockets, read from another process?
import os, socket, subprocess, sys
socks = {
 "unix stream unbound": socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
 "unix dgram unbound": socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM),
 "unix seqpacket unbound": socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET),
 "tcp unbound": socket.socket(socket.AF_INET, socket.SOCK_STREAM),
 "tcp6 unbound": socket.socket(socket.AF_INET6, socket.SOCK_STREAM),
}
b = socket.socket(socket.AF_UNIX); b.bind("\0lababstract"); socks["unix abstract bound"] = b
pid = os.getpid()
# Read from a *different* process, as the gate would.
table = subprocess.run(["cat", f"/proc/{pid}/net/unix"], capture_output=True, text=True).stdout
inodes = {line.split()[6] for line in table.splitlines()[1:]}
for name, s in socks.items():
    link = subprocess.run(["readlink", f"/proc/{pid}/fd/{s.fileno()}"], capture_output=True, text=True).stdout.strip()
    ino = link.split("[")[1].rstrip("]")
    print(f"{name:26} {link:22} in /proc/PID/net/unix: {ino in inodes}")
