# Runs confined (see proclab.sh). argv[1] = the unconfined launcher shell's pid.
# Prints, for each process, which /proc files it can read.
import os
import sys
import time

launcher = int(sys.argv[1])
sib = os.fork()
if sib == 0:
    time.sleep(30)
    os._exit(0)
time.sleep(0.3)
print(f"me {os.getpid()}  launcher shell {launcher}  sibling(same domain) {sib}  parent {os.getppid()}  1")
FILES = ["environ", "cmdline", "status", "stat", "statm", "cgroup", "maps", "mem", "fd/0", "cwd", "root", "exe"]


def can(path):
    try:
        if path.endswith(("/cwd", "/root", "/exe")):
            os.readlink(path)
        elif path.endswith("/mem"):
            os.close(os.open(path, os.O_RDONLY))
        else:
            with open(path, "rb") as fh:
                fh.read(64)
        return True
    except OSError as exc:
        return exc.errno


for who in ("self", str(sib), str(os.getppid()), str(launcher), "1"):
    row = []
    for name in FILES:
        got = can(f"/proc/{who}/{name}")
        row.append(f"{name}={'READ' if got is True else 'no'}")
    print(f"{who:>7}: " + " ".join(row))
    try:
        with open(f"/proc/{who}/environ", "rb") as fh:
            if b"SECRET_TOKEN" in fh.read():
                print(f"  !! /proc/{who}/environ HOLDS SECRET_TOKEN")
    except OSError:
        pass
for who in (str(os.getppid()), str(launcher), "1"):
    try:
        with open(f"/proc/{who}/cmdline", "rb") as fh:
            print(f"cmdline of {who}: {fh.read(80).replace(chr(0).encode(), b' ')!r}")
    except OSError as exc:
        print(f"cmdline of {who}: refused ({exc.strerror})")
try:
    with open("/proc/self/environ", "rb") as fh:
        print("own environ names:", sorted(e.split(b"=")[0].decode() for e in fh.read().split(b"\0") if e))
except OSError as exc:
    print("own environ: refused", exc.strerror)
try:
    print("memoryUsage-ish statm:", open("/proc/self/statm").read().strip())
except OSError as exc:
    print("own statm: refused", exc.strerror)
os.kill(sib, 9)
