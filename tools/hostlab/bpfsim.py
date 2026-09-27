# SPDX-License-Identifier: Apache-2.0
"""Run a classic-BPF seccomp program (from seccomp_export_bpf) against made-up
syscalls, so a filter built for x86_64 can be checked on any machine.

Only the instructions libseccomp emits are implemented; anything else raises,
so an unknown opcode can never be read as "allowed". Usage: bpfsim.py FILE
"""
import struct
import sys

KILL_PROCESS, KILL_THREAD, ALLOW = 0x80000000, 0x00000000, 0x7FFF0000
X86_64, I386 = 0xC000003E, 0x40000003


def run(prog, nr, arch, args=(0,) * 6):
    data = struct.pack("<iIQ6Q", nr, arch, 0, *args)
    a = x = 0
    pc = 0
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        cls = code & 0x07
        if code == 0x20:  # LD W ABS
            a = struct.unpack_from("<I", data, k)[0]
        elif code == 0x06:  # RET K
            return k
        elif code == 0x16:  # RET A
            return a
        elif cls == 0x05:  # JMP
            op, src = code & 0xF0, code & 0x08
            v = x if src else k
            if op == 0x00:  # JA
                pc += k
                continue
            hit = {0x10: a == v, 0x20: a > v, 0x30: a >= v, 0x40: bool(a & v)}[op]
            pc += jt if hit else jf
        elif code == 0x54:  # ALU AND K
            a &= k
        elif code == 0x00:  # LD IMM
            a = k
        elif code == 0x01:  # LDX IMM
            x = k
        elif code == 0x07:  # TAX
            x = a
        elif code == 0x87:  # TXA
            a = x
        else:
            raise ValueError(f"opcode {code:#x} not implemented")


def name(action):
    return {KILL_PROCESS: "KILL_PROCESS", KILL_THREAD: "KILL_THREAD", ALLOW: "ALLOW"}.get(
        action, f"{action:#x}")


if __name__ == "__main__":
    raw = open(sys.argv[1], "rb").read()
    prog = [struct.unpack_from("<HBBI", raw, i) for i in range(0, len(raw), 8)]
    print(f"{len(prog)} instructions")
    cases = [
        ("x86_64 read (0)", 0, X86_64),
        ("x86_64 ptrace (101)", 101, X86_64),
        ("x32 ptrace (0x40000000 | 521)", 0x40000000 | 521, X86_64),
        ("x32 bit on x86_64's ptrace number (0x40000000 | 101)", 0x40000000 | 101, X86_64),
        ("x32 read (0x40000000 | 0)", 0x40000000, X86_64),
        ("ia32 int 0x80 ptrace (26)", 26, I386),
        ("ia32 int 0x80 read (3)", 3, I386),
    ]
    for label, nr, arch in cases:
        print(f"{label:55} -> {name(run(prog, nr, arch))}")
