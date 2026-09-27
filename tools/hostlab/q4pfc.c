// Q4 (design gap 8.4): does hlyn's x86_64 filter kill a syscall that arrives
// through a foreign ABI (ia32 `int 0x80`, or any architecture other than
// x86_64/x32)?
//
// This runs on whatever host is available -- here, Docker Desktop's aarch64
// VM -- because seccomp_export_pfc() only serialises the rule database
// libseccomp already built; it never loads the filter into the kernel, so it
// never needs to run on the architecture it describes. We build exactly the
// architecture set hlyn's seccomp.load() builds for a real x86_64 host
// (native x86_64, plus x32 added explicitly, ia32 never added) and dump the
// Pseudo Filter Code libseccomp generates, so the arch-check at the top of
// the program can be read directly instead of asserted from documentation.
//
// A real ia32 `int 0x80` / x32 syscall test needs to execute on real x86_64
// hardware and belongs in tests/test_escape.py, skipped everywhere else; this
// program is the paper-and-pencil half of that check.
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const struct scmp_version *v = seccomp_version();
    printf("libseccomp %u.%u.%u\n", v->major, v->minor, v->micro);
    printf("running on native arch token 0x%x (not x86_64 -- that's the point)\n",
           seccomp_arch_native());

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { fprintf(stderr, "seccomp_init failed\n"); return 1; }

    // Match hlyn's load(): add x86_64 as a target arch, add x32 (the only
    // extra arch hlyn ever adds, and only on an x86_64 host), then drop this
    // machine's real native arch so the exported filter is exactly what an
    // x86_64 host would produce -- not a hybrid no x86_64 host could load.
    int rc = 0;
    rc |= seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
    rc |= seccomp_arch_add(ctx, SCMP_ARCH_X32);
    rc |= seccomp_arch_remove(ctx, seccomp_arch_native());
    if (rc) { fprintf(stderr, "arch setup failed: %d\n", rc); return 1; }

    // One representative KILL rule, so the PFC isn't a trivial empty allow.
    // ptrace is the first, load-bearing entry in hlyn's SHUT list.
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ptrace), 0)) {
        fprintf(stderr, "rule add failed\n");
        return 1;
    }

    puts("\n-- exported PFC for {x86_64, x32}, ia32 (AUDIT_ARCH_I386) never added --\n");
    if (seccomp_export_pfc(ctx, STDOUT_FILENO)) {
        fprintf(stderr, "export failed\n");
        return 1;
    }
    // The real program too, for bpfsim.py: the pseudo code can't show how x32
    // (same arch token as x86_64, told apart by bit 30 of the number) is routed.
    FILE *out = fopen("/tmp/x86_64.bpf", "wb");
    if (!out || seccomp_export_bpf(ctx, fileno(out))) {
        fprintf(stderr, "bpf export failed\n");
        return 1;
    }
    fclose(out);
    puts("wrote /tmp/x86_64.bpf");
    seccomp_release(ctx);
    return 0;
}
