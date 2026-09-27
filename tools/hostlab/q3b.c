// Q3: can libseccomp express the host-mode socket rules, and how?
#define _GNU_SOURCE
#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static void try(const char *what, int dom, int type, int proto) {
    int fd = socket(dom, type, proto);
    printf("  %-34s -> %s\n", what, fd >= 0 ? "allowed" : strerror(errno));
    if (fd >= 0) close(fd);
}
int main(void) {
    const struct scmp_version *v = seccomp_version();
    printf("libseccomp %u.%u.%u\n", v->major, v->minor, v->micro);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    int EP = SCMP_ACT_ERRNO(EPERM);

    int bad = 0;
    for (int fam = 0; fam <= 45; fam++) {
        if (fam == AF_UNIX || fam == AF_INET || fam == AF_INET6 || fam == AF_NETLINK) continue;
        if (seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_EQ, fam))) bad++;
    }
    if (seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 1, SCMP_A0(SCMP_CMP_GT, 45))) bad++;
    printf("per-family rules: %d failed to add\n", bad);
    // Netlink: route only.
    seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, 16), SCMP_A2(SCMP_CMP_NE, 0));
    // IP: stream only (type & 0xf), and not SCTP or MPTCP.
    int doms[] = { AF_INET, AF_INET6 };
    int bad_types[] = { SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP, SOCK_PACKET };
    for (int d = 0; d < 2; d++) {
        for (unsigned t = 0; t < sizeof bad_types / sizeof *bad_types; t++)
            seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, doms[d]),
                             SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, bad_types[t]));
        seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, doms[d]), SCMP_A2(SCMP_CMP_EQ, IPPROTO_SCTP));
        seccomp_rule_add(ctx, EP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, doms[d]), SCMP_A2(SCMP_CMP_EQ, IPPROTO_MPTCP));
    }
    int r;
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if ((r = seccomp_load(ctx))) { printf("load failed: %s\n", strerror(-r)); return 1; }

    puts("functional check under the loaded filter:");
    try("AF_UNIX stream", AF_UNIX, SOCK_STREAM, 0);
    try("AF_UNIX dgram", AF_UNIX, SOCK_DGRAM, 0);
    try("AF_INET stream", AF_INET, SOCK_STREAM, 0);
    try("AF_INET stream|NONBLOCK|CLOEXEC", AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    try("AF_INET6 stream tcp", AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    try("AF_INET dgram (UDP)", AF_INET, SOCK_DGRAM, 0);
    try("AF_INET6 dgram|CLOEXEC (UDP)", AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    try("AF_INET raw", AF_INET, SOCK_RAW, IPPROTO_ICMP);
    try("AF_INET stream SCTP", AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    try("AF_INET6 stream MPTCP", AF_INET6, SOCK_STREAM, IPPROTO_MPTCP);
    try("AF_NETLINK route", AF_NETLINK, SOCK_RAW, 0);
    try("AF_NETLINK sock_diag (4)", AF_NETLINK, SOCK_RAW, 4);
    try("AF_PACKET (17)", 17, SOCK_RAW, 0);
    try("AF_RDS (21)", 21, SOCK_SEQPACKET, 0);
    try("AF_TIPC (30)", 30, SOCK_RDM, 0);
    try("AF_ALG (38)", 38, SOCK_SEQPACKET, 0);
    try("AF_VSOCK (40)", 40, SOCK_STREAM, 0);
    try("AF_XDP (44)", 44, SOCK_RAW, 0);
    try("family 46 (past AF_MAX today)", 46, SOCK_STREAM, 0);
    try("AF_APPLETALK (5)", 5, SOCK_DGRAM, 0);
    return 0;
}
