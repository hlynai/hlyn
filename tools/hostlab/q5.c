// SPDX-License-Identifier: Apache-2.0
// Q5: does Landlock's TCP connect rule (ABI 4+) stop TCP Fast Open?
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif
#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
static int lst; static struct sockaddr_in addr;
static const char *accepted(void) {
    struct pollfd p = { lst, POLLIN, 0 };
    if (poll(&p, 1, 300) > 0) { int c = accept(lst, NULL, NULL); char b[16] = {0}; usleep(50000);
        int n = recv(c, b, sizeof b - 1, MSG_DONTWAIT); close(c);
        static char o[64]; snprintf(o, sizeof o, "LISTENER GOT A CONNECTION (data: %s)", n > 0 ? b : "none"); return o; }
    return "listener got nothing";
}
static void report(const char *what, int rc) {
    printf("  %-44s rc=%d %-24s %s\n", what, rc, rc < 0 ? strerror(errno) : "ok", accepted());
}
int main(void) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_fastopen", "r"); int tfo = -1; if (f) { fscanf(f, "%d", &tfo); fclose(f); }
    printf("Landlock ABI %d, net.ipv4.tcp_fastopen=%d\n", abi, tfo);
    // Listener set up before the sandbox, accepting TFO data in the SYN.
    lst = socket(AF_INET, SOCK_STREAM, 0); int one = 1, q = 16;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(lst, IPPROTO_TCP, TCP_FASTOPEN, &q, sizeof q);
    addr.sin_family = AF_INET; addr.sin_port = htons(47001); inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bind(lst, (void *)&addr, sizeof addr); listen(lst, 16);

    // Sandbox: handle TCP connect and bind, allow no port at all.
    struct landlock_ruleset_attr ra = { .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP };
    int rs = syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (rs < 0 || syscall(SYS_landlock_restrict_self, rs, 0)) { perror("landlock"); return 1; }
    puts("sealed: Landlock allows zero TCP ports");

    int s;
    s = socket(AF_INET, SOCK_STREAM, 0); report("connect()", connect(s, (void *)&addr, sizeof addr)); close(s);
    for (int round = 0; round < 2; round++) {   // round 2 has a TFO cookie cached from round 1, if round 1 got through
        s = socket(AF_INET, SOCK_STREAM, 0);
        report(round ? "sendto(MSG_FASTOPEN) again (cookie cached?)" : "sendto(MSG_FASTOPEN)",
               sendto(s, "tfo", 3, MSG_FASTOPEN, (void *)&addr, sizeof addr)); close(s);
    }
    s = socket(AF_INET, SOCK_STREAM, 0);
    struct msghdr m = {0}; struct iovec io = { "msg", 3 }; m.msg_name = &addr; m.msg_namelen = sizeof addr; m.msg_iov = &io; m.msg_iovlen = 1;
    report("sendmsg(MSG_FASTOPEN)", sendmsg(s, &m, MSG_FASTOPEN)); close(s);
    s = socket(AF_INET, SOCK_STREAM, 0); setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof one);
    report("TCP_FASTOPEN_CONNECT + connect()", connect(s, (void *)&addr, sizeof addr)); close(s);
    return 0;
}
