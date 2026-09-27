// Q2: when does a seccomp notification fd report POLLHUP?
#define _GNU_SOURCE
#include <seccomp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

static void sendfd(int sock, int fd) {
    char c = 'x'; struct iovec io = { &c, 1 };
    char buf[CMSG_SPACE(sizeof(int))]; memset(buf, 0, sizeof buf);
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    struct cmsghdr *c1 = CMSG_FIRSTHDR(&m);
    c1->cmsg_level = SOL_SOCKET; c1->cmsg_type = SCM_RIGHTS; c1->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c1), &fd, sizeof(int));
    if (sendmsg(sock, &m, 0) < 0) { perror("sendmsg"); exit(1); }
}
static int recvfd(int sock) {
    char c; struct iovec io = { &c, 1 };
    char buf[CMSG_SPACE(sizeof(int))];
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    if (recvmsg(sock, &m, 0) < 0) { perror("recvmsg"); exit(1); }
    int fd; memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof(int)); return fd;
}
static const char *state(int fd) {
    struct pollfd p = { fd, POLLIN, 0 };
    int n = poll(&p, 1, 200);
    static char out[64];
    snprintf(out, sizeof out, "poll=%d%s%s", n, (p.revents & POLLHUP) ? " POLLHUP" : "", (p.revents & POLLIN) ? " POLLIN" : "");
    return out;
}
int main(void) {
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pid_t kid = fork();
    if (kid == 0) {
        close(sv[0]);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(getppid), 0);
        if (seccomp_load(ctx)) { fprintf(stderr, "load failed\n"); _exit(1); }
        int nfd = seccomp_notify_fd(ctx);
        sendfd(sv[1], nfd);
        close(nfd);                   // design step 5: the sealed process drops its copy
        char c; read(sv[1], &c, 1);   // wait until told to exit
        _exit(0);
    }
    close(sv[1]);
    int nfd = recvfd(sv[0]);
    printf("child alive:            %s\n", state(nfd));
    write(sv[0], "x", 1);             // let it exit
    usleep(300000);
    printf("child exited, zombie:   %s\n", state(nfd));
    waitpid(kid, NULL, 0);
    printf("child reaped:           %s\n", state(nfd));
    return 0;
}
