// SPDX-License-Identifier: Apache-2.0
/* Matrix row 3 (DESIGN-host-allowlisting.md section 9): the race harness.
 *
 * One thread loops connect() on fresh sockets while other threads keep
 * rewriting the sockaddr it passes, between an address the gate allows and
 * one it refuses. The gate reads the address from /proc/PID/mem while the
 * call waits; a supervisor that let the call continue after that read (nono's
 * CONTINUE) could be raced into connecting to the refused address. hlyn's
 * gate never lets a TCP connect run, so the refused listener must see nothing.
 *
 * The unix variant races an allowed path against a refused one. The gate
 * does let unix connects run (5.3's residual before Landlock RESOLVE_UNIX,
 * 7.1+), so there the harness measures how often the race is won.
 *
 * Built as a shared library and called through ctypes from a sealed Python
 * process, so the threads run in parallel with no interpreter lock:
 *   cc -O2 -shared -fPIC -pthread -o race.so race.c
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>

static union { struct sockaddr_in in; struct sockaddr_un un; } addr, good, evil;
static socklen_t size;
static atomic_int stop;

static void *flip(void *unused)
{
    (void)unused;
    while (!atomic_load(&stop)) {
        memcpy(&addr, &evil, size);
        memcpy(&addr, &good, size);
    }
    return 0;
}

/* out[0]: connects that returned 0; out[1]: EACCES; out[2]: anything else. */
static int loop(int family, int iterations, int flippers, int *out)
{
    pthread_t threads[64];
    if (flippers > 64)
        flippers = 64;
    memcpy(&addr, &good, size);
    atomic_store(&stop, 0);
    for (int i = 0; i < flippers; i++)
        pthread_create(&threads[i], 0, flip, 0);
    for (int i = 0; i < iterations; i++) {
        int s = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            out[2]++;
            continue;
        }
        if (connect(s, (struct sockaddr *)&addr, size) == 0) {
            out[0]++;
            (void)!write(s, "x", 1);
        } else if (errno == EACCES) {
            out[1]++;
        } else {
            out[2]++;
        }
        close(s);
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < flippers; i++)
        pthread_join(threads[i], 0);
    return 0;
}

/* Addresses and ports in network byte order. */
int race_tcp(uint32_t good_ip, uint16_t good_port, uint32_t evil_ip, uint16_t evil_port,
             int iterations, int flippers, int *out)
{
    memset(&good, 0, sizeof good);
    memset(&evil, 0, sizeof evil);
    good.in.sin_family = evil.in.sin_family = AF_INET;
    good.in.sin_addr.s_addr = good_ip;
    good.in.sin_port = good_port;
    evil.in.sin_addr.s_addr = evil_ip;
    evil.in.sin_port = evil_port;
    size = sizeof(struct sockaddr_in);
    return loop(AF_INET, iterations, flippers, out);
}

int race_unix(const char *good_path, const char *evil_path, int iterations, int flippers, int *out)
{
    memset(&good, 0, sizeof good);
    memset(&evil, 0, sizeof evil);
    good.un.sun_family = evil.un.sun_family = AF_UNIX;
    strncpy(good.un.sun_path, good_path, sizeof good.un.sun_path - 1);
    strncpy(evil.un.sun_path, evil_path, sizeof evil.un.sun_path - 1);
    size = sizeof(struct sockaddr_un);
    return loop(AF_UNIX, iterations, flippers, out);
}
