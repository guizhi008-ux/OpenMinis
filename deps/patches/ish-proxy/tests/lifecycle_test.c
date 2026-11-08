#include "ish_proxy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
static int listener;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool accepted;
static int connecting_fd;
static struct sockaddr_in connecting_target;
static int connect_error;
static void signal_handler(int n) { (void)n; }
static void *blocking_connect(void *unused) {
    (void)unused;
    assert(ish_proxy_connect(connecting_fd, (void *)&connecting_target,
                             sizeof(connecting_target)) == -1);
    connect_error = errno;
    return NULL;
}
static void *stalled(void *unused) {
    (void)unused;
    int s = accept(listener, NULL, NULL);
    assert(s >= 0);
    pthread_mutex_lock(&lock);
    accepted = true;
    pthread_cond_signal(&changed);
    pthread_mutex_unlock(&lock);
    char b[16];
    while (read(s, b, sizeof(b)) > 0) {
    }
    close(s);
    return NULL;
}
static void wait_accepted(void) {
    pthread_mutex_lock(&lock);
    while (!accepted)
        pthread_cond_wait(&changed, &lock);
    pthread_mutex_unlock(&lock);
}
int main(void) {
    struct sockaddr_in target = {
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x01010101), .sin_port = htons(443)};
    /* Entry refusal must surface at connect, never reach the requested IP. */
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (void *)&local, sizeof(local)) == 0);
    socklen_t n = sizeof(local);
    getsockname(listener, (void *)&local, &n);
    uint16_t port = ntohs(local.sin_port);
    close(listener);
    assert(!ish_proxy_configure("127.0.0.1", port, "shell", "secret", true));
    int s = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    assert(ish_proxy_connect(s, (void *)&target, sizeof(target)) < 0 && errno == ECONNREFUSED);
    ish_proxy_close(s);
    /* Nonblocking refusal is reported once through SO_ERROR. */
    s = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    assert(ish_proxy_connect(s, (void *)&target, sizeof(target)) < 0 && errno == EINPROGRESS);
    struct pollfd refused = {s, POLLOUT, 0};
    assert(poll(&refused, 1, 3000) == 1);
    int error = 0;
    socklen_t error_len = sizeof(error);
    assert(!ish_proxy_getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &error_len) &&
           error == ECONNREFUSED);
    assert(!ish_proxy_getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &error_len) && error == 0);
    ish_proxy_close(s);
    /* An in-flight authenticated connect is cancellable by policy switch. */
    listener = socket(AF_INET, SOCK_STREAM, 0);
    local.sin_port = 0;
    assert(bind(listener, (void *)&local, sizeof(local)) == 0);
    assert(listen(listener, 1) == 0);
    n = sizeof(local);
    getsockname(listener, (void *)&local, &n);
    port = ntohs(local.sin_port);
    pthread_t worker;
    pthread_create(&worker, NULL, stalled, NULL);
    assert(!ish_proxy_configure("127.0.0.1", port, "shell", "secret", true));
    s = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    assert(ish_proxy_connect(s, (void *)&target, sizeof(target)) < 0 && errno == EINPROGRESS);
    wait_accepted();
    assert(!ish_proxy_configure("127.0.0.1", port, "shell", "new-secret", true));
    struct pollfd p = {s, POLLOUT, 0};
    assert(poll(&p, 1, 1000) == 1);
    assert(ish_proxy_sendto(s, "x", 1, 0, NULL, 0) < 0 && errno == ECONNRESET);
    ish_proxy_close(s);
    pthread_join(worker, NULL);
    close(listener);
    /* Host SIGUSR1 wake interrupts a blocking guest connect without waiting
       for the remote entry handshake to finish. */
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1, &action, NULL));
    listener = socket(AF_INET, SOCK_STREAM, 0);
    local.sin_port = 0;
    assert(!bind(listener, (void *)&local, sizeof(local)));
    assert(!listen(listener, 1));
    n = sizeof(local);
    getsockname(listener, (void *)&local, &n);
    accepted = false;
    pthread_create(&worker, NULL, stalled, NULL);
    assert(!ish_proxy_configure("127.0.0.1", ntohs(local.sin_port), "shell", "secret", true));
    connecting_fd = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    connecting_target = target;
    pthread_t caller;
    pthread_create(&caller, NULL, blocking_connect, NULL);
    wait_accepted();
    pthread_kill(caller, SIGUSR1);
    pthread_join(caller, NULL);
    assert(connect_error == EINTR);
    ish_proxy_close(connecting_fd);
    pthread_join(worker, NULL);
    close(listener);
    /* Existing direct guest internet sockets cannot survive enable. AF_UNIX
       remains usable because it carries local guest IPC. */
    assert(!ish_proxy_configure(NULL, 0, NULL, NULL, false));
    int d = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    assert(d >= 0);
    assert(!ish_proxy_configure("127.0.0.1", port, "shell", "secret", true));
    assert(ish_proxy_sendto(d, "x", 1, 0, (void *)&target, sizeof(target)) < 0 &&
           errno == ENETDOWN);
    ish_proxy_close(d);
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    assert(ish_proxy_write(pair[0], "x", 1) == 1);
    char b;
    assert(ish_proxy_read(pair[1], &b, 1) == 1 && b == 'x');
    ish_proxy_close(pair[0]);
    ish_proxy_close(pair[1]);
    assert(ish_proxy_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) < 0 && errno == EPROTONOSUPPORT);
    ish_proxy_configure(NULL, 0, NULL, NULL, false);
    puts("Blocking refusal, in-flight cancellation, policy switch, old direct socket denial, Unix "
         "IPC, raw rejection: PASS");
}
