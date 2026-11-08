#include "ish_proxy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int listener;
static void exact(int fd, void *p, size_t n) {
    while (n) {
        ssize_t r = read(fd, p, n);
        assert(r > 0);
        p = (char *)p + r;
        n -= r;
    }
}
static void *server(void *unused) {
    (void)unused;
    int s = accept(listener, NULL, NULL);
    assert(s >= 0);
    unsigned char b[512];
    exact(s, b, 3);
    assert(b[0] == 5 && b[2] == 2);
    write(s, "\5\2", 2);
    exact(s, b, 2);
    assert(b[0] == 1);
    unsigned n = b[1];
    exact(s, b, n);
    assert(n == 5 && !memcmp(b, "shell", 5));
    exact(s, b, 1);
    n = b[0];
    exact(s, b, n);
    assert(n == 6 && !memcmp(b, "secret", 6));
    write(s, "\1\0", 2);
    exact(s, b, 4);
    assert(b[0] == 5 && b[1] == 1 && b[3] == 4);
    exact(s, b, 18);
    assert(b[15] == 2 && b[16] == 1 && b[17] == 187);
    /* Hold CONNECT success until test checks that POLLOUT is suppressed. */
    usleep(150000);
    write(s, "\5\0\0\1\0\0\0\0\0\0", 10);
    exact(s, b, 4);
    assert(!memcmp(b, "ping", 4));
    write(s, "pong", 4);
    shutdown(s, SHUT_WR);
    close(s);
    return NULL;
}
int main(void) {
    assert(ish_proxy_configure("127.0.0.1", 1, "shell", "secret", false) == 0);
    assert(!ish_proxy_enabled());
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (void *)&a, sizeof(a)) == 0);
    assert(listen(listener, 4) == 0);
    socklen_t al = sizeof(a);
    getsockname(listener, (void *)&a, &al);
    pthread_t thread;
    pthread_create(&thread, NULL, server, NULL);
    assert(ish_proxy_configure("127.0.0.1", ntohs(a.sin_port), "shell", "secret", true) == 0);
    int s = ish_proxy_socket(AF_INET6, SOCK_STREAM, 0);
    assert(s >= 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    struct sockaddr_in6 target = {
        .sin6_family = AF_INET6, .sin6_port = htons(443), .sin6_addr = {{{0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}}};
    assert(ish_proxy_connect(s, (void *)&target, sizeof(target)) == -1 && errno == EINPROGRESS);
    int send_capacity = 1024 * 1024;
    assert(ish_proxy_setsockopt(s, SOL_SOCKET, SO_SNDBUF, &send_capacity, sizeof(send_capacity)) ==
           0);
    struct pollfd p = {.fd = s, .events = POLLOUT};
    assert(poll(&p, 1, 30) == 0);
    assert(poll(&p, 1, 3000) == 1 && (p.revents & POLLOUT));
    int e = -1;
    socklen_t el = sizeof(e);
    assert(ish_proxy_getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &el) == 0 && e == 0);
    struct sockaddr_in6 peer;
    socklen_t pl = sizeof(peer);
    assert(ish_proxy_getpeername(s, (void *)&peer, &pl) == 0 && peer.sin6_port == htons(443));
    assert(ish_proxy_sendto(s, "ping", 4, 0, NULL, 0) == 4);
    p.events = POLLIN;
    assert(poll(&p, 1, 3000) == 1);
    char b[10];
    assert(ish_proxy_recvfrom(s, b, sizeof(b), 0, NULL, NULL) == 4 && !memcmp(b, "pong", 4));
    ish_proxy_close(s);
    pthread_join(thread, NULL);
    close(listener);
    assert(ish_proxy_configure("example.com", 1, "shell", "secret", true) < 0);
    assert(ish_proxy_enabled()); /* bad reconfiguration stays fail closed */
    assert(ish_proxy_configure(NULL, 0, NULL, NULL, false) == 0);
    puts("TCP IPv6 SOCKS auth, nonblocking readiness, SO_ERROR, metadata, relay: PASS");
}
