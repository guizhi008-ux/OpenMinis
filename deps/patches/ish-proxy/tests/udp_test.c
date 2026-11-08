#include "ish_proxy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
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
    int controls[2], relays[2];
    unsigned char b[1024];
    for (int i = 0; i < 2; i++) {
        controls[i] = accept(listener, NULL, NULL);
        assert(controls[i] >= 0);
        exact(controls[i], b, 3);
        assert(b[0] == 5);
        usleep(150000);
        write(controls[i], "\5\2", 2);
        exact(controls[i], b, 2);
        unsigned n = b[1];
        exact(controls[i], b, n);
        assert(n == (i ? 9 : 5) && !memcmp(b, i ? "shell~dns" : "shell", n));
        exact(controls[i], b, 1);
        n = b[0];
        exact(controls[i], b, n);
        write(controls[i], "\1\0", 2);
        exact(controls[i], b, 10);
        assert(b[1] == 3 && b[3] == 1);
        relays[i] = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        assert(bind(relays[i], (void *)&a, sizeof(a)) == 0);
        socklen_t al = sizeof(a);
        getsockname(relays[i], (void *)&a, &al);
        unsigned char reply[10] = {5, 0, 0, 1, 127, 0, 0, 1};
        memcpy(reply + 8, &a.sin_port, 2);
        write(controls[i], reply, 10);
    }
    struct sockaddr_storage source;
    socklen_t sl = sizeof(source);
    ssize_t n = recvfrom(relays[1], b, sizeof(b), 0, (void *)&source, &sl);
    assert(n == 27 && b[3] == 4 && b[22] == 'q' && !memcmp(b + 22, "query", 5));
    /* Source endpoint is the DNS destination represented in SOCKS UDP header. */
    assert(sendto(relays[1], b, n, 0, (void *)&source, sl) == n);
    struct pollfd p = {.fd = controls[1], .events = POLLIN};
    assert(poll(&p, 1, 3000) > 0);
    for (int i = 0; i < 2; i++) {
        close(controls[i]);
        close(relays[i]);
    }
    return NULL;
}
int main(void) {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (void *)&a, sizeof(a)) == 0);
    assert(listen(listener, 2) == 0);
    socklen_t al = sizeof(a);
    getsockname(listener, (void *)&a, &al);
    pthread_t thread;
    pthread_create(&thread, NULL, server, NULL);
    assert(ish_proxy_configure("127.0.0.1", ntohs(a.sin_port), "shell", "secret", true) == 0);
    int s = ish_proxy_socket(AF_INET6, SOCK_DGRAM, 0);
    assert(s >= 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    struct pollfd writable = {s, POLLOUT, 0};
    assert(poll(&writable, 1, 30) == 0);
#ifdef __linux__
    int ep = epoll_create1(0);
    assert(ep >= 0);
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET, .data.fd = s};
    assert(!epoll_ctl(ep, EPOLL_CTL_ADD, s, &event));
    assert(epoll_wait(ep, &event, 1, 30) == 0);
    /* No write has occurred: handshake must progress and generate an edge. */
    assert(epoll_wait(ep, &event, 1, 3000) == 1 && (event.events & EPOLLOUT));
    close(ep);
#else
    assert(poll(&writable, 1, 3000) == 1 && (writable.revents & POLLOUT));
#endif
    fcntl(s, F_SETFL, 0);
    struct sockaddr_in6 target = {
        .sin6_family = AF_INET6, .sin6_port = htons(53), .sin6_addr = {{{0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}}};
    struct iovec out[2] = {{"qu", 2}, {"ery", 3}};
    struct msghdr msg = {
        .msg_name = &target, .msg_namelen = sizeof(target), .msg_iov = out, .msg_iovlen = 2};
    assert(ish_proxy_sendmsg(s, &msg, 0) == 5);
    struct pollfd p = {s, POLLIN, 0};
    assert(poll(&p, 1, 3000) == 1);
    char b[5];
    struct iovec in[2] = {{b, 2}, {b + 2, 3}};
    struct sockaddr_in6 source;
    msg = (struct msghdr){
        .msg_name = &source, .msg_namelen = sizeof(source), .msg_iov = in, .msg_iovlen = 2};
    assert(ish_proxy_recvmsg(s, &msg, MSG_PEEK) == 5 && !memcmp(b, "query", 5));
    assert(source.sin6_family == AF_INET6 && source.sin6_port == htons(53));
    in[0].iov_len = 1;
    in[1].iov_len = 1;
    assert(ish_proxy_recvmsg(s, &msg, 0) == 2 && (msg.msg_flags & MSG_TRUNC));
    fcntl(s, F_SETFL, O_NONBLOCK);
    assert(ish_proxy_recvfrom(s, b, 5, 0, NULL, NULL) < 0 && errno == EAGAIN);
    ish_proxy_close(s);
    pthread_join(thread, NULL);
    close(listener);
    ish_proxy_configure(NULL, 0, NULL, NULL, false);
    puts("UDP SOCKS auth, shell~dns lane, IPv6 source, sendmsg/recvmsg scatter, PEEK/TRUNC, "
         "nonblocking: PASS");
}
