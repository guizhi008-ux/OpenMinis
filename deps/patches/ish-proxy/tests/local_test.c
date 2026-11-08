#include "ish_proxy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
static void tcp(int family) {
    struct sockaddr_storage a = {0};
    socklen_t n;
    if (family == AF_INET) {
        struct sockaddr_in *v = (void *)&a;
        v->sin_family = family; v->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        n = sizeof(*v);
    } else {
        struct sockaddr_in6 *v = (void *)&a;
        v->sin6_family = family; v->sin6_addr = in6addr_loopback;
        n = sizeof(*v);
    }
    /* Reserve an actual available fixed port, then bind the guest listener. */
    int probe = socket(family, SOCK_STREAM, 0);
    assert(probe >= 0 && !bind(probe, (void *)&a, n));
    assert(!getsockname(probe, (void *)&a, &n)); close(probe);
    int listener = ish_proxy_socket(family, SOCK_STREAM, 0);
#ifdef __linux__
    int ep = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.fd = listener};
    assert(ep >= 0 && !epoll_ctl(ep, EPOLL_CTL_ADD, listener, &event));
#endif
    int one = 1;
    assert(!ish_proxy_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    assert(!ish_proxy_bind(listener, (void *)&a, n));
    assert(!ish_proxy_listen(listener, 4));
    int client = ish_proxy_socket(family, SOCK_STREAM, 0);
#ifdef __linux__
    event = (struct epoll_event){.events = EPOLLIN | EPOLLET, .data.fd = client};
    assert(!epoll_ctl(ep, EPOLL_CTL_ADD, client, &event));
#endif
    assert(!fcntl(client, F_SETFL, O_NONBLOCK));
    assert(ish_proxy_connect(client, (void *)&a, n) < 0 && errno == EINPROGRESS);
    struct pollfd connected = {client, POLLOUT, 0};
    assert(poll(&connected, 1, 3000) == 1);
    int error = -1; socklen_t error_size = sizeof(error);
    assert(!ish_proxy_getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &error_size) && !error);
    assert(!fcntl(client, F_SETFL, 0));
#ifdef __linux__
    assert(epoll_wait(ep, &event, 1, 3000) == 1 && event.data.fd == listener);
#endif
    int accepted = ish_proxy_accept(listener, NULL, NULL);
    assert(accepted >= 0);
    assert(!ish_proxy_setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
    struct sockaddr_storage actual;
    socklen_t size = sizeof(actual);
    assert(!ish_proxy_getsockname(listener, (void *)&actual, &size));
    assert(size == n && !memcmp(&a, &actual, n));
    size = sizeof(actual);
    assert(!ish_proxy_getpeername(client, (void *)&actual, &size));
    assert(size == n && !memcmp(&a, &actual, n));
    assert(!ish_proxy_configure("127.0.0.1", 1, "shell", "changed", true));
    assert(ish_proxy_write(client, "ping", 4) == 4);
    char b[4];
    assert(ish_proxy_read(accepted, b, 4) == 4 && !memcmp(b, "ping", 4));
    struct iovec iov = {"pong", 4};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    assert(ish_proxy_sendmsg(accepted, &msg, 0) == 4);
#ifdef __linux__
    assert(epoll_wait(ep, &event, 1, 3000) == 1 && event.data.fd == client);
    close(ep);
#endif
    iov.iov_base = b;
    assert(ish_proxy_recvmsg(client, &msg, 0) == 4 && !memcmp(b, "pong", 4));
    ish_proxy_close(accepted); ish_proxy_close(client); ish_proxy_close(listener);
}
int main(void) {
    assert(!ish_proxy_configure("127.0.0.1", 1, "shell", "secret", true));
    tcp(AF_INET); tcp(AF_INET6);
    int udp = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!ish_proxy_bind(udp, (void *)&a, sizeof(a)));
    socklen_t size = sizeof(a);
    assert(!ish_proxy_getsockname(udp, (void *)&a, &size) && a.sin_port);
    int client = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    assert(ish_proxy_sendto(client, "x", 1, 0, (void *)&a, sizeof(a)) == 1);
    struct sockaddr_in source; size = sizeof(source); char b;
    assert(ish_proxy_recvfrom(udp, &b, 1, 0, (void *)&source, &size) == 1 && b == 'x');
    assert(ish_proxy_sendto(udp, "y", 1, 0, (void *)&source, size) == 1);
    assert(ish_proxy_read(client, &b, 1) == 1 && b == 'y');
    a.sin_addr.s_addr = htonl(0x08080808);
    assert(ish_proxy_sendto(udp, "x", 1, 0, (void *)&a, sizeof(a)) < 0 && errno == EACCES);
    assert(ish_proxy_connect(udp, (void *)&a, sizeof(a)) < 0 && errno == EACCES);
    ish_proxy_close(client); ish_proxy_close(udp);
    int wild = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    a.sin_addr.s_addr = INADDR_ANY;
    assert(ish_proxy_bind(wild, (void *)&a, sizeof(a)) < 0);
    ish_proxy_close(wild);
    /* Services already bound while proxying was disabled remain available. */
    assert(!ish_proxy_configure(NULL, 0, NULL, NULL, false));
    int old = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    assert(old >= 0 && !ish_proxy_bind(old, (void *)&a, sizeof(a)));
    size = sizeof(a);
    assert(!ish_proxy_getsockname(old, (void *)&a, &size));
    assert(!ish_proxy_configure("127.0.0.1", 1, "shell", "secret", true));
    client = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    assert(ish_proxy_sendto(client, "o", 1, 0, (void *)&a, sizeof(a)) == 1);
    assert(ish_proxy_read(old, &b, 1) == 1 && b == 'o');
    a.sin_addr.s_addr = htonl(0x08080808);
    assert(ish_proxy_sendto(old, "x", 1, 0, (void *)&a, sizeof(a)) < 0 && errno == EACCES);
    struct iovec iov = {"x", 1};
    struct msghdr msg = {.msg_name = &a, .msg_namelen = sizeof(a), .msg_iov = &iov, .msg_iovlen = 1};
    assert(ish_proxy_sendmsg(old, &msg, 0) < 0 && errno == EACCES);
    ish_proxy_close(client); ish_proxy_close(old);
    /* Missing/invalid entry still permits explicitly local services. */
    assert(ish_proxy_configure("invalid", 0, "", "", true) < 0);
    tcp(AF_INET);
    puts("Strict loopback IPv4/IPv6 TCP listeners, accepted I/O, UDP and policy lifecycle: PASS");
}
