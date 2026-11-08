#include "ish_proxy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
static void failure_wakes(bool reconfigure) {
    int probe = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(probe >= 0 && !bind(probe, (void *)&a, sizeof(a)));
    socklen_t n = sizeof(a);
    assert(!getsockname(probe, (void *)&a, &n));
    if (reconfigure) assert(!listen(probe, 1));
    else close(probe);
    assert(!ish_proxy_configure("127.0.0.1", ntohs(a.sin_port), "shell", "secret", true));
    int fd = ish_proxy_socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef __linux__
    int ep = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET, .data.fd = fd};
    assert(ep >= 0 && !epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event));
#endif
    if (reconfigure) {
        assert(!ish_proxy_configure("127.0.0.1", ntohs(a.sin_port), "shell", "new", true));
        close(probe);
    }
#ifdef __linux__
    assert(epoll_wait(ep, &event, 1, 3000) == 1);
    assert(event.events & (EPOLLOUT | EPOLLERR | EPOLLHUP));
    close(ep);
#else
    struct pollfd p = {fd, POLLOUT, 0};
    assert(poll(&p, 1, 3000) == 1);
#endif
    int error = 0; n = sizeof(error);
    assert(!ish_proxy_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n));
    assert(error == (reconfigure ? ECONNRESET : ECONNREFUSED));
    a.sin_addr.s_addr = htonl(0x08080808);
    assert(ish_proxy_sendto(fd, "x", 1, 0, (void *)&a, sizeof(a)) < 0);
    ish_proxy_close(fd);
}
int main(void) {
    failure_wakes(false);
    failure_wakes(true);
    puts("UDP refusal and policy cancellation wake poll/EPOLLET with SO_ERROR: PASS");
}
