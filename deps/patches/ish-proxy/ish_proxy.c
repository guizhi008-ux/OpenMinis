/* Guest-only transport. No process-wide symbol interposition. */
#include "ish_proxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define MAX_PACKET 65507
struct config {
    bool enabled;
    uint16_t port;
    char user[256], pass[256];
};
struct packet {
    struct sockaddr_storage addr;
    socklen_t len;
    unsigned char bytes[MAX_PACKET];
};
struct proxy_socket {
    int fd, peer, remote, control[2], udp[2], type, domain, native;
    bool local, converting, listener, notified;
    bool started, cancel, done;
    int error, terminal_error;
    int deferred_sendbuf;
    bool has_deferred_sendbuf;
    size_t padding;
    struct config config;
    struct sockaddr_storage target;
    socklen_t target_len;
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned refs;
    struct proxy_socket *next;
};
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct proxy_socket *sockets;
static struct config active;
static _Atomic(ish_proxy_interrupt_hook) interrupt_hook;
void ish_proxy_set_interrupt_hook(ish_proxy_interrupt_hook hook) {
    atomic_store(&interrupt_hook, hook);
}
static bool interrupted(void) {
    ish_proxy_interrupt_hook hook = atomic_load(&interrupt_hook);
    return hook && hook();
}
static unsigned long generation;
struct direct_socket {
    int fd;
    struct direct_socket *next;
};
static struct direct_socket *direct_sockets;
static bool loopback(const struct sockaddr *a, socklen_t n) {
    if (!a) return false;
    if (a->sa_family == AF_INET && n >= sizeof(struct sockaddr_in))
        return (ntohl(((const struct sockaddr_in *)a)->sin_addr.s_addr) >> 24) == 127;
    if (a->sa_family == AF_INET6 && n >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v = (const void *)a;
        return !v->sin6_scope_id && IN6_IS_ADDR_LOOPBACK(&v->sin6_addr);
    }
    return false;
}
static bool local_direct(int fd) {
    struct sockaddr_storage a;
    socklen_t n = sizeof(a);
    if (getsockname(fd, (void *)&a, &n) < 0 || !loopback((void *)&a, n)) return false;
    n = sizeof(a);
    return getpeername(fd, (void *)&a, &n) < 0 || loopback((void *)&a, n);
}
static bool deny_direct(int fd) {
    if (!ish_proxy_enabled())
        return false;
    struct sockaddr_storage a;
    socklen_t n = sizeof(a);
    return getsockname(fd, (void *)&a, &n) < 0 ||
        (a.ss_family != AF_UNIX && !local_direct(fd));
}
static int fail(int e) {
    errno = e;
    return -1;
}
bool ish_proxy_enabled(void) {
    pthread_mutex_lock(&registry_lock);
    bool e = active.enabled;
    pthread_mutex_unlock(&registry_lock);
    return e;
}
static struct proxy_socket *acquire(int fd) {
    pthread_mutex_lock(&registry_lock);
    struct proxy_socket *s = sockets;
    while (s && s->fd != fd)
        s = s->next;
    if (s)
        s->refs++;
    pthread_mutex_unlock(&registry_lock);
    return s;
}
static void release(struct proxy_socket *s) {
    int saved = errno;
    pthread_mutex_lock(&registry_lock);
    s->refs--;
    pthread_mutex_unlock(&registry_lock);
    errno = saved;
}
static void cancel(struct proxy_socket *s) {
    pthread_mutex_lock(&s->lock);
    s->cancel = true;
    s->error = ECONNRESET;
    s->terminal_error = ECONNRESET;
    if (s->type == SOCK_DGRAM) {
        unsigned char b[sizeof(struct packet)];
        while (recv(s->peer, b, sizeof(b), MSG_DONTWAIT) >= 0) {}
    }
    shutdown(s->peer, SHUT_RDWR);
    if (s->remote >= 0)
        shutdown(s->remote, SHUT_RDWR);
    if (s->native >= 0)
        shutdown(s->native, SHUT_RDWR);
    for (int i = 0; i < 2; i++)
        if (s->control[i] >= 0)
            shutdown(s->control[i], SHUT_RDWR);
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lock);
}
int ish_proxy_configure(const char *host, uint16_t port, const char *user, const char *pass,
                        bool enabled) {
    struct config c = {.enabled = enabled, .port = port};
    bool valid = !enabled ||
                 (host && !strcmp(host, "127.0.0.1") && port && user && pass && strlen(user) > 0 &&
                  strlen(user) <= 250 && strlen(pass) > 0 && strlen(pass) <= 255);
    pthread_mutex_lock(&registry_lock);
    /* Any policy transition invalidates old sockets, including direct sockets at
       the guest ABI integration layer. Invalid policy remains enabled/closed. */
    for (struct proxy_socket *s = sockets; s; s = s->next)
        if (!s->local) cancel(s);
    for (struct direct_socket *d = direct_sockets; d; d = d->next)
        if (!local_direct(d->fd)) shutdown(d->fd, SHUT_RDWR);
    generation++;
    if (valid && enabled) {
        memcpy(c.user, user, strlen(user) + 1);
        memcpy(c.pass, pass, strlen(pass) + 1);
    }
    active = c;
    pthread_mutex_unlock(&registry_lock);
    return valid ? 0 : -EINVAL;
}
static bool cancelled(struct proxy_socket *s) {
    pthread_mutex_lock(&s->lock);
    bool c = s->cancel;
    pthread_mutex_unlock(&s->lock);
    return c;
}
static int waitfd(struct proxy_socket *s, int fd, short ev) {
    for (int i = 0; i < 300; i++) {
        if (cancelled(s))
            return fail(ECANCELED);
        struct pollfd p = {fd, ev, 0};
        int r = poll(&p, 1, 100);
        if (r > 0)
            return 0;
        if (r < 0 && errno != EINTR)
            return -1;
    }
    return fail(ETIMEDOUT);
}
static int transfer(struct proxy_socket *s, int fd, void *data, size_t n, bool writing) {
    unsigned char *p = data;
    while (n) {
        ssize_t r = writing ? send(fd, p, n, MSG_NOSIGNAL) : recv(fd, p, n, 0);
        if (r > 0) {
            p += r;
            n -= r;
            continue;
        }
        if (!r)
            return fail(ECONNRESET);
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        if (waitfd(s, fd, writing ? POLLOUT : POLLIN) < 0)
            return -1;
    }
    return 0;
}
static int address_encode(const struct sockaddr *a, socklen_t len, unsigned char *b) {
    if (a && a->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v = (void *)a;
        b[0] = 1;
        memcpy(b + 1, &v->sin_addr, 4);
        memcpy(b + 5, &v->sin_port, 2);
        return 7;
    }
    if (a && a->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v = (void *)a;
        if (v->sin6_scope_id)
            return fail(EOPNOTSUPP);
        b[0] = 4;
        memcpy(b + 1, &v->sin6_addr, 16);
        memcpy(b + 17, &v->sin6_port, 2);
        return 19;
    }
    return fail(EAFNOSUPPORT);
}
static int address_decode(const unsigned char *b, size_t n, struct sockaddr_storage *a,
                          socklen_t *len) {
    memset(a, 0, sizeof(*a));
    if (n >= 7 && b[0] == 1) {
        struct sockaddr_in *v = (void *)a;
        v->sin_family = AF_INET;
        memcpy(&v->sin_addr, b + 1, 4);
        memcpy(&v->sin_port, b + 5, 2);
        *len = sizeof(*v);
        return 7;
    }
    if (n >= 19 && b[0] == 4) {
        struct sockaddr_in6 *v = (void *)a;
        v->sin6_family = AF_INET6;
        memcpy(&v->sin6_addr, b + 1, 16);
        memcpy(&v->sin6_port, b + 17, 2);
        *len = sizeof(*v);
        return 19;
    }
    return fail(EPROTO);
}
static int socks(struct proxy_socket *s, int command, const struct sockaddr *target, socklen_t len,
                 bool dns, struct sockaddr_storage *bound, socklen_t *blen, int slot) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    pthread_mutex_lock(&s->lock);
    if (slot < 0)
        s->remote = fd;
    else
        s->control[slot] = fd;
    pthread_mutex_unlock(&s->lock);
    struct sockaddr_in entry = {.sin_family = AF_INET,
                                .sin_port = htons(s->config.port),
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(fd, (void *)&entry, sizeof(entry)) < 0 && errno != EINPROGRESS)
        return -1;
    if (waitfd(s, fd, POLLOUT) < 0)
        return -1;
    int e = 0;
    socklen_t el = sizeof(e);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) < 0 || e)
        return fail(e ? e : errno);
    unsigned char b[520] = {5, 1, 2};
    if (transfer(s, fd, b, 3, true) < 0 || transfer(s, fd, b, 2, false) < 0)
        return -1;
    if (b[0] != 5 || b[1] != 2)
        return fail(EACCES);
    size_t un = strlen(s->config.user), pn = strlen(s->config.pass);
    b[0] = 1;
    b[1] = un + (dns ? 4 : 0);
    memcpy(b + 2, s->config.user, un);
    if (dns)
        memcpy(b + 2 + un, "~dns", 4);
    un = b[1];
    b[2 + un] = pn;
    memcpy(b + 3 + un, s->config.pass, pn);
    if (transfer(s, fd, b, 3 + un + pn, true) < 0 || transfer(s, fd, b, 2, false) < 0)
        return -1;
    if (b[0] != 1 || b[1])
        return fail(EACCES);
    b[0] = 5;
    b[1] = command;
    b[2] = 0;
    int n = address_encode(target, len, b + 3);
    if (n < 0)
        return -1;
    if (transfer(s, fd, b, 3 + n, true) < 0 || transfer(s, fd, b, 4, false) < 0)
        return -1;
    if (b[0] != 5 || b[2] || b[1])
        return fail(b[1] == 5 ? ECONNREFUSED : b[1] == 2 ? EACCES : EHOSTUNREACH);
    int size = b[3] == 1 ? 6 : b[3] == 4 ? 18 : 0;
    if (!size)
        return fail(EPROTO);
    b[0] = b[3];
    if (transfer(s, fd, b + 1, size, false) < 0)
        return -1;
    if (bound && address_decode(b, size + 1, bound, blen) < 0)
        return -1;
    return fd;
}
static void completion(struct proxy_socket *s, int error) {
    pthread_mutex_lock(&s->lock);
    if (s->cancel) error = ECONNRESET;
    if (!error && s->has_deferred_sendbuf) {
        setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &s->deferred_sendbuf, sizeof(s->deferred_sendbuf));
        s->has_deferred_sendbuf = false;
    }
    s->done = true;
    s->error = error;
    s->terminal_error = error;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->lock);
}
static void tcp_relay(struct proxy_socket *s) {
    unsigned char to_remote[65536], to_guest[65536];
    size_t rn = 0, gn = 0;
    bool leof = false, reof = false;
    while (!cancelled(s)) {
        if (leof && !rn)
            shutdown(s->remote, SHUT_WR);
        if (reof && !gn)
            shutdown(s->peer, SHUT_WR);
        if (leof && reof && !rn && !gn)
            break;
        struct pollfd p[2] = {
            {s->peer, (!leof && rn < sizeof(to_remote) ? POLLIN : 0) | (gn ? POLLOUT : 0), 0},
            {s->remote, (!reof && gn < sizeof(to_guest) ? POLLIN : 0) | (rn ? POLLOUT : 0), 0}};
        if (poll(p, 2, 100) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (!leof && rn < sizeof(to_remote) && (p[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(s->peer, to_remote + rn, sizeof(to_remote) - rn, 0);
            if (n > 0)
                rn += n;
            else if (!n)
                leof = true;
            else if (errno != EAGAIN && errno != EINTR)
                break;
        }
        if (!reof && gn < sizeof(to_guest) && (p[1].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(s->remote, to_guest + gn, sizeof(to_guest) - gn, 0);
            if (n > 0)
                gn += n;
            else if (!n)
                reof = true;
            else if (errno != EAGAIN && errno != EINTR)
                break;
        }
        if (rn && (p[1].revents & POLLOUT)) {
            ssize_t n = send(s->remote, to_remote, rn, MSG_NOSIGNAL);
            if (n > 0) {
                rn -= n;
                memmove(to_remote, to_remote + n, rn);
            } else if (n < 0 && errno != EAGAIN && errno != EINTR)
                break;
        }
        if (gn && (p[0].revents & POLLOUT)) {
            ssize_t n = send(s->peer, to_guest, gn, MSG_NOSIGNAL);
            if (n > 0) {
                gn -= n;
                memmove(to_guest, to_guest + n, gn);
            } else if (n < 0 && errno != EAGAIN && errno != EINTR)
                break;
        }
    }
}
static int port_of(const struct sockaddr_storage *a);
static void *tcp_worker(void *data) {
    struct proxy_socket *s = data;
    int r;
    if (s->local) {
        s->remote = dup(s->native);
        r = s->remote < 0 ? -1 : connect(s->remote, (void *)&s->target, s->target_len);
        if (r < 0 && errno == EINPROGRESS) {
            r = waitfd(s, s->remote, POLLOUT);
            if (!r) {
                int e = 0; socklen_t n = sizeof(e);
                if (getsockopt(s->remote, SOL_SOCKET, SO_ERROR, &e, &n) < 0 || e)
                    r = fail(e ? e : errno);
            }
        }
    } else {
        r = socks(s, 1, (void *)&s->target, s->target_len,
                  port_of(&s->target) == 53, NULL, NULL, -1);
    }
    if (r < 0) {
        int e = errno;
        completion(s, e);
        shutdown(s->peer, SHUT_RDWR);
        return NULL;
    }
    /* State precedes the kernel writable edge created by draining padding. */
    completion(s, 0);
    unsigned char buf[4096];
    size_t left = s->padding;
    while (left) {
        ssize_t n = recv(s->peer, buf, left < sizeof(buf) ? left : sizeof(buf), 0);
        if (n <= 0) {
            completion(s, ECONNRESET);
            shutdown(s->peer, SHUT_RDWR);
            return NULL;
        }
        left -= n;
    }
    tcp_relay(s);
    shutdown(s->peer, SHUT_RDWR);
    return NULL;
}
static int ready(struct proxy_socket *, int, int);
static void *local_udp_worker(void *);
int ish_proxy_socket(int domain, int type, int protocol) {
    pthread_mutex_lock(&registry_lock);
    struct config c = active;
    unsigned long epoch = generation;
    if (!c.enabled || (domain != AF_INET && domain != AF_INET6)) {
        int fd = socket(domain, type, protocol);
        if (fd >= 0 && (domain == AF_INET || domain == AF_INET6)) {
            struct direct_socket *d = malloc(sizeof(*d));
            if (!d) {
                close(fd);
                fd = fail(ENOMEM);
            } else {
                d->fd = fd;
                d->next = direct_sockets;
                direct_sockets = d;
            }
        }
        pthread_mutex_unlock(&registry_lock);
        return fd;
    }
    pthread_mutex_unlock(&registry_lock);
    if ((type != SOCK_STREAM && type != SOCK_DGRAM) ||
        (protocol && protocol != (type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP)))
        return fail(EPROTONOSUPPORT);
    int pair[2];
    if (socketpair(AF_UNIX, type, 0, pair) < 0)
        return -1;
    struct proxy_socket *s = calloc(1, sizeof(*s));
    if (!s) {
        close(pair[0]);
        close(pair[1]);
        return fail(ENOMEM);
    }
    if (type == SOCK_DGRAM) {
        int capacity = 256 * 1024;
        for (int i = 0; i < 2; i++) {
            setsockopt(pair[i], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity));
            setsockopt(pair[i], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity));
        }
    }
    /* Dormant native socket retains options until an explicitly loopback-only
       bind/connect selects local service semantics. It never sends externally. */
    s->native = socket(domain, type, protocol);
    if (s->native < 0) {
        int e = errno;
        close(pair[0]); close(pair[1]); free(s);
        return fail(e);
    }
    s->fd = pair[0];
    s->peer = pair[1];
    s->remote = -1;
    s->control[0] = s->control[1] = s->udp[0] = s->udp[1] = -1;
    s->type = type;
    s->domain = domain;
    s->config = c;
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->changed, NULL);
    fcntl(s->peer, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(s->peer, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    setsockopt(s->fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    setsockopt(s->native, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    if (type == SOCK_DGRAM) {
        /* Gate native poll/epoll/kqueue readiness before exposing the fd. */
        unsigned char padding[4096] = {0};
        int flags = fcntl(s->fd, F_GETFL);
        fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);
        while (send(s->fd, padding, sizeof(padding), MSG_NOSIGNAL) > 0)
            s->padding++;
        fcntl(s->fd, F_SETFL, flags);
    }
    pthread_mutex_lock(&registry_lock);
    s->next = sockets;
    sockets = s;
    if (epoch != generation)
        cancel(s);
    pthread_mutex_unlock(&registry_lock);
    /* Authentication must progress even when the caller polls before sending. */
    if (type == SOCK_DGRAM && ready(s, s->fd, MSG_DONTWAIT) < 0 && errno != EAGAIN) {
        int e = errno;
        completion(s, e);
        unsigned char b[sizeof(struct packet)];
        while (recv(s->peer, b, sizeof(b), MSG_DONTWAIT) >= 0) {}
    }
    return s->fd;
}
static int make_local(struct proxy_socket *s) {
    pthread_mutex_lock(&registry_lock);
    if (!s->local) {
        if (s->type == SOCK_STREAM && s->started) {
            pthread_mutex_unlock(&registry_lock);
            return fail(EISCONN);
        }
        /* Do not replace/shutdown the guest open-file description: poll and
           epoll registrations can precede local bind/connect. Stop only the
           eager SOCKS UDP worker, retaining the readiness pair. */
        pthread_mutex_lock(&s->lock);
        s->converting = true;
        s->cancel = true;
        for (int i = 0; i < 2; i++)
            if (s->control[i] >= 0) shutdown(s->control[i], SHUT_RDWR);
        pthread_mutex_unlock(&s->lock);
        if (s->started) pthread_join(s->worker, NULL);
        for (int i = 0; i < 2; i++) {
            if (s->control[i] >= 0) close(s->control[i]);
            if (s->udp[i] >= 0) close(s->udp[i]);
            s->control[i] = s->udp[i] = -1;
        }
        fcntl(s->native, F_SETFL, O_NONBLOCK);
        pthread_mutex_lock(&s->lock);
        s->local = true;
        s->converting = false;
        s->cancel = false;
        s->started = false;
        s->done = false;
        s->error = 0;
        s->terminal_error = 0;
        s->padding = 0;
        if (s->type == SOCK_DGRAM) {
            /* Publish local readiness before releasing the datagram gate. */
            s->done = true;
            s->started = true;
            unsigned char b[sizeof(struct packet)];
            while (recv(s->peer, b, sizeof(b), MSG_DONTWAIT) >= 0) {}
            int e = pthread_create(&s->worker, NULL, local_udp_worker, s);
            if (e) {
                s->started = false;
                s->error = s->terminal_error = e;
                pthread_mutex_unlock(&s->lock);
                pthread_mutex_unlock(&registry_lock);
                return fail(e);
            }
        }
        pthread_mutex_unlock(&s->lock);
    }
    pthread_mutex_unlock(&registry_lock);
    return 0;
}
int ish_proxy_connect(int fd, const struct sockaddr *a, socklen_t len) {
    struct proxy_socket *s = acquire(fd);
    if (!s) {
        if (deny_direct(fd)) return fail(ENETDOWN);
        if (ish_proxy_enabled() && local_direct(fd) && !loopback(a, len))
            return fail(EACCES);
        return connect(fd, a, len);
    }
    if (s->local || loopback(a, len)) {
        if ((!loopback(a, len) &&
             !(a && a->sa_family == AF_UNSPEC && s->type == SOCK_DGRAM)) ||
            make_local(s) < 0) {
            release(s); return fail(EACCES);
        }
        if (s->type == SOCK_DGRAM) {
            int r = connect(s->native, a, len);
            if (r < 0) { release(s); return r; }
        }
    }
    if (a && a->sa_family == AF_UNSPEC && s->type == SOCK_DGRAM) {
        pthread_mutex_lock(&s->lock);
        s->target_len = 0;
        memset(&s->target, 0, sizeof(s->target));
        pthread_mutex_unlock(&s->lock);
        release(s);
        return 0;
    }
    if (len > sizeof(s->target)) {
        release(s);
        return fail(EINVAL);
    }
    if (!s->local && (!s->config.port || !s->config.user[0])) {
        release(s);
        return fail(ENETDOWN);
    }
    unsigned char encoded[19];
    if (address_encode(a, len, encoded) < 0) {
        release(s);
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    if (s->cancel) {
        pthread_mutex_unlock(&s->lock);
        release(s);
        return fail(ECONNRESET);
    }
    if (s->type == SOCK_DGRAM) {
        memcpy(&s->target, a, len);
        s->target_len = len;
        pthread_mutex_unlock(&s->lock);
        release(s);
        return 0;
    }
    if (s->started) {
        int e = s->done ? (s->error ? s->error : EISCONN) : EALREADY;
        pthread_mutex_unlock(&s->lock);
        release(s);
        return fail(e);
    }
    memcpy(&s->target, a, len);
    s->target_len = len;
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    unsigned char padding[4096] = {0};
    ssize_t n;
    while ((n = send(fd, padding, sizeof(padding), MSG_NOSIGNAL)) > 0)
        s->padding += n;
    fcntl(fd, F_SETFL, flags);
    s->started = true;
    int e = pthread_create(&s->worker, NULL, tcp_worker, s);
    if (e) {
        s->started = false;
        pthread_mutex_unlock(&s->lock);
        release(s);
        return fail(e);
    }
    if (flags & O_NONBLOCK) {
        pthread_mutex_unlock(&s->lock);
        release(s);
        return fail(EINPROGRESS);
    }
    pthread_mutex_unlock(&s->lock);
    struct pollfd pending = {fd, POLLOUT, 0};
    int result = poll(&pending, 1, -1);
    pthread_mutex_lock(&s->lock);
    if (result < 0) {
        int saved = errno;
        pthread_mutex_unlock(&s->lock);
        release(s);
        return fail(saved);
    }
    while (!s->done && !s->cancel)
        pthread_cond_wait(&s->changed, &s->lock);
    e = s->error;
    pthread_mutex_unlock(&s->lock);
    release(s);
    return e ? fail(e) : 0;
}
static int port_of(const struct sockaddr_storage *a) {
    return a->ss_family == AF_INET ? ntohs(((const struct sockaddr_in *)a)->sin_port)
                                   : ntohs(((const struct sockaddr_in6 *)a)->sin6_port);
}
static void *local_udp_worker(void *data) {
    struct proxy_socket *s = data;
    completion(s, 0);
    while (!cancelled(s)) {
        struct pollfd p[2] = {{s->peer, POLLIN, 0}, {s->native, POLLIN, 0}};
        if (poll(p, 2, 100) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        struct packet packet;
        if (p[0].revents & POLLIN) {
            ssize_t n = recv(s->peer, &packet, sizeof(packet), 0);
            if (n >= (ssize_t)offsetof(struct packet, bytes) &&
                loopback((void *)&packet.addr, packet.len))
                sendto(s->native, packet.bytes, n - offsetof(struct packet, bytes),
                       MSG_NOSIGNAL, (void *)&packet.addr, packet.len);
        }
        if (p[1].revents & POLLIN) {
            packet.len = sizeof(packet.addr);
            ssize_t n = recvfrom(s->native, packet.bytes, sizeof(packet.bytes), 0,
                                 (void *)&packet.addr, &packet.len);
            if (n >= 0 && loopback((void *)&packet.addr, packet.len))
                send(s->peer, &packet, offsetof(struct packet, bytes) + n, MSG_NOSIGNAL);
        }
    }
    return NULL;
}
static void *listener_worker(void *data) {
    struct proxy_socket *s = data;
    while (!cancelled(s)) {
        pthread_mutex_lock(&s->lock);
        bool notified = s->notified;
        pthread_mutex_unlock(&s->lock);
        struct pollfd p = {s->native, notified ? 0 : POLLIN, 0};
        if (poll(&p, 1, 100) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (p.revents & POLLIN) {
            pthread_mutex_lock(&s->lock);
            if (!s->notified && send(s->peer, "L", 1, MSG_NOSIGNAL) == 1)
                s->notified = true;
            pthread_mutex_unlock(&s->lock);
        }
    }
    return NULL;
}
static void *udp_worker(void *data) {
    struct proxy_socket *s = data;
    struct sockaddr_in zero = {.sin_family = AF_INET};
    for (int i = 0; i < 2; i++) {
        struct sockaddr_storage bound;
        socklen_t blen;
        if (socks(s, 3, (void *)&zero, sizeof(zero), i == 1, &bound, &blen, i) < 0)
            goto error;
        if (bound.ss_family != AF_INET || !((struct sockaddr_in *)&bound)->sin_port) {
            errno = EPROTO;
            goto error;
        }
        /* A local SOCKS entry must advertise its loopback relay. Never send a
           datagram to an arbitrary address supplied by a compromised entry. */
        struct sockaddr_in *v = (void *)&bound;
        if (v->sin_addr.s_addr != 0 && v->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            errno = EPROTO;
            goto error;
        }
        v->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        s->udp[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (s->udp[i] < 0)
            goto error;
        fcntl(s->udp[i], F_SETFL, O_NONBLOCK);
        if (connect(s->udp[i], (void *)&bound, blen) < 0)
            goto error;
    }
    /* Publish success before freeing queue capacity: a woken edge-triggered
       sender must never see a still-pending handshake after the writable edge. */
    completion(s, 0);
    unsigned char padding[4096];
    for (size_t i = 0; i < s->padding; i++)
        if (recv(s->peer, padding, sizeof(padding), 0) < 0)
            goto error;
    while (!cancelled(s)) {
        struct pollfd p[5] = {{s->peer, POLLIN, 0},
                              {s->udp[0], POLLIN, 0},
                              {s->udp[1], POLLIN, 0},
                              {s->control[0], POLLIN, 0},
                              {s->control[1], POLLIN, 0}};
        if (poll(p, 5, 100) < 0) {
            if (errno == EINTR)
                continue;
            goto error;
        }
        if (p[3].revents || p[4].revents) {
            errno = ECONNRESET;
            goto error;
        }
        if (p[0].revents & POLLIN) {
            struct packet packet;
            ssize_t n = recv(s->peer, &packet, sizeof(packet), 0);
            if (n >= (ssize_t)offsetof(struct packet, bytes)) {
                unsigned char wire[MAX_PACKET + 22] = {0};
                int h = address_encode((void *)&packet.addr, packet.len, wire + 3);
                size_t payload = n - offsetof(struct packet, bytes);
                if (h > 0 && payload + 3 + h <= 65507) {
                    memcpy(wire + 3 + h, packet.bytes, payload);
                    int lane = port_of(&packet.addr) == 53;
                    send(s->udp[lane], wire, payload + 3 + h, MSG_NOSIGNAL);
                }
            }
        }
        for (int i = 0; i < 2; i++)
            if (p[1 + i].revents & POLLIN) {
                unsigned char wire[MAX_PACKET + 22];
                ssize_t n = recv(s->udp[i], wire, sizeof(wire), 0);
                if (n < 4 || wire[0] || wire[1] || wire[2])
                    continue;
                struct packet packet;
                int h = address_decode(wire + 3, n - 3, &packet.addr, &packet.len);
                if (h < 0)
                    continue;
                unsigned char expected[19], received[19];
                pthread_mutex_lock(&s->lock);
                int en =
                    s->target_len ? address_encode((void *)&s->target, s->target_len, expected) : 0;
                pthread_mutex_unlock(&s->lock);
                int got = address_encode((void *)&packet.addr, packet.len, received);
                if (en && (en != got || memcmp(expected, received, en)))
                    continue;
                size_t payload = n - 3 - h;
                memcpy(packet.bytes, wire + 3 + h, payload);
                send(s->peer, &packet, offsetof(struct packet, bytes) + payload, MSG_NOSIGNAL);
            }
    }
    return NULL;
error:
    completion(s, errno ? errno : EIO);
    /* Datagram shutdown alone leaves a full outgoing queue non-writable on
       Linux. Draining after publishing error creates the required wake edge. */
    {
        unsigned char b[sizeof(struct packet)];
        while (recv(s->peer, b, sizeof(b), MSG_DONTWAIT) >= 0) {}
    }
    return NULL;
}
static int ready(struct proxy_socket *s, int fd, int flags) {
    pthread_mutex_lock(&s->lock);
    if (s->listener) {
        pthread_mutex_unlock(&s->lock);
        return fail(EOPNOTSUPP);
    }
    if (!s->local && (!s->config.port || !s->config.user[0])) {
        pthread_mutex_unlock(&s->lock);
        return fail(ENETDOWN);
    }
    if (s->type == SOCK_DGRAM && !s->started && !s->cancel) {
        s->started = true;
        int e = pthread_create(&s->worker, NULL, s->local ? local_udp_worker : udp_worker, s);
        if (e) {
            s->started = false;
            pthread_mutex_unlock(&s->lock);
            return fail(e);
        }
    }
    bool nonblock = (flags & MSG_DONTWAIT) || (fcntl(fd, F_GETFL) & O_NONBLOCK);
    while (s->started && !s->done && !s->cancel && !nonblock) {
        if (interrupted()) {
            pthread_mutex_unlock(&s->lock);
            return fail(EINTR);
        }
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += 100000000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&s->changed, &s->lock, &deadline);
    }
    int e = s->cancel ? ECONNRESET : !s->started ? ENOTCONN : !s->done ? EAGAIN : s->terminal_error;
    pthread_mutex_unlock(&s->lock);
    return e ? fail(e) : 0;
}
ssize_t ish_proxy_sendto(int fd, const void *b, size_t n, int flags, const struct sockaddr *a,
                         socklen_t len) {
    struct proxy_socket *s = acquire(fd);
    if (!s) {
        if (deny_direct(fd)) return fail(ENETDOWN);
        if (ish_proxy_enabled() && local_direct(fd) && a && !loopback(a, len))
            return fail(EACCES);
        return sendto(fd, b, n, flags, a, len);
    }
    if (s->local || (s->type == SOCK_DGRAM && loopback(a, len))) {
        if ((a && !loopback(a, len)) || make_local(s) < 0) {
            release(s); return fail(EACCES);
        }
    }
    if (ready(s, fd, flags) < 0) {
        release(s);
        return -1;
    }
    if (s->type == SOCK_STREAM) {
        ssize_t result = send(fd, b, n, flags | MSG_NOSIGNAL);
        release(s);
        return result;
    }
    struct packet packet;
    memset(&packet, 0, offsetof(struct packet, bytes));
    if (a) {
        if (len > sizeof(packet.addr)) {
            release(s);
            return fail(EINVAL);
        }
        memcpy(&packet.addr, a, len);
        packet.len = len;
    } else {
        pthread_mutex_lock(&s->lock);
        packet.addr = s->target;
        packet.len = s->target_len;
        pthread_mutex_unlock(&s->lock);
    }
    unsigned char enc[19];
    int h = address_encode((void *)&packet.addr, packet.len, enc);
    if (h < 0) {
        release(s);
        return -1;
    }
    if (n + 3 + h > 65507) {
        release(s);
        return fail(EMSGSIZE);
    }
    memcpy(packet.bytes, b, n);
    ssize_t r = send(fd, &packet, offsetof(struct packet, bytes) + n, flags | MSG_NOSIGNAL);
    release(s);
    return r < 0 ? -1 : (ssize_t)n;
}
static void copy_addr(struct sockaddr *a, socklen_t *len, const struct sockaddr_storage *src,
                      socklen_t size) {
    if (a && len) {
        socklen_t n = *len < size ? *len : size;
        memcpy(a, src, n);
        *len = size;
    }
}
ssize_t ish_proxy_recvfrom(int fd, void *b, size_t n, int flags, struct sockaddr *a,
                           socklen_t *len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return recvfrom(fd, b, n, flags, a, len);
    if (ready(s, fd, flags) < 0) {
        release(s);
        return -1;
    }
    if (s->type == SOCK_STREAM) {
        ssize_t r = recv(fd, b, n, flags);
        if (r >= 0)
            copy_addr(a, len, &s->target, s->target_len);
        release(s);
        return r;
    }
    struct packet packet;
    ssize_t r = recv(fd, &packet, sizeof(packet), flags & ~MSG_TRUNC);
    if (r < 0) {
        release(s);
        return -1;
    }
    if (r < (ssize_t)offsetof(struct packet, bytes)) {
        release(s);
        return fail(EPROTO);
    }
    size_t payload = r - offsetof(struct packet, bytes), take = payload < n ? payload : n;
    memcpy(b, packet.bytes, take);
    copy_addr(a, len, &packet.addr, packet.len);
    release(s);
    return flags & MSG_TRUNC ? (ssize_t)payload : (ssize_t)take;
}
ssize_t ish_proxy_sendmsg(int fd, const struct msghdr *msg, int flags) {
    struct proxy_socket *s = acquire(fd);
    if (!s) {
        if (deny_direct(fd)) return fail(ENETDOWN);
        if (ish_proxy_enabled() && local_direct(fd) && msg->msg_name &&
            !loopback(msg->msg_name, msg->msg_namelen)) return fail(EACCES);
        return sendmsg(fd, msg, flags);
    }
    if (s->local) {
        if (msg->msg_name && !loopback(msg->msg_name, msg->msg_namelen)) {
            release(s); return fail(EACCES);
        }
    }
    if (msg->msg_controllen) {
        release(s);
        return fail(EOPNOTSUPP);
    }
    if (s->type == SOCK_STREAM) {
        if (ready(s, fd, flags) < 0) {
            release(s);
            return -1;
        }
        struct msghdr local = *msg;
        local.msg_name = NULL;
        local.msg_namelen = 0;
        ssize_t result = sendmsg(fd, &local, flags | MSG_NOSIGNAL);
        release(s);
        return result;
    }
    release(s);
    size_t n = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > MAX_PACKET - n)
            return fail(EMSGSIZE);
        n += msg->msg_iov[i].iov_len;
    }
    unsigned char *b = malloc(n ? n : 1);
    if (!b)
        return fail(ENOMEM);
    size_t off = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        memcpy(b + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        off += msg->msg_iov[i].iov_len;
    }
    ssize_t r = ish_proxy_sendto(fd, b, n, flags, msg->msg_name, msg->msg_namelen);
    free(b);
    return r;
}
ssize_t ish_proxy_recvmsg(int fd, struct msghdr *msg, int flags) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return recvmsg(fd, msg, flags);
    bool udp = s->type == SOCK_DGRAM;
    if (!udp) {
        if (ready(s, fd, flags) < 0) {
            release(s);
            return -1;
        }
        struct msghdr local = *msg;
        local.msg_name = NULL;
        local.msg_namelen = 0;
        local.msg_control = NULL;
        local.msg_controllen = 0;
        ssize_t result = recvmsg(fd, &local, flags);
        if (result >= 0) {
            copy_addr(msg->msg_name, &msg->msg_namelen, &s->target, s->target_len);
            msg->msg_flags = local.msg_flags;
            msg->msg_controllen = 0;
        }
        release(s);
        return result;
    }
    release(s);
    size_t n = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_len > MAX_PACKET - n)
            return fail(EMSGSIZE);
        n += msg->msg_iov[i].iov_len;
    }
    unsigned char *b = malloc(n ? n : 1);
    if (!b)
        return fail(ENOMEM);
    socklen_t len = msg->msg_namelen;
    ssize_t r = ish_proxy_recvfrom(fd, b, n, flags | (udp ? MSG_TRUNC : 0), msg->msg_name, &len);
    if (r >= 0) {
        size_t left = (size_t)r < n ? (size_t)r : n, off = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            size_t chunk = msg->msg_iov[i].iov_len < left ? msg->msg_iov[i].iov_len : left;
            memcpy(msg->msg_iov[i].iov_base, b + off, chunk);
            off += chunk;
            left -= chunk;
        }
        msg->msg_flags = (size_t)r > n ? MSG_TRUNC : 0;
        msg->msg_namelen = len;
        msg->msg_controllen = 0;
        if (!(flags & MSG_TRUNC) && (size_t)r > n)
            r = n;
    }
    free(b);
    return r;
}
int ish_proxy_getsockopt(int fd, int level, int option, void *v, socklen_t *len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return getsockopt(fd, level, option, v, len);
    if (s->local && !(level == SOL_SOCKET && option == SO_ERROR &&
                      s->type == SOCK_STREAM && !s->listener)) {
        int r = getsockopt(s->native, level, option, v, len);
        release(s);
        return r;
    }
    if (level == SOL_SOCKET && option == SO_SNDBUF) {
        pthread_mutex_lock(&s->lock);
        if (s->has_deferred_sendbuf) {
            if (*len < sizeof(int)) {
                pthread_mutex_unlock(&s->lock);
                release(s);
                return fail(EINVAL);
            }
            *(int *)v = s->deferred_sendbuf;
            *len = sizeof(int);
            pthread_mutex_unlock(&s->lock);
            release(s);
            return 0;
        }
        pthread_mutex_unlock(&s->lock);
    }
    if (level == SOL_SOCKET && option == SO_ERROR) {
        if (*len < sizeof(int)) {
            release(s);
            return fail(EINVAL);
        }
        pthread_mutex_lock(&s->lock);
        *(int *)v = s->error;
        s->error = 0;
        pthread_mutex_unlock(&s->lock);
        *len = sizeof(int);
        release(s);
        return 0;
    }
    release(s);
    return getsockopt(fd, level, option, v, len);
}
int ish_proxy_getpeername(int fd, struct sockaddr *a, socklen_t *len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return getpeername(fd, a, len);
    if (s->local) {
        int r = getpeername(s->native, a, len);
        release(s);
        return r;
    }
    pthread_mutex_lock(&s->lock);
    int e = s->target_len ? 0 : ENOTCONN;
    if (!e)
        copy_addr(a, len, &s->target, s->target_len);
    pthread_mutex_unlock(&s->lock);
    release(s);
    return e ? fail(e) : 0;
}
int ish_proxy_getsockname(int fd, struct sockaddr *a, socklen_t *len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return getsockname(fd, a, len);
    if (s->local) {
        int r = getsockname(s->native, a, len);
        release(s);
        return r;
    }
    struct sockaddr_storage zero = {0};
    zero.ss_family = s->domain;
    copy_addr(a, len, &zero,
              s->domain == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    release(s);
    return 0;
}
int ish_proxy_bind(int fd, const struct sockaddr *a, socklen_t len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return deny_direct(fd) ? fail(ENETDOWN) : bind(fd, a, len);
    int r = !loopback(a, len) ? fail(EACCES) : make_local(s) < 0 ? -1 : bind(s->native, a, len);
    release(s);
    return r;
}
int ish_proxy_listen(int fd, int n) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return deny_direct(fd) ? fail(ENETDOWN) : listen(fd, n);
    int r = s->local ? listen(s->native, n) : fail(EOPNOTSUPP);
    if (!r) {
        pthread_mutex_lock(&s->lock);
        if (!s->started) {
            s->listener = true;
            s->started = true;
            int e = pthread_create(&s->worker, NULL, listener_worker, s);
            if (e) { s->started = false; r = fail(e); }
        }
        pthread_mutex_unlock(&s->lock);
    }
    release(s);
    return r;
}
int ish_proxy_close(int fd) {
    pthread_mutex_lock(&registry_lock);
    struct proxy_socket **p = &sockets;
    while (*p && (*p)->fd != fd)
        p = &(*p)->next;
    struct proxy_socket *s = *p;
    if (s)
        *p = s->next;
    pthread_mutex_unlock(&registry_lock);
    if (!s) {
        pthread_mutex_lock(&registry_lock);
        struct direct_socket **d = &direct_sockets;
        while (*d && (*d)->fd != fd)
            d = &(*d)->next;
        if (*d) {
            struct direct_socket *old = *d;
            *d = old->next;
            free(old);
        }
        pthread_mutex_unlock(&registry_lock);
        return close(fd);
    }
    cancel(s);
    if (s->started)
        pthread_join(s->worker, NULL);
    for (;;) {
        pthread_mutex_lock(&registry_lock);
        unsigned refs = s->refs;
        pthread_mutex_unlock(&registry_lock);
        if (!refs)
            break;
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    if (s->native >= 0) close(s->native);
    close(s->peer);
    if (s->remote >= 0)
        close(s->remote);
    for (int i = 0; i < 2; i++) {
        if (s->control[i] >= 0)
            close(s->control[i]);
        if (s->udp[i] >= 0)
            close(s->udp[i]);
    }
    pthread_cond_destroy(&s->changed);
    pthread_mutex_destroy(&s->lock);
    memset(&s->config, 0, sizeof(s->config));
    free(s);
    return close(fd);
}

int ish_proxy_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
    struct proxy_socket *s = acquire(fd);
    if (!s)
        return setsockopt(fd, level, option, value, len);
    if (s->local) {
        int r = setsockopt(s->native, level, option, value, len);
        release(s);
        return r;
    }
    /* The dormant local socket must retain settings applied before bind. */
    if (setsockopt(s->native, level, option, value, len) < 0) {
        release(s);
        return -1;
    }
    if (level == SOL_SOCKET && option == SO_SNDBUF) {
        if (len != sizeof(int) || *(const int *)value <= 0) {
            release(s);
            return fail(EINVAL);
        }
        pthread_mutex_lock(&s->lock);
        // Increasing capacity before SOCKS CONNECT succeeds would defeat
        // the full-buffer readiness gate. Defer until the gate is released.
        if ((s->started || s->type == SOCK_DGRAM) && !s->done) {
            s->deferred_sendbuf = *(const int *)value;
            s->has_deferred_sendbuf = true;
            pthread_mutex_unlock(&s->lock);
            release(s);
            return 0;
        }
        int r = setsockopt(fd, level, option, value, len);
        pthread_mutex_unlock(&s->lock);
        release(s);
        return r;
    }
    /* TCP's host transport belongs to the relay, not the Unix readiness pair.
       NODELAY/KEEPALIVE are transport hints; configure them on the remote. */
    if (level == IPPROTO_TCP) {
        if (option != TCP_NODELAY) {
            release(s);
            return fail(EOPNOTSUPP);
        }
        pthread_mutex_lock(&s->lock);
        int remote = s->remote;
        int r = remote >= 0 ? setsockopt(remote, level, option, value, len) : 0;
        pthread_mutex_unlock(&s->lock);
        release(s);
        return r;
    }
    if (level == IPPROTO_IPV6 && option == IPV6_V6ONLY) {
        release(s);
        return 0;
    }
    release(s);
    return setsockopt(fd, level, option, value, len);
}
/* Listener waits have no handshake deadline. Poll in bounded slices only to
   observe guest interruption/cancellation; an explicit SO_RCVTIMEO is absolute
   across spurious readiness and repeated native nonblocking accept attempts. */
static int listener_wait(struct proxy_socket *s, const struct timespec *deadline) {
    for (;;) {
        if (cancelled(s)) return fail(ECANCELED);
        if (interrupted()) return fail(EINTR);
        int timeout = 100;
        if (deadline) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
            if (now.tv_sec > deadline->tv_sec ||
                (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec))
                return fail(EAGAIN);
            if (deadline->tv_sec - now.tv_sec <= 1) {
                long long ns = (deadline->tv_sec - now.tv_sec) * 1000000000LL +
                               deadline->tv_nsec - now.tv_nsec;
                int remaining = (ns + 999999) / 1000000;
                if (remaining < timeout) timeout = remaining;
            }
        }
        struct pollfd p = {s->native, POLLIN, 0};
        int result = poll(&p, 1, timeout);
        if (result > 0) return 0;
        if (result < 0) return -1; /* Preserve host EINTR for the guest. */
    }
}
int ish_proxy_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    struct proxy_socket *s = acquire(fd);
    int result;
    if (s) {
        if (!s->local || !s->listener) { release(s); return fail(EINVAL); }
        struct timeval timeout;
        socklen_t timeout_size = sizeof(timeout);
        if (getsockopt(s->native, SOL_SOCKET, SO_RCVTIMEO, &timeout, &timeout_size) < 0) {
            int e = errno;
            release(s);
            return fail(e);
        }
        struct timespec deadline, *limit = NULL;
        if (timeout.tv_sec || timeout.tv_usec) {
            if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
                int e = errno;
                release(s);
                return fail(e);
            }
            deadline.tv_sec += timeout.tv_sec;
            deadline.tv_nsec += timeout.tv_usec * 1000;
            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }
            limit = &deadline;
        }
        for (;;) {
            if (cancelled(s)) { result = fail(ECANCELED); break; }
            if (interrupted()) { result = fail(EINTR); break; }
            result = accept(s->native, addr, len);
            if (result >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
                (fcntl(fd, F_GETFL) & O_NONBLOCK)) break;
            if (listener_wait(s, limit) < 0) break;
        }
        int accept_error = errno;
        pthread_mutex_lock(&s->lock);
        char byte;
        recv(fd, &byte, 1, MSG_DONTWAIT);
        s->notified = false;
        pthread_mutex_unlock(&s->lock);
        release(s);
        if (result < 0) return fail(accept_error);
        /* Host accept flag inheritance differs; guest accept returns blocking. */
        int flags = fcntl(result, F_GETFL);
        fcntl(result, F_SETFL, flags & ~O_NONBLOCK);
    } else {
        if (deny_direct(fd)) return fail(ENETDOWN);
        /* Policy shutdown interrupts blocking accept on old direct listeners. */
        result = accept(fd, addr, len);
        if (result < 0) return result;
    }
    struct sockaddr_storage local;
    socklen_t size = sizeof(local);
    if (getsockname(result, (void *)&local, &size) < 0) {
        int e = errno;
        close(result);
        return fail(e);
    }
    if (local.ss_family == AF_INET || local.ss_family == AF_INET6) {
        pthread_mutex_lock(&registry_lock);
        if (active.enabled && !local_direct(result)) {
            pthread_mutex_unlock(&registry_lock);
            close(result);
            return fail(ENETDOWN);
        }
        struct direct_socket *d = malloc(sizeof(*d));
        if (!d) {
            pthread_mutex_unlock(&registry_lock);
            close(result);
            return fail(ENOMEM);
        }
        d->fd = result;
        d->next = direct_sockets;
        direct_sockets = d;
        pthread_mutex_unlock(&registry_lock);
    }
    return result;
}
