#ifndef ISH_PROXY_H
#define ISH_PROXY_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
/* Host errno convention for socket operations; configure returns negative errno. */
typedef bool (*ish_proxy_interrupt_hook)(void);
void ish_proxy_set_interrupt_hook(ish_proxy_interrupt_hook);
int ish_proxy_configure(const char *, uint16_t, const char *, const char *, bool);
bool ish_proxy_enabled(void);
int ish_proxy_socket(int, int, int);
int ish_proxy_connect(int, const struct sockaddr *, socklen_t);
ssize_t ish_proxy_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t ish_proxy_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t ish_proxy_sendmsg(int, const struct msghdr *, int);
ssize_t ish_proxy_recvmsg(int, struct msghdr *, int);
int ish_proxy_getsockopt(int, int, int, void *, socklen_t *);
int ish_proxy_getpeername(int, struct sockaddr *, socklen_t *);
int ish_proxy_getsockname(int, struct sockaddr *, socklen_t *);
int ish_proxy_bind(int, const struct sockaddr *, socklen_t);
int ish_proxy_listen(int, int);
int ish_proxy_close(int);
int ish_proxy_accept(int, struct sockaddr *, socklen_t *);
int ish_proxy_setsockopt(int, int, int, const void *, socklen_t);
static inline ssize_t ish_proxy_read(int fd, void *buf, size_t n) {
    return ish_proxy_recvfrom(fd, buf, n, 0, NULL, NULL);
}
static inline ssize_t ish_proxy_write(int fd, const void *buf, size_t n) {
    return ish_proxy_sendto(fd, buf, n, 0, NULL, 0);
}
#endif
