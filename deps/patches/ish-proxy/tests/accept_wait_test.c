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
#include <sys/time.h>
#include <time.h>
static int listener, completion[2];
static struct sockaddr_in endpoint;
static volatile sig_atomic_t pending;
static bool interrupt_pending(void) { return pending != 0; }
static void signal_handler(int signal) { (void)signal; pending = 1; }
static void *accept_thread(void *unused) {
    (void)unused;
    int result = ish_proxy_accept(listener, NULL, NULL);
    int reply[2] = {result, errno};
    assert(write(completion[1], reply, sizeof(reply)) == sizeof(reply));
    return NULL;
}
static void setup(void) {
    pending = 0;
    assert(!ish_proxy_configure("127.0.0.1", 1, "shell", "secret", true));
    listener = ish_proxy_socket(AF_INET, SOCK_STREAM, 0);
    endpoint = (struct sockaddr_in){.sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(listener >= 0 && !ish_proxy_bind(listener, (void *)&endpoint, sizeof(endpoint)));
    assert(!ish_proxy_listen(listener, 4));
    socklen_t size = sizeof(endpoint);
    assert(!ish_proxy_getsockname(listener, (void *)&endpoint, &size));
    assert(!pipe(completion));
}
static void finish(pthread_t thread, int expected) {
    struct pollfd p = {completion[0], POLLIN, 0};
    assert(poll(&p, 1, 2000) == 1);
    int reply[2];
    assert(read(completion[0], reply, sizeof(reply)) == sizeof(reply));
    assert(reply[0] == -1 && reply[1] == expected);
    assert(!pthread_join(thread, NULL));
    ish_proxy_close(listener);
    close(completion[0]); close(completion[1]);
}
static void interrupt_test(bool already_pending) {
    setup();
    ish_proxy_set_interrupt_hook(interrupt_pending);
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1, &action, NULL));
    if (already_pending) pending = 1;
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, accept_thread, NULL));
    if (!already_pending) {
        struct pollfd p = {completion[0], POLLIN, 0};
        assert(poll(&p, 1, 100) == 0);
        assert(!pthread_kill(thread, SIGUSR1));
    }
    finish(thread, EINTR);
    ish_proxy_set_interrupt_hook(NULL);
    puts(already_pending ? "Local accept pending guest interrupt: PASS" :
                           "Local accept real signal/guest interrupt: PASS");
}
static void timeout_test(void) {
    setup();
    assert(!fcntl(listener, F_SETFL, O_NONBLOCK));
    assert(ish_proxy_accept(listener, NULL, NULL) == -1 && errno == EAGAIN);
    assert(!fcntl(listener, F_SETFL, 0));
    struct timeval timeout = {.tv_usec = 150000};
    assert(!ish_proxy_setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    struct timespec start, end;
    assert(!clock_gettime(CLOCK_MONOTONIC, &start));
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, accept_thread, NULL));
    finish(thread, EAGAIN);
    assert(!clock_gettime(CLOCK_MONOTONIC, &end));
    double elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    assert(elapsed >= 0.10 && elapsed < 2.0);
    puts("Local accept nonblocking EAGAIN and explicit SO_RCVTIMEO: PASS");
}
static void persistence_test(void) {
    setup();
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, accept_thread, NULL));
    struct pollfd p = {completion[0], POLLIN, 0};
    /* A default listener must remain alive beyond the former 30 second cap. */
    assert(poll(&p, 1, 31000) == 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0 && !connect(client, (void *)&endpoint, sizeof(endpoint)));
    assert(poll(&p, 1, 2000) == 1);
    int reply[2];
    assert(read(completion[0], reply, sizeof(reply)) == sizeof(reply) && reply[0] >= 0);
    assert(!pthread_join(thread, NULL));
    close(client); ish_proxy_close(reply[0]); ish_proxy_close(listener);
    close(completion[0]); close(completion[1]);
    puts("Local accept waits beyond 31 seconds without timeout then accepts: PASS");
}
int main(int argc, char **argv) {
    if (argc == 1 || !strcmp(argv[1], "interrupt")) {
        interrupt_test(false); interrupt_test(true);
    }
    if (argc == 1 || !strcmp(argv[1], "timeout")) timeout_test();
    if (argc == 1 || !strcmp(argv[1], "persistent")) persistence_test();
}
