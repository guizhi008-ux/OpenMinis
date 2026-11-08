# iSH guest socket transport

`apply.py` patches the iSH submodule at commit
`0fd17a135e78b7a0cf08a4f5831217bbb76ed22f`. It checks the revision and
unmodified file fingerprints, verifies that the complete patch applies, and
copies the canonical C transport into the guest library. Reapplication is safe.
`deps/build_ish.sh` invokes it before building both Apple platforms. Rebuild
libish after changing this adapter; existing binary libraries lack its symbols.

The public C configuration function is:

```c
int ish_proxy_configure(const char *host, uint16_t port,
                        const char *username, const char *password,
                        bool enabled);
```

It returns zero or a negative host errno. It starts disabled. The only accepted
entry host is `127.0.0.1`; credentials are required when enabled. Invalid enabled
configuration stays enabled and denies external operations. Reconfiguration
revokes old external guest network sockets, including sockets created while disabled.
Numeric loopback services and their local clients remain available across policy
changes, including invalid entry configuration.
Only `fs/sock.c` calls are redirected; host app and Go runtime calls retain their
normal socket implementation.

TCP uses a Unix socketpair as its guest descriptor. At connect time its send
queue is filled before starting a SOCKS worker. The worker drains these reserved
bytes only after authenticated CONNECT succeeds, then relays application bytes
with bounded buffers and backpressure. Consequently existing native
poll/kqueue/epoll registrations become writable after CONNECT, rather than after
the preliminary local TCP connection. A send-buffer increase during CONNECT is
deferred until this gate opens. Failures wake the descriptor and are delivered
through guest SO_ERROR. Blocking connect can be interrupted by the guest's host
signal wake. Workers are cancelled and joined before their descriptors and
state are reclaimed.

UDP uses a datagram socketpair and a private sockaddr envelope. Its outgoing
queue is filled before returning the guest descriptor and authentication starts
immediately, including when a caller polls before its first write. Success is
published before reserved datagrams are drained, producing a real writable edge
for poll/epoll/kqueue. Failure and cancellation publish the error before draining
the gate, so a full datagram queue cannot hide the failure wake. Send-buffer
changes during authentication are deferred. Consuming SO_ERROR does not make a
failed association usable. Guest
read/write, sendto/recvfrom and sendmsg/recvmsg translate this envelope, including
source addresses, scatter/gather, PEEK, TRUNC and connected-source filtering.
Separate authenticated UDP associations carry ordinary packets and DNS. TCP
and UDP port 53 use the `<username>~dns` identity consumed by nethub; strict
resolver routing remains nethub's responsibility. All host datagrams go only
to the local authenticated entry's loopback UDP relay. No direct fallback exists.

Numeric IPv4 `127.0.0.0/8` and IPv6 `::1` use the necessary internal-service path.
Explicit loopback binds support chosen ports, TCP listen/accept and UDP services;
loopback TCP connect and UDP sendto/connect remain on device. The guest descriptor
stays the same socketpair throughout, preserving poll registrations installed
before bind/connect/listen. A worker relays local TCP/UDP; listeners signal queued
accepts through the pair. Accepted sockets are tracked native loopback sockets.
Local socket options and names use the native transport. These sockets cannot
later connect or send to LAN/public addresses, including through sendmsg. Wildcard
and non-loopback binds are rejected; servers must explicitly bind `127.0.0.1` or
`::1`. A socket that selects local service semantics remains loopback-only until
close. IPv4-mapped IPv6 loopback addresses are not a direct exception.
Blocking local accept has no default handshake deadline, returns promptly for
guest interruptions, and honors an explicit `SO_RCVTIMEO`; nonblocking accept
retains `EAGAIN` when no client is queued.

For external SOCKS traffic, getsockname reports an unspecified address/port of
the logical family; source addresses/ports cannot be preserved. Raw/ICMP sockets,
scoped IPv6 destinations, ancillary IP messages and unsupported TCP options fail
explicitly. SOCKS overhead reduces the maximum legal UDP payload; oversize sends
return EMSGSIZE. UDP transport loss remains possible under backpressure, as for
ordinary UDP. These are explicit limits rather than direct-routing exceptions.

Run portable behavioral tests with:

```sh
./deps/patches/ish-proxy/tests/run.sh
CFLAGS='-fsanitize=address,undefined -g' ./deps/patches/ish-proxy/tests/run.sh
```

Tests create loopback-only controlled SOCKS endpoints and local guest services,
including pre-registered Linux EPOLLET descriptors, delayed UDP authentication,
UDP refusal/cancellation wakes, and local service survival across policy changes.
Linux tests do not certify
Darwin socketpair low-water behavior, an Xcode build, guest binaries on iOS, or
actual iPhone egress. Device validation must check those separately.
