package nethub

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestStrictStopClosesActiveTunnels(t *testing.T) {
	endpoint := echoServer(t, "exit:")
	h := New(nil, nil)
	h.Configure(Config{Strict: true, DefaultRoute: "proxy:chosen", Upstreams: []Upstream{{ID: "chosen", Type: "socks5", Host: "127.0.0.1", Port: 1}}})
	// Use the loopback exception so this test isolates Stop from upstream
	// negotiation; the actual routed traffic is already covered separately.
	h.dialDirect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, endpoint)
	}
	entry, password, err := h.Start(0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	c := socksHello(t, entry, password, "default")
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("connect reply=%v err=%v", reply, err)
	}
	h.Stop()
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var b [1]byte
	_, err = c.Read(b[:])
	if e, ok := err.(net.Error); err == nil || ok && e.Timeout() {
		t.Fatalf("tunnel survived Stop: %v", err)
	}
}
