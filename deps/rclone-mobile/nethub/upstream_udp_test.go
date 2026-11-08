package nethub

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// The destination is a nonlocal test address: only the upstream SOCKS hub
// maps it to the real echo endpoint, proving that no direct UDP escaped.
func TestStrictSOCKSUpstreamCarriesUDP(t *testing.T) {
	echo := udpEcho(t, "upstream:")
	up := New(nil, nil)
	up.Configure(Config{DefaultRoute: "direct"})
	up.dialDirect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.LocalAddr().String())
	}
	entry, password, err := up.Start(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Stop)
	host, portString, _ := net.SplitHostPort(entry)
	port, _ := strconv.Atoi(portString)
	h := New(nil, nil)
	h.Configure(Config{Strict: true, DefaultRoute: "proxy:node", Upstreams: []Upstream{{ID: "node", Type: "socks5", Host: host, Port: port, Username: "default", Password: password}}})
	c, _, _, err := h.dialUDPRoute("test", "shell", "203.0.113.9:443", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:n]) != "upstream:hello" {
		t.Fatalf("wrong exit payload %q", b[:n])
	}
}
