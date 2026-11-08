package nethub

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func strictHub(t *testing.T, route string) *Hub {
	t.Helper()
	var cfg Config
	b, _ := json.Marshal(map[string]any{
		"strict": true, "defaultRoute": route,
		"upstreams": []map[string]any{{"id": "chosen", "type": "http", "host": "127.0.0.1", "port": 1, "bypass": []string{"example.com", "192.168.0.0/16"}}},
	})
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	h := New(nil, nil)
	h.Configure(cfg)
	return h
}

func TestStrictInvalidRoutesNeverDialDirect(t *testing.T) {
	for _, route := range []string{"direct", "", "typo", "proxy:deleted", "tailscale"} {
		t.Run(route, func(t *testing.T) {
			h := strictHub(t, route)
			direct := false
			h.dialDirect = func(context.Context, string, string) (net.Conn, error) {
				direct = true
				return nil, errors.New("unexpected direct dial")
			}
			c, d, err := h.DialVia(context.Background(), "unregistered-client", "example.com:443")
			if c != nil {
				c.Close()
			}
			if err == nil || direct || d.Kind != "reject" {
				t.Fatalf("strict route escaped: decision=%+v direct=%v err=%v", d, direct, err)
			}
		})
	}
}

func TestStrictIgnoresBypassExceptLoopback(t *testing.T) {
	h := strictHub(t, "proxy:chosen")
	for _, host := range []string{"example.com", "192.168.1.1"} {
		if d := h.Decide("browser", host); d.Kind != "proxy" {
			t.Fatalf("%s bypassed: %+v", host, d)
		}
	}
	if d := h.Decide("shell", "127.0.0.1"); d.Kind != "direct" {
		t.Fatalf("internal loopback rejected: %+v", d)
	}
}

func TestStrictProxyUDPDoesNotFallBackToDirect(t *testing.T) {
	h := strictHub(t, "proxy:chosen")
	direct := false
	h.dialDirect = func(context.Context, string, string) (net.Conn, error) {
		direct = true
		return nil, errors.New("unexpected direct UDP")
	}
	c, _, _, err := h.dialUDPRoute("test", "shell", "203.0.113.1:443", "203.0.113.1")
	if c != nil {
		c.Close()
	}
	if err == nil || direct {
		t.Fatalf("UDP escaped strict route: direct=%v err=%v", direct, err)
	}
}

func TestStrictResolverNeverDialsDirect(t *testing.T) {
	h := strictHub(t, "proxy:chosen")
	direct := false
	h.dialDirect = func(context.Context, string, string) (net.Conn, error) {
		direct = true
		return nil, errors.New("unexpected direct DNS")
	}
	c, err := h.resolverDial(context.Background(), "udp", "203.0.113.53:53")
	if c != nil {
		c.Close()
	}
	if err == nil || direct {
		t.Fatalf("DNS escaped strict route: direct=%v err=%v", direct, err)
	}
}

func TestStrictGuestSnapshotHooksAllEvenWhenProxyMissing(t *testing.T) {
	for _, route := range []string{"proxy:chosen", "proxy:deleted", "direct"} {
		h := strictHub(t, route)
		s := h.HookRoutesWithResolvers("shell", []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}, nil)
		if !s.Everything || !s.DNSIntercept || len(s.Hook) != 2 || len(s.UDPHook) != 2 || len(s.Exempt) != 0 {
			t.Fatalf("route=%s guest can bypass: %+v", route, s)
		}
	}
}
