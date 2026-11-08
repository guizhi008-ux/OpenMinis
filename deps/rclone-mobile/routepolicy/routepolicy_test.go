package routepolicy_test

import (
	"context"
	"errors"
	"net"
	"testing"

	. "github.com/OpenMinis/minis-rclone/routepolicy"
	"github.com/rclone/rclone/fs/fshttp"
)

func TestStagedUpstreamRegistersStrictHook(t *testing.T) {
	if !Installed() {
		t.Fatal("rclone was built without its strict network hook")
	}
}

func TestUpstreamDialerUsesHook(t *testing.T) {
	sentinel := errors.New("strict route intercepted")
	SetDialer(func(ctx context.Context, network, address string) (net.Conn, bool, error) {
		if network != "tcp" || address != "smb.example:445" {
			t.Fatalf("unexpected destination %s %s", network, address)
		}
		return nil, true, sentinel
	})
	defer SetDialer(nil)
	_, err := fshttp.NewDialer(context.Background()).DialContext(context.Background(), "tcp", "smb.example:445")
	if !errors.Is(err, sentinel) {
		t.Fatalf("upstream bypassed route hook: %v", err)
	}
}

func TestPolicyFailClosed(t *testing.T) {
	calls := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("local entry unavailable")
	}
	for _, s := range []Status{{Mode: "blocked"}, {Mode: "manual"}, {Mode: "node", Running: true, Port: 1234, Password: "secret"}} {
		_, handled, err := DialStrict(context.Background(), "tcp", "public.example:445", s, dial)
		if !handled || err == nil {
			t.Fatalf("status %+v did not fail closed", s)
		}
	}
	if calls != 1 {
		t.Fatalf("inactive runtime reached dialer %d times", calls)
	}
	_, handled, err := DialStrict(context.Background(), "udp", "public.example:53", Status{Mode: "manual", Running: true, Port: 1234, Password: "secret"}, dial)
	if !handled || err == nil || calls != 1 {
		t.Fatal("unknown network not rejected")
	}
}

func TestOffAndLoopbackLeaveOriginalBehavior(t *testing.T) {
	for _, tc := range []struct {
		status Status
		addr   string
	}{{Status{Mode: "off"}, "public.example:445"}, {Status{Mode: "blocked"}, "127.0.0.1:1234"}, {Status{Mode: "blocked"}, "[::1]:1234"}, {Status{Mode: "blocked"}, "localhost:1234"}} {
		_, handled, err := DialStrict(context.Background(), "tcp", tc.addr, tc.status, nil)
		if handled || err != nil {
			t.Fatalf("original route not retained: %s %v", tc.addr, err)
		}
	}
}
