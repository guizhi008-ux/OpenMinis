// Package routepolicy is the dependency-free dial hook injected into the pinned
// rclone fshttp dialer by scripts/rclone_proxy_overlay.py. It must never import
// rclone: fshttp imports this package.
package routepolicy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

type Dialer func(context.Context, string, string) (net.Conn, bool, error)

var installed atomic.Bool

// MarkInstalled is called only by the patched upstream dialer's init. A
// native library built without the staging step must refuse strict mode.
func MarkInstalled()  { installed.Store(true) }
func Installed() bool { return installed.Load() }

var hook struct {
	sync.RWMutex
	dial Dialer
}

func SetDialer(dial Dialer) { hook.Lock(); hook.dial = dial; hook.Unlock() }

// DialContext reports handled=false only when the original dialer may run.
func DialContext(ctx context.Context, network, address string) (net.Conn, bool, error) {
	hook.RLock()
	dial := hook.dial
	hook.RUnlock()
	if dial == nil {
		return nil, false, nil
	}
	return dial(ctx, network, address)
}

type Status struct {
	Mode     string
	Running  bool
	Port     int
	Password string
}

// DialStrict preserves the original behavior only in off mode or for internal
// loopback services. LAN, tailnet, and unresolved names are routed normally.
func DialStrict(ctx context.Context, network, address string, status Status, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, bool, error) {
	if status.Mode == "off" {
		return nil, false, nil
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, true, errors.New("app proxy: unsupported rclone network")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, true, errors.New("app proxy: invalid rclone destination")
	}
	if strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() {
		return nil, false, nil
	}
	if !status.Running || status.Port < 1 || status.Port > 65535 || status.Password == "" || dial == nil {
		return nil, true, errors.New("app proxy: rclone route unavailable")
	}
	conn, err := dial(ctx, network, address)
	return conn, true, err
}
