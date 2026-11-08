package main

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/OpenMinis/minis-rclone/routepolicy"
	"golang.org/x/net/proxy"
)

func init() {
	routepolicy.SetDialer(func(ctx context.Context, network, address string) (net.Conn, bool, error) {
		s := appProxy.Status()
		return routepolicy.DialStrict(ctx, network, address, routepolicy.Status{Mode: s.Mode, Running: s.Running, Port: s.Port, Password: s.Password}, func(ctx context.Context, network, address string) (net.Conn, error) {
			// The local entry owns routing and tracks this tunnel, so Stop and node
			// switches close established backup connections as well as future dials.
			dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)), &proxy.Auth{User: "default", Password: s.Password}, &net.Dialer{Timeout: 30 * time.Second})
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			// Send the original hostname to SOCKS; never resolve the target locally.
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
		})
	})
}
