//go:build darwin || ios || android

package tsnet

import "tailscale.com/net/netmon"

func setDefaultRouteInterface(name string) {
	netmon.UpdateLastKnownDefaultRouteInterface(name)
}
