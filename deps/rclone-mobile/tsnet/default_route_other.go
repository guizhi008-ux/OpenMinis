//go:build !darwin && !ios && !android

package tsnet

// Tailscale observes the route itself on desktop Linux. The explicit
// NWPathMonitor/Android update hook exists only in mobile netmon builds.
func setDefaultRouteInterface(string) {}
