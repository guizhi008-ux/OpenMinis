package appproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/OpenMinis/minis-rclone/nethub"
	box "github.com/sagernet/sing-box"
)

type Configuration struct {
	Mode              string           `json:"mode"`
	Manual            *nethub.Upstream `json:"manual,omitempty"`
	Node              *Node            `json:"node,omitempty"`
	AllowBootstrapDNS bool             `json:"allowBootstrapDNS"`
}
type Status struct {
	Running  bool   `json:"running"`
	Mode     string `json:"mode"`
	Port     int    `json:"port"`
	HTTPPort int    `json:"httpPort"`
	Password string `json:"password"`
}
type Manager struct {
	mu     sync.Mutex
	hub    *nethub.Hub
	core   *box.Box
	status Status
}

func NewManager() *Manager     { return &Manager{status: Status{Mode: "off"}} }
func safeError(s string) error { return errors.New(s) }
func (m *Manager) Configure(data []byte) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fail := func(s string) (Status, error) { return m.status, safeError(s) }
	if len(data) > MaxImportBytes {
		return fail("configuration exceeds size limit")
	}
	var c Configuration
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return fail("invalid configuration")
	}
	if d.Decode(new(any)) != io.EOF {
		return fail("invalid configuration")
	}
	if c.Mode == "off" {
		m.stop()
		return m.status, nil
	}
	var upstream nethub.Upstream
	var outbound map[string]any
	switch c.Mode {
	case "manual":
		if c.Manual == nil || c.Node != nil {
			return fail("missing manual proxy")
		}
		upstream = *c.Manual
		if upstream.Type != "http" && upstream.Type != "https" && upstream.Type != "socks5" {
			return fail("unsupported manual proxy")
		}
		if upstream.Port < 1 || upstream.Port > 65535 || len(upstream.Bypass) > 0 {
			return fail("invalid manual proxy")
		}
	case "node":
		if c.Node == nil || c.Manual != nil {
			return fail("missing selected node")
		}
		b, _ := json.Marshal(c.Node.Outbound)
		json.Unmarshal(b, &outbound)
		if e := validateOutbound(*c.Node); e != nil {
			return fail("invalid or unsupported node")
		}
		upstream.Host, _ = outbound["server"].(string)
	default:
		return fail("unsupported mode")
	}
	if !validateServer(upstream.Host) {
		return fail("invalid proxy server")
	}
	if net.ParseIP(upstream.Host) == nil {
		if !c.AllowBootstrapDNS {
			return fail("proxy server needs explicit bootstrap DNS permission or an IP address")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		addresses, e := net.DefaultResolver.LookupIPAddr(ctx, upstream.Host)
		cancel()
		if e != nil || len(addresses) == 0 {
			return fail("proxy server bootstrap DNS failed")
		}
		original := upstream.Host
		upstream.Host = addresses[0].IP.String()
		if outbound != nil {
			outbound["server"] = upstream.Host
			if tls, ok := outbound["tls"].(map[string]any); ok && tls["server_name"] == nil {
				tls["server_name"] = original
			}
		}
		if outbound == nil && upstream.Type == "https" {
			upstream.TLSServerName = original
		}
	}
	var core *box.Box
	if outbound != nil {
		secret := make([]byte, 32)
		if _, e := rand.Read(secret); e != nil {
			return fail("proxy secret generation failed")
		}
		password := hex.EncodeToString(secret)
		var port int
		var e error
		core, port, e = startCore(outbound, password)
		if e != nil {
			return fail("proxy core rejected node configuration")
		}
		upstream = nethub.Upstream{Type: "socks5", Host: "127.0.0.1", Port: port, Username: "core", Password: password}
	}
	upstream.ID = "app"
	upstream.Name = "selected"
	hub := nethub.New(nil, nil)
	hub.Configure(nethub.Config{Strict: true, DefaultRoute: "proxy:app", Upstreams: []nethub.Upstream{upstream}})
	addr, password, e := hub.Start(0)
	if e != nil {
		if core != nil {
			core.Close()
		}
		return fail("local proxy entry failed")
	}
	httpAddr, e := hub.StartHTTP(0)
	if e != nil {
		hub.Stop()
		if core != nil {
			core.Close()
		}
		return fail("local HTTP entry failed")
	}
	m.stop()
	m.hub = hub
	m.core = core
	m.status = Status{Running: true, Mode: c.Mode, Port: portOf(addr), HTTPPort: portOf(httpAddr), Password: password}
	return m.status, nil
}
func (m *Manager) stop() {
	if m.hub != nil {
		m.hub.StopHTTP()
		m.hub.Stop()
		m.hub = nil
	}
	if m.core != nil {
		m.core.Close()
		m.core = nil
	}
	m.status = Status{Mode: "off"}
}
func (m *Manager) Stop() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stop()
	m.status.Mode = "blocked"
	return m.status
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	if m.hub != nil && !m.hub.Alive() {
		s.Running = false
	}
	return s
}

// The C boundary accepts only the same explicit fields the importer creates.
// Unknown core knobs (detours, domain resolvers, plugins, custom certificates)
// cannot smuggle a second route or silently alter imported semantics.
func validateOutbound(n Node) error {
	o := n.Outbound
	expected := n.Type
	if expected == "ss" {
		expected = "shadowsocks"
	}
	if expected != "shadowsocks" && expected != "vmess" && expected != "vless" && expected != "trojan" {
		return errLink
	}
	if o["type"] != expected {
		return errLink
	}
	allowed := map[string]bool{}
	for _, k := range []string{"type", "server", "server_port"} {
		allowed[k] = true
	}
	fields := map[string][]string{
		"shadowsocks": {"method", "password"},
		"vmess":       {"uuid", "alter_id", "security", "tls", "transport"},
		"vless":       {"uuid", "flow", "packet_encoding", "tls", "transport"},
		"trojan":      {"password", "tls", "transport"},
	}
	for _, k := range fields[expected] {
		allowed[k] = true
	}
	for k := range o {
		if !allowed[k] {
			return errLink
		}
	}
	host, ok := o["server"].(string)
	if !ok || !validateServer(host) {
		return errLink
	}
	p, ok := number(o["server_port"])
	if !ok || p < 1 || p > 65535 {
		return errLink
	}
	if expected == "shadowsocks" || expected == "trojan" {
		if password, ok := o["password"].(string); !ok || password == "" {
			return errLink
		}
	}
	if expected == "shadowsocks" {
		switch o["method"] {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		default:
			return errLink
		}
	}
	if expected == "vmess" || expected == "vless" {
		if uuid, ok := o["uuid"].(string); !ok || !validUUID(uuid) {
			return errLink
		}
	}
	if expected == "trojan" && o["tls"] == nil {
		return errLink
	}
	if flow, exists := o["flow"]; exists {
		if flow != "xtls-rprx-vision" || o["tls"] == nil || o["transport"] != nil {
			return errLink
		}
	}
	if tls, exists := o["tls"]; exists {
		v, ok := tls.(map[string]any)
		if !ok || v["enabled"] != true {
			return errLink
		}
		for k := range v {
			switch k {
			case "enabled", "server_name", "insecure", "alpn":
			default:
				return errLink
			}
		}
	}
	if transport, exists := o["transport"]; exists {
		v, ok := transport.(map[string]any)
		if !ok {
			return errLink
		}
		for k := range v {
			switch k {
			case "type", "path", "headers", "service_name":
			default:
				return errLink
			}
		}
		if v["type"] != "ws" && v["type"] != "grpc" {
			return errLink
		}
	}
	return nil
}
func number(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), n == float64(int(n))
	}
	return 0, false
}
