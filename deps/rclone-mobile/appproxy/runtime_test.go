package appproxy

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestLifecycleAndInvalidConfig(t *testing.T) {
	m := NewManager()
	defer m.Stop()
	if _, e := m.Configure([]byte(`{"mode":"manual","manual":{"type":"socks5","host":"127.0.0.1","port":9}}`)); e != nil {
		t.Fatal(e)
	}
	s := m.Status()
	if !s.Running || s.Port == 0 || s.HTTPPort == 0 || s.Password == "" {
		t.Fatal("entry not ready")
	}
	if _, e := m.Configure([]byte(`{"mode":"manual","manual":{"type":"socks5","host":"example.org","port":9}}`)); e == nil {
		t.Fatal("silent bootstrap")
	}
	if !m.Status().Running {
		t.Fatal("invalid replacement destroyed old config")
	}
	m.Stop()
	if m.Status().Running || m.Status().Mode != "blocked" {
		t.Fatal("stop failed to block policy")
	}
}
func TestCoreConstructsEveryImportedProtocol(t *testing.T) {
	pbk := realityKey()
	for _, link := range []string{"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(`{"v":"2","add":"127.0.0.1","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","net":"tcp","aid":"0","scy":"auto"}`)), "ss://YWVzLTEyOC1nY206cHc@127.0.0.1:8388", "vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=tls&type=ws&path=%2Fx&sni=example.org", "vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&fp=chrome&pbk=" + pbk + "&sid=ab12", "trojan://pw@127.0.0.1:443", "trojan://pw@127.0.0.1:443?security=reality&sni=www.amazon.com&pbk=" + pbk} {
		r, e := Import(link)
		if e != nil || len(r.Nodes) != 1 {
			t.Fatal("import failed")
		}
		b, _ := json.Marshal(map[string]any{"mode": "node", "node": r.Nodes[0]})
		m := NewManager()
		_, e = m.Configure(b)
		m.Stop()
		if e != nil {
			t.Fatalf("%s core failed: %v", r.Nodes[0].Type, e)
		}
	}
}
func TestOffIsExplicitAndStopBlocks(t *testing.T) {
	m := NewManager()
	if m.Stop().Mode != "blocked" {
		t.Fatal("Stop must retain strict intent")
	}
	s, e := m.Configure([]byte(`{"mode":"off"}`))
	if e != nil || s.Mode != "off" || s.Running {
		t.Fatal("explicit off failed")
	}
	for _, raw := range []string{`{"mode":"node","node":{"type":"direct","outbound":{"type":"direct","server":"127.0.0.1","server_port":80}}}`, `{"mode":"manual","manual":{"type":"socks5","host":"127.0.0.1","port":1080},"unknown":true}`, `{"mode":"off"} {"mode":"manual"}`} {
		if _, e = m.Configure([]byte(raw)); e == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}
func TestConfigureRejectsNodesOutsideImportSchema(t *testing.T) {
	for _, outbound := range []map[string]any{
		{"type": "trojan", "server": "127.0.0.1", "server_port": 443, "password": "secret"},
		{"type": "shadowsocks", "server": "127.0.0.1", "server_port": 443, "method": "none", "password": "secret"},
		{"type": "vless", "server": "127.0.0.1", "server_port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000", "flow": "xtls-rprx-vision"},
		{"type": "vless", "server": "127.0.0.1", "server_port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000", "tls": map[string]any{"enabled": true, "reality": map[string]any{"enabled": true, "public_key": realityKey()}}},
		{"type": "vmess", "server": "127.0.0.1", "server_port": 443, "uuid": "550e8400-e29b-41d4-a716-446655440000", "alter_id": 0, "security": "auto", "tls": map[string]any{"enabled": true, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": realityKey()}}},
	} {
		kind := outbound["type"].(string)
		if kind == "shadowsocks" {
			kind = "ss"
		}
		raw, _ := json.Marshal(Configuration{Mode: "node", Node: &Node{Type: kind, Outbound: outbound}})
		m := NewManager()
		_, e := m.Configure(raw)
		m.Stop()
		if e == nil {
			t.Fatal("accepted node schema importer cannot produce")
		}
	}
}
