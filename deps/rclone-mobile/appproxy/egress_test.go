package appproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	inboundRegistry "github.com/sagernet/sing-box/adapter/inbound"
	outboundRegistry "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	sj "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/proxy"
)

func shadowsocksPeer(t *testing.T) int {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	testCtx := testPeerContext(coreContext())
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "dns": map[string]any{"servers": []any{map[string]any{"type": "hosts"}}}, "inbounds": []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "aes-128-gcm", "password": "test-password"}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "local"}}, "route": map[string]any{"final": "local"}})
	var o option.Options
	if e = sj.UnmarshalContext(testCtx, raw, &o); e != nil {
		t.Fatal(e)
	}
	peer, e := box.New(box.Options{Context: testCtx, Options: o})
	if e != nil {
		t.Fatal(e)
	}
	if e = peer.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peer.Close() })
	return port
}
func testPeerContext(ctx context.Context) context.Context {
	ir := service.FromContext[adapter.InboundRegistry](ctx)
	or := service.FromContext[adapter.OutboundRegistry](ctx)
	// Concrete registries implement both option and constructor registries.
	shadowsocks.RegisterInbound(ir.(*inboundRegistry.Registry))
	vmess.RegisterInbound(ir.(*inboundRegistry.Registry))
	vless.RegisterInbound(ir.(*inboundRegistry.Registry))
	trojan.RegisterInbound(ir.(*inboundRegistry.Registry))
	direct.RegisterOutbound(or.(*outboundRegistry.Registry))
	return ctx
}

func TestEncryptedTCPThroughAuthenticatedEntry(t *testing.T) {
	peer := shadowsocksPeer(t)
	ln, e := net.Listen("tcp4", net.JoinHostPort(testLocalIP(t), "0"))
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	m := NewManager()
	defer m.Stop()
	n := Node{Type: "ss", Outbound: map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": peer, "method": "aes-128-gcm", "password": "test-password"}}
	b, _ := json.Marshal(Configuration{Mode: "node", Node: &n})
	s, e := m.Configure(b)
	if e != nil {
		t.Fatal(e)
	}
	dialer, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)), &proxy.Auth{User: "default", Password: s.Password}, &net.Dialer{Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	c, e := dialer.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write([]byte("encrypted-echo")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len("encrypted-echo"))
	if _, e = io.ReadFull(c, got); e != nil || string(got) != "encrypted-echo" {
		t.Fatalf("echo %q %v", got, e)
	}
	// Killing the core leaves the target reachable directly, but the managed
	// entry must fail rather than using that direct route.
	if e = m.core.Close(); e != nil {
		t.Fatal(e)
	}
	failed, e := dialer.Dial("tcp", ln.Addr().String())
	if e == nil {
		defer failed.Close()
		failed.SetDeadline(time.Now().Add(2 * time.Second))
		failed.Write([]byte("must-not-arrive"))
		probe := make([]byte, 14)
		if _, e = io.ReadFull(failed, probe); e == nil {
			t.Fatal("dead core fell back to direct")
		}
	}
}

// A non-loopback destination is essential: nethub intentionally bypasses
// localhost services, so a loopback echo would not exercise encryption.
func testLocalIP(t *testing.T) string {
	t.Helper()
	addresses, e := net.InterfaceAddrs()
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range addresses {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Fatal("non-loopback IPv4 required for egress test")
	return ""
}
func TestEncryptedUDPThroughAuthenticatedEntry(t *testing.T) {
	peer := shadowsocksPeer(t)
	encryptedUDP(t, Node{Type: "ss", Outbound: map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": peer, "method": "aes-128-gcm", "password": "test-password"}})
}
func encryptedUDP(t *testing.T, n Node) {
	t.Helper()
	target, e := net.ListenPacket("udp4", net.JoinHostPort(testLocalIP(t), "0"))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, e := target.ReadFrom(buf)
			if e != nil {
				return
			}
			target.WriteTo(buf[:n], a)
		}
	}()
	m := NewManager()
	defer m.Stop()
	b, _ := json.Marshal(Configuration{Mode: "node", Node: &n})
	s, e := m.Configure(b)
	if e != nil {
		t.Fatal(e)
	}
	control, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port), 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	control.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, e = io.ReadFull(control, reply); e != nil || reply[1] != 2 {
		t.Fatal("SOCKS method", e)
	}
	auth := []byte{1, 7}
	auth = append(auth, []byte("default")...)
	auth = append(auth, byte(len(s.Password)))
	auth = append(auth, []byte(s.Password)...)
	control.Write(auth)
	if _, e = io.ReadFull(control, reply); e != nil || reply[1] != 0 {
		t.Fatal("SOCKS auth", e)
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	response := make([]byte, 10)
	if _, e = io.ReadFull(control, response); e != nil || response[1] != 0 || response[3] != 1 {
		t.Fatalf("UDP associate %v %v", response, e)
	}
	relay := &net.UDPAddr{IP: net.IP(response[4:8]), Port: int(binary.BigEndian.Uint16(response[8:]))}
	udp, e := net.DialUDP("udp4", nil, relay)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	dest := target.LocalAddr().(*net.UDPAddr)
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, dest.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(dest.Port))
	packet = append(packet, []byte("encrypted-udp")...)
	if _, e = udp.Write(packet); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 2048)
	count, e := udp.Read(buf)
	if e != nil {
		t.Fatal(e)
	}
	if count < 10 || string(buf[10:count]) != "encrypted-udp" || !net.IP(buf[4:8]).Equal(dest.IP) || int(binary.BigEndian.Uint16(buf[8:10])) != dest.Port {
		t.Fatalf("UDP source/data mismatch: %x", buf[:count])
	}
}

// Each protocol peer terminates its real encrypted transport before forwarding
// to the local non-loopback echo target; no outbound dialing is mocked.
func protocolPeer(t *testing.T, kind string) Node {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	input := map[string]any{"type": kind, "listen": "127.0.0.1", "listen_port": port}
	output := map[string]any{"type": kind, "server": "127.0.0.1", "server_port": port}
	switch kind {
	case "vmess":
		input["users"] = []any{map[string]any{"uuid": uuid}}
		output["uuid"] = uuid
		output["security"] = "aes-128-gcm"
	case "vless":
		input["users"] = []any{map[string]any{"uuid": uuid}}
		output["uuid"] = uuid
	case "trojan":
		input["users"] = []any{map[string]any{"password": "test-password"}}
		output["password"] = "test-password"
	}
	// TLS makes VLESS and Trojan tests cover authenticated encrypted transport.
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	input["tls"] = map[string]any{"enabled": true, "certificate": []string{cert}, "key": []string{keyPEM}}
	output["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}
	ctx := testPeerContext(coreContext())
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "dns": map[string]any{"servers": []any{map[string]any{"type": "hosts"}}}, "inbounds": []any{input}, "outbounds": []any{map[string]any{"type": "direct", "tag": "local"}}, "route": map[string]any{"final": "local"}})
	var o option.Options
	if e = sj.UnmarshalContext(ctx, raw, &o); e != nil {
		t.Fatal(e)
	}
	peer, e := box.New(box.Options{Context: ctx, Options: o})
	if e != nil {
		t.Fatal(e)
	}
	if e = peer.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peer.Close() })
	return Node{Type: kind, Outbound: output}
}
func TestEncryptedProtocolTCP(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			node := protocolPeer(t, kind)
			ln, e := net.Listen("tcp4", net.JoinHostPort(testLocalIP(t), "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			go func() {
				c, e := ln.Accept()
				if e == nil {
					defer c.Close()
					io.Copy(c, c)
				}
			}()
			m := NewManager()
			defer m.Stop()
			raw, _ := json.Marshal(Configuration{Mode: "node", Node: &node})
			status, e := m.Configure(raw)
			if e != nil {
				t.Fatal(e)
			}
			dialer, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", status.Port), &proxy.Auth{User: "default", Password: status.Password}, &net.Dialer{Timeout: 3 * time.Second})
			if e != nil {
				t.Fatal(e)
			}
			c, e := dialer.Dial("tcp", ln.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			c.Write([]byte("encrypted"))
			got := make([]byte, 9)
			if _, e = io.ReadFull(c, got); e != nil || string(got) != "encrypted" {
				t.Fatalf("real encrypted echo: %q %v", got, e)
			}
		})
	}
}

func TestEncryptedProtocolUDP(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		t.Run(kind, func(t *testing.T) { encryptedUDP(t, protocolPeer(t, kind)) })
	}
}
