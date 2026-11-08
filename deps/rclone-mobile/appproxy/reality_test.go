package appproxy

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
	"golang.org/x/net/proxy"
)

func realityKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()),
		base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// realityDest stands in for the camouflage site (e.g. www.amazon.com): the
// Reality server borrows its certificate during the handshake.
func realityDest(t *testing.T) int {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "www.amazon.com"}, DNSNames: []string{"www.amazon.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, e := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func realityPeer(t *testing.T, priv string, destPort int) int {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	input := map[string]any{
		"type": "vless", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}},
		"tls": map[string]any{
			"enabled": true, "server_name": "www.amazon.com",
			"reality": map[string]any{
				"enabled": true, "private_key": priv, "short_id": []string{"ab12"},
				"handshake": map[string]any{"server": "127.0.0.1", "server_port": destPort},
			},
		},
	}
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
	return port
}

func realityEcho(t *testing.T) string {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func realityDial(t *testing.T, link, target string) error {
	t.Helper()
	r, e := Import(link)
	if e != nil || len(r.Nodes) != 1 {
		t.Fatalf("import: %v %+v", e, r)
	}
	if e := validateOutbound(r.Nodes[0]); e != nil {
		t.Fatalf("validateOutbound rejected reality node: %v", e)
	}
	core, port, e := startCore(r.Nodes[0].Outbound, "core-password")
	if e != nil {
		t.Fatalf("core start: %v", e)
	}
	defer core.Close()
	d, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &proxy.Auth{User: "core", Password: "core-password"}, &net.Dialer{Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	c, e := d.Dial("tcp", target)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = c.Write([]byte("reality-echo")); e != nil {
		return e
	}
	got := make([]byte, len("reality-echo"))
	if _, e = io.ReadFull(c, got); e != nil {
		return e
	}
	if string(got) != "reality-echo" {
		return fmt.Errorf("echo mismatch: %q", got)
	}
	return nil
}

func TestRealityVLESSLoopback(t *testing.T) {
	priv, pub := realityKeyPair(t)
	peerPort := realityPeer(t, priv, realityDest(t))
	target := realityEcho(t)
	good := fmt.Sprintf("vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&fp=chrome&pbk=%s&sid=ab12#R", peerPort, pub)
	if e := realityDial(t, good, target); e != nil {
		t.Fatalf("reality echo failed: %v", e)
	}
	// A wrong short ID must be rejected by the server, never fall back.
	badSID := fmt.Sprintf("vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&pbk=%s&sid=cd34#R", peerPort, pub)
	if e := realityDial(t, badSID, target); e == nil {
		t.Fatal("wrong short id accepted")
	}
	// A wrong public key must fail the same way.
	_, otherPub := realityKeyPair(t)
	badKey := fmt.Sprintf("vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&pbk=%s&sid=ab12#R", peerPort, otherPub)
	if e := realityDial(t, badKey, target); e == nil {
		t.Fatal("wrong public key accepted")
	}
}
