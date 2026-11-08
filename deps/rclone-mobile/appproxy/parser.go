// Package appproxy owns app-only strict proxy lifecycle and offline subscriptions.
package appproxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const MaxImportBytes = 1 << 20
const maxNodes = 2048

var errLink = errors.New("invalid or unsupported node parameters")

type Node struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Outbound map[string]any `json:"outbound"`
}
type Issue struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}
type ImportResult struct {
	Nodes  []Node  `json:"nodes"`
	Issues []Issue `json:"issues"`
}

func decode64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errLink
}
func Import(text string) (ImportResult, error) {
	r := ImportResult{Nodes: []Node{}, Issues: []Issue{}}
	if len(text) > MaxImportBytes {
		return r, errors.New("subscription exceeds size limit")
	}
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "://") {
		b, e := decode64(strings.Join(strings.Fields(text), ""))
		if e != nil {
			return r, errors.New("unsupported subscription format")
		}
		text = string(b)
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i >= maxNodes {
			return r, errors.New("subscription exceeds line limit")
		}
		n, e := parseLink(line)
		if e != nil {
			r.Issues = append(r.Issues, Issue{i + 1, errLink.Error()})
			continue
		}
		if !seen[n.ID] {
			r.Nodes = append(r.Nodes, n)
			seen[n.ID] = true
		}
	}
	return r, nil
}
func parseLink(s string) (Node, error) {
	n := Node{Outbound: map[string]any{}}
	if strings.HasPrefix(s, "vmess://") {
		return parseVMess(strings.TrimPrefix(s, "vmess://"))
	}
	// Legacy SS encodes the entire authority rather than just userinfo.
	if strings.HasPrefix(s, "ss://") {
		body := strings.TrimPrefix(s, "ss://")
		auth, frag, _ := strings.Cut(body, "#")
		if !strings.Contains(auth, "@") {
			b, e := decode64(strings.TrimSuffix(auth, "/"))
			if e != nil {
				return n, errLink
			}
			s = "ss://" + string(b)
			if frag != "" {
				s += "#" + frag
			}
		}
	}
	u, e := url.Parse(s)
	if e != nil || u.User == nil || u.Hostname() == "" {
		return n, errLink
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return n, errLink
	}
	if u.Path != "" && u.Path != "/" {
		return n, errLink
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return n, errLink
	}
	for _, v := range q {
		if len(v) != 1 {
			return n, errLink
		}
	}
	n.Type = u.Scheme
	n.Name = u.Fragment
	if n.Name == "" {
		n.Name = n.Type + " node"
	}
	o := n.Outbound
	o["server"] = u.Hostname()
	o["server_port"] = port
	switch n.Type {
	case "ss":
		if len(q) != 0 {
			return n, errLink
		}
		o["type"] = "shadowsocks"
		creds := u.User.String()
		if !strings.Contains(creds, ":") {
			b, e := decode64(creds)
			if e != nil {
				return n, errLink
			}
			creds = string(b)
		} else {
			creds, e = url.PathUnescape(creds)
			if e != nil {
				return n, errLink
			}
		}
		method, pw, ok := strings.Cut(creds, ":")
		if !ok || pw == "" {
			return n, errLink
		}
		switch method {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		default:
			return n, errLink
		}
		o["method"] = method
		o["password"] = pw
	case "vless", "trojan":
		o["type"] = n.Type
		if _, ok := u.User.Password(); ok {
			return n, errLink
		}
		credential := u.User.Username()
		if credential == "" {
			return n, errLink
		}
		if n.Type == "vless" {
			if !validUUID(credential) {
				return n, errLink
			}
			o["uuid"] = credential
		} else {
			o["password"] = credential
		}
		allowed := map[string]bool{}
		for _, k := range []string{"security", "type", "sni", "peer", "alpn", "allowInsecure", "insecure", "path", "host", "serviceName", "flow", "encryption", "packetEncoding", "pbk", "sid", "fp", "spx"} {
			allowed[k] = true
		}
		for k := range q {
			if !allowed[k] {
				return n, errLink
			}
		}
		if n.Type == "trojan" {
			for _, k := range []string{"encryption", "flow", "packetEncoding"} {
				if _, exists := q[k]; exists {
					return n, errLink
				}
			}
		}
		if q.Get("encryption") != "" && q.Get("encryption") != "none" {
			return n, errLink
		}
		if f := q.Get("flow"); f != "" {
			if n.Type != "vless" || f != "xtls-rprx-vision" {
				return n, errLink
			}
			o["flow"] = f
			if q.Get("type") != "" && q.Get("type") != "tcp" {
				return n, errLink
			}
			if s := q.Get("security"); s != "tls" && s != "reality" {
				return n, errLink
			}
		}
		security := q.Get("security")
		if security == "" && n.Type == "trojan" {
			security = "tls"
		}
		if security != "" && security != "none" && security != "tls" && security != "reality" {
			return n, errLink
		}
		if n.Type == "trojan" && security != "tls" && security != "reality" {
			return n, errLink
		}
		if security == "tls" {
			for _, k := range []string{"pbk", "sid", "fp", "spx"} {
				if q.Get(k) != "" {
					return n, errLink
				}
			}
			tls, e := tlsFields(q)
			if e != nil {
				return n, e
			}
			o["tls"] = tls
		} else if security == "reality" {
			// Reality runs over the raw transport only; ws/grpc Reality links
			// are not produced by mainstream servers and stay rejected.
			if t := q.Get("type"); t != "" && t != "tcp" {
				return n, errLink
			}
			tls, e := realityFields(q)
			if e != nil {
				return n, e
			}
			o["tls"] = tls
		} else {
			for _, k := range []string{"sni", "peer", "alpn", "allowInsecure", "insecure", "pbk", "sid", "fp", "spx"} {
				if q.Get(k) != "" {
					return n, errLink
				}
			}
		}
		if e := transportFields(o, q.Get("type"), q.Get("path"), q.Get("host"), q.Get("serviceName")); e != nil {
			return n, e
		}
		if p := q.Get("packetEncoding"); p != "" {
			if n.Type != "vless" || (p != "xudp" && p != "packetaddr") {
				return n, errLink
			}
			o["packet_encoding"] = p
		}
	default:
		return n, errLink
	}
	return finalize(n)
}
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}
func tlsFields(q url.Values) (map[string]any, error) {
	if a, b := q.Get("insecure"), q.Get("allowInsecure"); a != "" && b != "" {
		av := a == "1" || a == "true"
		bv := b == "1" || b == "true"
		if av != bv {
			return nil, errLink
		}
	}
	t := map[string]any{"enabled": true}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if q.Get("sni") != "" && q.Get("peer") != "" && q.Get("sni") != q.Get("peer") {
		return nil, errLink
	}
	if sni != "" {
		t["server_name"] = sni
	}
	if a := q.Get("alpn"); a != "" {
		t["alpn"] = strings.Split(a, ",")
	}
	for _, k := range []string{"allowInsecure", "insecure"} {
		if s := q.Get(k); s != "" {
			if s != "0" && s != "1" && s != "true" && s != "false" {
				return nil, errLink
			}
			if s == "1" || s == "true" {
				t["insecure"] = true
			}
		}
	}
	return t, nil
}
// realityFields builds the sing-box TLS block for security=reality links.
// pbk must be the base64 (raw or padded, std or URL) encoding of a 32-byte
// X25519 public key; sid is an optional hex short ID of at most 8 bytes.
// fp defaults to chrome, matching mainstream client behavior. spx (spiderX)
// is accepted and ignored: it only steers Xray's handshake crawling and has
// no effect on the connection itself.
func realityFields(q url.Values) (map[string]any, error) {
	t, e := tlsFields(q)
	if e != nil {
		return nil, e
	}
	if _, bad := t["insecure"]; bad {
		return nil, errLink
	}
	pbk := q.Get("pbk")
	key, e := decode64(pbk)
	if e != nil || len(key) != 32 {
		return nil, errLink
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	switch fp {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
	default:
		return nil, errLink
	}
	t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	reality := map[string]any{"enabled": true, "public_key": pbk}
	if sid := q.Get("sid"); sid != "" {
		if len(sid) > 16 || len(sid)%2 != 0 {
			return nil, errLink
		}
		if _, e := hex.DecodeString(sid); e != nil {
			return nil, errLink
		}
		reality["short_id"] = sid
	}
	t["reality"] = reality
	return t, nil
}
func transportFields(o map[string]any, kind, path, host, service string) error {
	switch kind {
	case "", "tcp":
		if path != "" || host != "" || service != "" {
			return errLink
		}
	case "ws":
		if service != "" {
			return errLink
		}
		t := map[string]any{"type": "ws"}
		if path != "" {
			t["path"] = path
		}
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		o["transport"] = t
	case "grpc":
		if path != "" || host != "" {
			return errLink
		}
		o["transport"] = map[string]any{"type": "grpc", "service_name": service}
	default:
		return errLink
	}
	return nil
}
func finalize(n Node) (Node, error) {
	b, e := json.Marshal(n.Outbound)
	if e != nil {
		return n, errLink
	}
	h := sha256.Sum256(b)
	n.ID = hex.EncodeToString(h[:16])
	return n, nil
}
func parseVMess(encoded string) (Node, error) {
	n := Node{Type: "vmess", Outbound: map[string]any{"type": "vmess"}}
	b, e := decode64(encoded)
	if e != nil {
		return n, e
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(b, &v) != nil {
		return n, errLink
	}
	allowed := map[string]bool{}
	for _, k := range []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "allowInsecure"} {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return n, errLink
		}
	}
	// VMess share links use strings, with numeric v/port/aid tolerated.
	// A boolean TLS or null transport must never become an empty default.
	for k, raw := range v {
		if len(raw) == 0 || string(raw) == "null" {
			return n, errLink
		}
		var str string
		if json.Unmarshal(raw, &str) == nil {
			continue
		}
		if k != "v" && k != "port" && k != "aid" {
			return n, errLink
		}
		var num json.Number
		if json.Unmarshal(raw, &num) != nil {
			return n, errLink
		}
	}
	get := func(k string) string {
		var s string
		if json.Unmarshal(v[k], &s) == nil {
			return s
		}
		var number json.Number
		if json.Unmarshal(v[k], &number) == nil {
			return string(number)
		}
		return ""
	}
	if version := get("v"); version != "" && version != "2" {
		return n, errLink
	}
	port, e := strconv.Atoi(get("port"))
	if e != nil || port < 1 || port > 65535 || get("add") == "" || !validUUID(get("id")) {
		return n, errLink
	}
	if get("type") != "" && get("type") != "none" {
		return n, errLink
	}
	aid := 0
	if s := get("aid"); s != "" {
		aid, e = strconv.Atoi(s)
		if e != nil || aid < 0 || aid > 65535 {
			return n, errLink
		}
	}
	o := n.Outbound
	o["server"] = get("add")
	o["server_port"] = port
	o["uuid"] = get("id")
	o["alter_id"] = aid
	security := get("scy")
	if security == "" {
		security = "auto"
	}
	switch security {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
	default:
		return n, errLink
	}
	o["security"] = security
	if e := transportFields(o, get("net"), get("path"), get("host"), ""); e != nil {
		return n, e
	}
	if get("tls") != "" && get("tls") != "none" {
		if get("tls") != "tls" {
			return n, errLink
		}
		q := url.Values{}
		for _, k := range []string{"sni", "alpn", "allowInsecure"} {
			if s := get(k); s != "" {
				q.Set(k, s)
			}
		}
		tls, e := tlsFields(q)
		if e != nil {
			return n, e
		}
		o["tls"] = tls
	} else if get("sni") != "" || get("alpn") != "" || get("allowInsecure") != "" {
		return n, errLink
	}
	n.Name = get("ps")
	if n.Name == "" {
		n.Name = "vmess node"
	}
	return finalize(n)
}

// validateServer deliberately does not resolve: bootstrap must be explicitly authorized.
func validateServer(host string) bool {
	return host != "" && !strings.ContainsAny(host, " /\\\x00") && (net.ParseIP(host) != nil || !strings.Contains(host, ":"))
}
