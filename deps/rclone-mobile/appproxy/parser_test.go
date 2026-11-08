package appproxy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestImportPreservesAndDeduplicates(t *testing.T) {
	ss := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:p:a@ss")) + "@127.0.0.1:8388#My%20Node"
	vless := "vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=tls&type=ws&path=%2Fa%3Fb%3D1&host=example.org&sni=tls.example.org#V"
	text := ss + "\n" + vless + "\n" + ss + "\ntrojan://secret@127.0.0.1:443?plugin=bad\n"
	for _, input := range []string{text, base64.StdEncoding.EncodeToString([]byte(text))} {
		result, err := Import(input)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Nodes) != 2 || len(result.Issues) != 1 {
			t.Fatalf("counts: %d %d", len(result.Nodes), len(result.Issues))
		}
		if result.Nodes[0].Name != "My Node" || result.Nodes[0].Outbound["password"] != "p:a@ss" {
			t.Fatal("SS fields lost")
		}
		tr := result.Nodes[1].Outbound["transport"].(map[string]any)
		if tr["path"] != "/a?b=1" {
			t.Fatal("encoded path lost")
		}
		if strings.Contains(result.Issues[0].Reason, "secret") {
			t.Fatal("credential leak")
		}
	}
}
func TestImportRejectsInvalidAndBounds(t *testing.T) {
	for _, input := range []string{"vless://id@127.0.0.1:0", "trojan://pw@127.0.0.1:65536", "ss://YQ@127.0.0.1:3", "trojan://pw@127.0.0.1:443?security=none"} {
		got, err := Import(input)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Nodes) != 0 || len(got.Issues) != 1 {
			t.Fatal("accepted invalid link")
		}
	}
	if _, err := Import(strings.Repeat("a", MaxImportBytes+1)); err == nil {
		t.Fatal("missing size limit")
	}
}
func TestVMessFields(t *testing.T) {
	data := `{"v":"2","ps":"V","add":"127.0.0.1","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","scy":"auto","net":"ws","type":"none","host":"web.example","path":"/x","tls":"tls","sni":"tls.example","alpn":"h2,http/1.1"}`
	got, err := Import("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(data)))
	if err != nil || len(got.Nodes) != 1 {
		t.Fatalf("vmess: %v %+v", err, got)
	}
}
func TestImportRejectsAmbiguousOrDiscardedParameters(t *testing.T) {
	for _, link := range []string{
		"trojan://pw@127.0.0.1:443?insecure=0&allowInsecure=1",
		"trojan://pw@127.0.0.1:443?encryption=none",
		"vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=tls&type=ws&flow=xtls-rprx-vision",
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(`{"v":"99","add":"127.0.0.1","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","net":"tcp"}`)),
	} {
		r, e := Import(link)
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Nodes) != 0 || len(r.Issues) != 1 {
			t.Fatal("ambiguous parameter accepted")
		}
	}
}
func realityKey() string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}
func TestImportRealityVLESS(t *testing.T) {
	link := "vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&fp=chrome&pbk=" + realityKey() + "&sid=ab12#Seoul"
	r, err := Import(link)
	if err != nil || len(r.Nodes) != 1 || len(r.Issues) != 0 {
		t.Fatalf("reality vless: %v %+v", err, r)
	}
	o := r.Nodes[0].Outbound
	if o["flow"] != "xtls-rprx-vision" {
		t.Fatal("vision flow lost")
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "www.amazon.com" {
		t.Fatal("reality sni lost")
	}
	utls := tls["utls"].(map[string]any)
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" {
		t.Fatal("utls block wrong")
	}
	reality := tls["reality"].(map[string]any)
	if reality["enabled"] != true || reality["public_key"] != realityKey() || reality["short_id"] != "ab12" {
		t.Fatal("reality block wrong")
	}
}
func TestImportRealityDefaults(t *testing.T) {
	for _, link := range []string{
		"vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=reality&pbk=" + realityKey(),
		"vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&spx=%2Fspider",
		"trojan://secret@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&sni=www.amazon.com",
	} {
		r, err := Import(link)
		if err != nil || len(r.Nodes) != 1 {
			t.Fatalf("reality defaults: %v %+v", err, r)
		}
		fp := r.Nodes[0].Outbound["tls"].(map[string]any)["utls"].(map[string]any)["fingerprint"]
		if fp != "chrome" {
			t.Fatal("default fingerprint is not chrome")
		}
	}
}
func TestImportRejectsBadReality(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	for _, link := range []string{
		"vless://" + uuid + "@127.0.0.1:443?security=reality",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=AAAA",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&sid=xyz",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&sid=ab123",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&fp=nokia",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&type=ws&path=%2Fx",
		"vless://" + uuid + "@127.0.0.1:443?security=reality&pbk=" + realityKey() + "&allowInsecure=1",
		"vless://" + uuid + "@127.0.0.1:443?flow=xtls-rprx-vision&security=none&pbk=" + realityKey(),
		"trojan://pw@127.0.0.1:443?security=reality",
	} {
		r, err := Import(link)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Nodes) != 0 || len(r.Issues) != 1 {
			t.Fatalf("bad reality link accepted: %s", link)
		}
	}
}
func TestVMessRejectsWrongParameterTypes(t *testing.T) {
	for _, field := range []string{`"tls":true`, `"net":null`, `"allowInsecure":true`, `"ps":23`} {
		raw := `{"add":"127.0.0.1","port":443,"id":"550e8400-e29b-41d4-a716-446655440000",` + field + `}`
		r, e := Import("vmess://" + base64.RawStdEncoding.EncodeToString([]byte(raw)))
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Nodes) != 0 || len(r.Issues) != 1 {
			t.Fatal("wrong VMess parameter type silently altered")
		}
	}
}
