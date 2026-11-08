package appproxy

import (
	"context"
	"encoding/json"
	"net"
	"strconv"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	serviceRegistry "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	singjson "github.com/sagernet/sing/common/json"
)

func coreContext() context.Context {
	i := inbound.NewRegistry()
	socks.RegisterInbound(i)
	o := outbound.NewRegistry()
	shadowsocks.RegisterOutbound(o)
	vmess.RegisterOutbound(o)
	vless.RegisterOutbound(o)
	trojan.RegisterOutbound(o)
	d := dns.NewTransportRegistry()
	hosts.RegisterTransport(d)
	return box.Context(context.Background(), i, o, endpoint.NewRegistry(), d, serviceRegistry.NewRegistry(), certificate.NewRegistry())
}
func startCore(o map[string]any, password string) (*box.Box, int, error) {
	// The port reservation is released immediately before sing-box binds. A bind
	// race fails configuration; it never selects a direct route.
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, 0, e
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	clone := map[string]any{}
	for k, v := range o {
		clone[k] = v
	}
	clone["tag"] = "selected"
	config := map[string]any{"log": map[string]any{"disabled": true}, "dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "no-network-dns"}}}, "inbounds": []any{map[string]any{"type": "socks", "tag": "entry", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "core", "password": password}}}}, "outbounds": []any{clone}, "route": map[string]any{"final": "selected"}}
	b, _ := json.Marshal(config)
	ctx := coreContext()
	var options option.Options
	if e = singjson.UnmarshalContext(ctx, b, &options); e != nil {
		return nil, 0, e
	}
	instance, e := box.New(box.Options{Context: ctx, Options: options})
	if e != nil {
		return nil, 0, e
	}
	if e = instance.Start(); e != nil {
		instance.Close()
		return nil, 0, e
	}
	return instance, port, nil
}
func portOf(addr string) int { _, s, _ := net.SplitHostPort(addr); p, _ := strconv.Atoi(s); return p }
