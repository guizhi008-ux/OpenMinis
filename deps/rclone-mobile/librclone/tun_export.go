package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TUN bridge for the PacketTunnel extension (verification build).
//
// The extension process starts its own Xray instance (the same export the
// app uses) and then terminates the tunnel's IP flows in a gVisor netstack,
// forwarding every TCP connection and UDP flow to that Xray's SOCKS5
// inbound on 127.0.0.1:10808. Swift pumps raw packets both ways through
// MinisTunWritePacket / MinisTunReadPacket.
//
// IPv4 only in this proof build. ICMP is not forwarded (SOCKS cannot carry
// it); TCP + UDP (including DNS) cover the verification goal.

const (
	tunNICID    = tcpip.NICID(1)
	tunSocksAddr = "127.0.0.1:10808"
	tunMTU      = 1500
)

var (
	tunMu    sync.Mutex
	tunStack *stack.Stack
	tunEP    *channel.Endpoint
)

//export MinisTunStart
func MinisTunStart(xrayJSON *C.char) *C.char {
	tunMu.Lock()
	defer tunMu.Unlock()
	if tunStack != nil {
		return C.CString("tun: already running")
	}
	// Start the proxy core inside this (extension) process first.
	res := MinisXrayStart(xrayJSON)
	errStr := C.GoString(res)
	MinisRcloneFreeString(res)
	if errStr != "" {
		return C.CString("tun: xray: " + errStr)
	}

	ep := channel.New(1024, tunMTU, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(tunNICID, ep); err != nil {
		MinisXrayStop()
		return C.CString("tun: create NIC: " + err.String())
	}
	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(tunNICID, addr, stack.AddressProperties{}); err != nil {
		s.Close()
		MinisXrayStop()
		return C.CString("tun: add address: " + err.String())
	}
	s.SetPromiscuousMode(tunNICID, true)
	s.SetSpoofing(tunNICID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: tunNICID},
	})

	tcpFwd := tcp.NewForwarder(s, 0, 1024, tunHandleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, tunHandleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	tunEP = ep
	tunStack = s
	return C.CString("")
}

//export MinisTunStop
func MinisTunStop() {
	tunMu.Lock()
	defer tunMu.Unlock()
	if tunStack != nil {
		tunStack.Close()
		tunStack = nil
	}
	if tunEP != nil {
		tunEP.Close()
		tunEP = nil
	}
	MinisXrayStop()
}

//export MinisTunRunning
func MinisTunRunning() C.int {
	tunMu.Lock()
	defer tunMu.Unlock()
	if tunStack != nil {
		return 1
	}
	return 0
}

// MinisTunWritePacket injects one raw IPv4 packet from the tunnel into the
// netstack. family is the Darwin AF_* value from NEPacketTunnelFlow (only
// AF_INET = 2 is handled in this proof build).
//
//export MinisTunWritePacket
func MinisTunWritePacket(data *C.uchar, length C.int, family C.int) {
	if family != 2 || data == nil || length <= 0 {
		return
	}
	tunMu.Lock()
	ep := tunEP
	tunMu.Unlock()
	if ep == nil {
		return
	}
	b := C.GoBytes(unsafe.Pointer(data), length)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(b),
	})
	ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

// MinisTunReadPacket pops one outbound packet into buf. The first byte
// written is the address family (2), followed by the raw packet bytes.
// Returns the total number of bytes written, or 0 when the queue is empty.
//
//export MinisTunReadPacket
func MinisTunReadPacket(buf *C.uchar, bufLen C.int) C.int {
	tunMu.Lock()
	ep := tunEP
	tunMu.Unlock()
	if ep == nil || buf == nil || bufLen < 2 {
		return 0
	}
	pkt := ep.Read()
	if pkt == nil {
		return 0
	}
	total := pkt.Size()
	if total+1 > int(bufLen) {
		pkt.DecRef()
		return 0
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	out[0] = 2
	off := 1
	for _, sl := range pkt.AsSlices() {
		copy(out[off:], sl)
		off += len(sl)
	}
	pkt.DecRef()
	return C.int(off)
}

// MARK: - TCP forwarding

func tunHandleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	client := gonet.NewTCPConn(&wq, ep)
	go tunRelayTCP(client, id)
}

func tunRelayTCP(client *gonet.TCPConn, id stack.TransportEndpointID) {
	defer client.Close()
	dst := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprintf("%d", id.LocalPort))
	dialer, err := proxy.SOCKS5("tcp", tunSocksAddr, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return
	}
	remote, err := dialer.Dial("tcp", dst)
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, remote)
		done <- struct{}{}
	}()
	<-done
}

// MARK: - UDP forwarding (SOCKS5 UDP ASSOCIATE)

func tunHandleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)
	go tunRelayUDP(conn, id)
}

// socksUDPAssociate performs the SOCKS5 handshake + UDP ASSOCIATE and
// returns the control connection (keep alive for the session) and a UDP
// socket connected to the relay endpoint.
func socksUDPAssociate() (net.Conn, *net.UDPConn, error) {
	ctrl, err := net.DialTimeout("tcp", tunSocksAddr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (net.Conn, *net.UDPConn, error) {
		ctrl.Close()
		return nil, nil, e
	}
	// Greeting: VER=5, 1 method, NO-AUTH.
	if _, err := ctrl.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		return fail(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		return fail(fmt.Errorf("socks: auth rejected"))
	}
	// UDP ASSOCIATE request with 0.0.0.0:0.
	if _, err := ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		return fail(err)
	}
	if head[0] != 5 || head[1] != 0 {
		return fail(fmt.Errorf("socks: associate failed (%d)", head[1]))
	}
	var relayIP net.IP
	switch head[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			return fail(err)
		}
		relayIP = net.IP(b)
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(ctrl, lb); err != nil {
			return fail(err)
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(ctrl, b); err != nil {
			return fail(err)
		}
		ips, err := net.LookupIP(string(b))
		if err != nil || len(ips) == 0 {
			return fail(fmt.Errorf("socks: relay host lookup failed"))
		}
		relayIP = ips[0]
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(ctrl, b); err != nil {
			return fail(err)
		}
		relayIP = net.IP(b)
	default:
		return fail(fmt.Errorf("socks: bad atyp %d", head[3]))
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, pb); err != nil {
		return fail(err)
	}
	port := int(binary.BigEndian.Uint16(pb))
	if relayIP.IsUnspecified() {
		relayIP = net.ParseIP("127.0.0.1")
	}
	relay, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: port})
	if err != nil {
		return fail(err)
	}
	return ctrl, relay, nil
}

func tunRelayUDP(client *gonet.UDPConn, id stack.TransportEndpointID) {
	defer client.Close()
	ctrl, relay, err := socksUDPAssociate()
	if err != nil {
		return
	}
	defer ctrl.Close()
	defer relay.Close()

	dstIP := net.ParseIP(id.LocalAddress.String())
	if dstIP == nil {
		return
	}
	clientAddr := &net.UDPAddr{
		IP:   net.ParseIP(id.RemoteAddress.String()),
		Port: int(id.RemotePort),
	}

	// client -> remote: wrap payloads in SOCKS UDP datagrams for the
	// flow's fixed destination.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
			var hdr []byte
			if ip4 := dstIP.To4(); ip4 != nil {
				hdr = []byte{0, 0, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
			} else {
				ip16 := dstIP.To16()
				hdr = make([]byte, 0, 22)
				hdr = append(hdr, 0, 0, 0, 4)
				hdr = append(hdr, ip16...)
				hdr = append(hdr, 0, 0)
			}
			binary.BigEndian.PutUint16(hdr[len(hdr)-2:], id.LocalPort)
			msg := make([]byte, 0, len(hdr)+n)
			msg = append(msg, hdr...)
			msg = append(msg, buf[:n]...)
			if _, err := relay.Write(msg); err != nil {
				return
			}
		}
	}()

	// remote -> client: strip SOCKS UDP headers and hand payloads back.
	buf := make([]byte, 65535)
	for {
		_ = relay.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := relay.Read(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		off := 3
		switch buf[off] {
		case 1:
			off += 1 + 4 + 2
		case 3:
			if n < 5 {
				continue
			}
			off += 1 + 1 + int(buf[4]) + 2
		case 4:
			off += 1 + 16 + 2
		default:
			continue
		}
		if off > n {
			continue
		}
		if _, err := client.WriteTo(buf[off:n], clientAddr); err != nil {
			return
		}
	}
}
