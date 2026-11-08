package nethub

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// dialSOCKSUDP keeps the RFC 1928 control connection alive for the lifetime
// of a connected datagram flow. Only proxy infrastructure is dialed here;
// the destination hostname stays in the SOCKS datagram header.
func dialSOCKSUDP(ctx context.Context, base *net.Dialer, u Upstream, destination string) (net.Conn, error) {
	if u.Type != "socks5" {
		return nil, errors.New("selected upstream does not support UDP")
	}
	ctl, err := base.DialContext(ctx, "tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
	if err != nil {
		return nil, stageErr("proxy-connect", err)
	}
	ok := false
	defer func() {
		if !ok {
			ctl.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		ctl.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() { ctl.Close() })
	defer stopCancel()
	method := byte(0)
	if u.Username != "" || u.Password != "" {
		method = 2
	}
	if len(u.Username) > 255 || len(u.Password) > 255 {
		return nil, errors.New("SOCKS credentials too long")
	}
	if _, err = ctl.Write([]byte{5, 1, method}); err != nil {
		return nil, err
	}
	var answer [2]byte
	if _, err = io.ReadFull(ctl, answer[:]); err != nil {
		return nil, err
	}
	if answer[0] != 5 || answer[1] != method {
		return nil, errors.New("SOCKS authentication method rejected")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(u.Username))}, u.Username...)
		auth = append(auth, byte(len(u.Password)))
		auth = append(auth, u.Password...)
		if _, err = ctl.Write(auth); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(ctl, answer[:]); err != nil {
			return nil, err
		}
		if answer != [2]byte{1, 0} {
			return nil, errors.New("SOCKS authentication rejected")
		}
	}
	if _, err = ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err = io.ReadFull(ctl, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, errors.New("SOCKS UDP association rejected")
	}
	var ip net.IP
	switch reply[3] {
	case atypIPv4:
		ip = make(net.IP, 4)
	case atypIPv6:
		ip = make(net.IP, 16)
	default:
		return nil, errors.New("SOCKS UDP relay must use an IP address")
	}
	if _, err = io.ReadFull(ctl, ip); err != nil {
		return nil, err
	}
	var portBytes [2]byte
	if _, err = io.ReadFull(ctl, portBytes[:]); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if port == 0 {
		return nil, errors.New("SOCKS UDP relay port is zero")
	}
	if ip.IsUnspecified() {
		ip = ctl.RemoteAddr().(*net.TCPAddr).IP
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	host, portString, err := net.SplitHostPort(destination)
	targetPort, portErr := strconv.Atoi(portString)
	if err != nil || portErr != nil || len(host) > 255 || targetPort < 1 || targetPort > 65535 {
		udp.Close()
		return nil, errors.New("invalid UDP destination")
	}
	ctl.SetDeadline(time.Time{})
	c := &socksPacketConn{UDPConn: udp, control: ctl, header: udpHeader(host, targetPort), destination: packetAddr(destination)}
	ok = true
	go func() { var b [1]byte; ctl.Read(b[:]); c.Close() }()
	return c, nil
}

type packetAddr string

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }

type socksPacketConn struct {
	*net.UDPConn
	control     net.Conn
	header      []byte
	destination net.Addr
	once        sync.Once
}

func (c *socksPacketConn) Write(b []byte) (int, error) {
	if len(b)+len(c.header) > 65507 {
		return 0, errors.New("UDP datagram too large")
	}
	frame := append(append([]byte(nil), c.header...), b...)
	n, err := c.UDPConn.Write(frame)
	if err != nil {
		return 0, err
	}
	if n != len(frame) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (c *socksPacketConn) Read(b []byte) (int, error) {
	frame := make([]byte, 65535)
	n, err := c.UDPConn.Read(frame)
	if err != nil {
		return 0, err
	}
	_, _, payload, err := parseUDPHeader(frame[:n])
	if err != nil {
		return 0, err
	}
	return copy(b, payload), nil
}

func (c *socksPacketConn) RemoteAddr() net.Addr { return c.destination }
func (c *socksPacketConn) Close() error {
	c.once.Do(func() { c.control.Close(); c.UDPConn.Close() })
	return nil
}
