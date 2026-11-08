package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/rclone/rclone/fs/fshttp"
)

// A real SOCKS upstream echoes only after it receives the unresolved target.
// The production init callback, appProxy manager, and local authenticated entry
// all participate; backup.invalid cannot be reached by a direct fallback.
func TestRcloneBackupThroughEntryAndStop(t *testing.T) {
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := peer.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 2)
		if _, err = io.ReadFull(c, header); err != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err = io.ReadFull(c, methods); err != nil {
			return
		}
		c.Write([]byte{5, 0})
		req := make([]byte, 5)
		if _, err = io.ReadFull(c, req); err != nil {
			return
		}
		if req[3] != 3 {
			seen <- "target was locally resolved"
			return
		}
		host := make([]byte, int(req[4])+2)
		if _, err = io.ReadFull(c, host); err != nil {
			return
		}
		seen <- string(host[:len(host)-2])
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		io.Copy(c, c)
	}()
	defer appProxy.Configure([]byte(`{"mode":"off"}`))
	port := peer.Addr().(*net.TCPAddr).Port
	config := fmt.Sprintf(`{"mode":"manual","manual":{"type":"socks5","host":"127.0.0.1","port":%d}}`, port)
	if _, err = appProxy.Configure([]byte(config)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := fshttp.NewDialer(ctx).DialContext(ctx, "tcp", net.JoinHostPort("backup.invalid", strconv.Itoa(445)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte("backup")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err = io.ReadFull(c, got); err != nil || string(got) != "backup" {
		t.Fatalf("echo %q %v", got, err)
	}
	if host := <-seen; host != "backup.invalid" {
		t.Fatalf("target %s", host)
	}
	appProxy.Stop()
	if _, err = c.Read(got); err == nil {
		t.Fatal("Stop retained backup tunnel")
	}
	if _, err = fshttp.NewDialer(ctx).DialContext(ctx, "tcp", "backup.invalid:445"); err == nil {
		t.Fatal("stopped entry allowed backup")
	}
}
