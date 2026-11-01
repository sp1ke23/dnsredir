package dnsredir

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNewSocks5Dialer(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr bool
	}{
		{"socks5://127.0.0.1:1080", false},
		{"socks5h://127.0.0.1:1080", false},
		{"socks5://user:pass@127.0.0.1:1080", false},
		{"http://127.0.0.1:1080", true},
		{"socks5://", true},
		{"://bad", true},
	}
	for _, tt := range tests {
		d, err := newSocks5Dialer(tt.raw)
		if (err != nil) != tt.wantErr {
			t.Fatalf("newSocks5Dialer(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
		}
		if err == nil && d.String() == "" {
			t.Fatalf("newSocks5Dialer(%q) returned empty String()", tt.raw)
		}
	}
}

// fakeSocks5Server accepts a single SOCKS5 CONNECT request and echoes data
// back to the client.
func fakeSocks5Server(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Errorf("read greeting: %v", err)
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("read methods: %v", err)
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		t.Errorf("write method: %v", err)
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		t.Errorf("read request: %v", err)
		return
	}
	switch req[3] {
	case 1:
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			t.Errorf("read IPv4: %v", err)
			return
		}
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			t.Errorf("read domain length: %v", err)
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0]))); err != nil {
			t.Errorf("read domain: %v", err)
			return
		}
	case 4:
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			t.Errorf("read IPv6: %v", err)
			return
		}
	default:
		t.Errorf("unexpected address type %d", req[3])
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Errorf("read port: %v", err)
		return
	}

	switch req[1] {
	case 1: // CONNECT
		if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Errorf("write reply: %v", err)
			return
		}
		// Echo whatever the client sends.
		_, _ = io.Copy(conn, conn)
	case 3: // UDP ASSOCIATE
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Errorf("listen udp: %v", err)
			return
		}
		defer pc.Close()
		go func() {
			buf := make([]byte, 65535)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], addr)
			}
		}()
		port := pc.LocalAddr().(*net.UDPAddr).Port
		reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
		if _, err := conn.Write(reply); err != nil {
			t.Errorf("write udp reply: %v", err)
			return
		}
		// Keep the control connection open for the association lifetime.
		_, _ = io.Copy(io.Discard, conn)
	default:
		t.Errorf("unexpected command %d", req[1])
	}
}

func TestDialProxyConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fakeSocks5Server(t, ln)

	pd, err := newSocks5Dialer("socks5://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialProxyConn("tcp", "example.com:80", nil, 2*time.Second, pd)
	if err != nil {
		t.Fatalf("dialProxyConn: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
}

func TestDialProxyUDPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fakeSocks5Server(t, ln)

	pd, err := newSocks5Dialer("socks5://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dialProxyConn("udp", "example.com:53", nil, 2*time.Second, pd)
	if err != nil {
		t.Fatalf("dialProxyConn(udp): %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}
}
