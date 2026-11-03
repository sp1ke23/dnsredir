package dnsredir

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	xproxy "golang.org/x/net/proxy"
)

// socks5Dialer dials upstream connections through a SOCKS5 proxy.
type socks5Dialer struct {
	address string
	auth    *xproxy.Auth
	dialer  xproxy.Dialer
}

func newSocks5Dialer(raw string) (*socks5Dialer, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme %q, only socks5 is supported", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing proxy address")
	}

	var auth *xproxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &xproxy.Auth{User: u.User.Username(), Password: password}
	}

	d, err := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	return &socks5Dialer{address: u.Host, auth: auth, dialer: d}, nil
}

func (d *socks5Dialer) String() string {
	return "socks5://" + d.address
}

// DialContext implements xproxy.ContextDialer.
func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if cd, ok := d.dialer.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, address)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, err := d.dialer.Dial(network, address)
		ch <- dialResult{conn, err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dialProxyConn dials a DNS connection through the configured SOCKS5 proxy.
func dialProxyConn(network, address string, tlsConfig *tls.Config, timeout time.Duration, pd *socks5Dialer) (*dns.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		return dialProxyUDPConn(address, timeout, pd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := pd.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(network, "-tls") {
		cfg := &tls.Config{}
		if tlsConfig != nil {
			cfg = tlsConfig.Clone()
		}
		if cfg.ServerName == "" {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			cfg.ServerName = host
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	return &dns.Conn{Conn: conn}, nil
}

const (
	socks5Version         = 0x05
	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
)

// socks5UDPConn sends DNS messages through a SOCKS5 UDP association
// (RFC 1928 UDP ASSOCIATE). It implements net.PacketConn so that
// miekg/dns treats it as a datagram transport.
type socks5UDPConn struct {
	ctrl   net.Conn
	udp    *net.UDPConn
	header []byte // ATYP + DST.ADDR + DST.PORT
	buf    []byte
}

func (c *socks5UDPConn) Read(p []byte) (int, error) {
	n, err := c.udp.Read(c.buf)
	if err != nil {
		return 0, err
	}
	payload, err := stripUDPHeader(c.buf[:n])
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *socks5UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.udp.RemoteAddr(), err
}

func (c *socks5UDPConn) Write(p []byte) (int, error) {
	pkt := make([]byte, 3+len(c.header)+len(p))
	copy(pkt[3:], c.header)
	copy(pkt[3+len(c.header):], p)
	if _, err := c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func (c *socks5UDPConn) Close() error {
	ctrlErr := c.ctrl.Close()
	udpErr := c.udp.Close()
	if ctrlErr != nil {
		return ctrlErr
	}
	return udpErr
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.udp.RemoteAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// dialProxyUDPConn establishes a SOCKS5 UDP association and returns a
// datagram connection to address.
func dialProxyUDPConn(address string, timeout time.Duration, pd *socks5Dialer) (*dns.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ctrl, relay, err := pd.associate(ctx)
	if err != nil {
		return nil, err
	}

	header, err := encodeUDPHeader(address)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}

	udp, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}

	return &dns.Conn{Conn: &socks5UDPConn{
		ctrl:   ctrl,
		udp:    udp,
		header: header,
		buf:    make([]byte, 65535),
	}}, nil
}

// associate performs the SOCKS5 handshake and requests a UDP relay.
func (d *socks5Dialer) associate(ctx context.Context) (net.Conn, *net.UDPAddr, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	relay, err := d.negotiate(conn, socks5CmdUDPAssociate)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, relay, nil
}

func (d *socks5Dialer) negotiate(conn net.Conn, cmd byte) (*net.UDPAddr, error) {
	methods := []byte{0x00}
	if d.auth != nil {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[0] != socks5Version {
		return nil, fmt.Errorf("unexpected SOCKS version %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
	case 0x02:
		if d.auth == nil {
			return nil, fmt.Errorf("proxy requested username/password authentication")
		}
		if err := d.authenticate(conn); err != nil {
			return nil, err
		}
	case 0xFF:
		return nil, fmt.Errorf("proxy accepted none of the offered authentication methods")
	default:
		return nil, fmt.Errorf("proxy selected unsupported authentication method 0x%02x", resp[1])
	}

	req := []byte{socks5Version, cmd, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	return readUDPAssociateReply(conn)
}

func (d *socks5Dialer) authenticate(conn net.Conn) error {
	user, pass := []byte(d.auth.User), []byte(d.auth.Password)
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("username/password too long")
	}
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("proxy authentication failed with status 0x%02x", resp[1])
	}
	return nil
}

func readUDPAssociateReply(conn net.Conn) (*net.UDPAddr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != socks5Version {
		return nil, fmt.Errorf("unexpected SOCKS version %d", head[0])
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE failed with status 0x%02x", head[1])
	}

	var ip net.IP
	switch head[3] {
	case socks5AtypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case socks5AtypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case socks5AtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		addr, err := net.ResolveIPAddr("ip", string(b))
		if err != nil {
			return nil, err
		}
		ip = addr.IP
	default:
		return nil, fmt.Errorf("unexpected address type 0x%02x", head[3])
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return nil, err
	}

	if ip == nil || ip.IsUnspecified() {
		tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("unexpected proxy remote address %v", conn.RemoteAddr())
		}
		ip = tcpAddr.IP
	}
	return &net.UDPAddr{IP: ip, Port: int(port[0])<<8 | int(port[1])}, nil
}

// encodeUDPHeader encodes ATYP + DST.ADDR + DST.PORT for a UDP datagram.
func encodeUDPHeader(address string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	var header []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = append([]byte{socks5AtypIPv4}, ip4...)
		} else {
			header = append([]byte{socks5AtypIPv6}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host name too long")
		}
		header = append([]byte{socks5AtypDomain, byte(len(host))}, host...)
	}
	header = append(header, byte(port>>8), byte(port))
	return header, nil
}

// stripUDPHeader removes RSV + FRAG + ATYP + DST.ADDR + DST.PORT.
func stripUDPHeader(p []byte) ([]byte, error) {
	if len(p) < 4 {
		return nil, fmt.Errorf("short SOCKS5 UDP datagram")
	}
	if p[2] != 0x00 {
		return nil, fmt.Errorf("fragmented SOCKS5 UDP datagrams are not supported")
	}

	off := 4
	switch p[3] {
	case socks5AtypIPv4:
		off += net.IPv4len
	case socks5AtypIPv6:
		off += net.IPv6len
	case socks5AtypDomain:
		if len(p) < 5 {
			return nil, fmt.Errorf("short SOCKS5 UDP datagram")
		}
		off += 1 + int(p[4])
	default:
		return nil, fmt.Errorf("unexpected address type 0x%02x", p[3])
	}
	off += 2 // port
	if len(p) < off {
		return nil, fmt.Errorf("short SOCKS5 UDP datagram")
	}
	return p[off:], nil
}
