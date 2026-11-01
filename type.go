// Taken from github.com/coredns/plugin/forward/type.go with modification

package dnsredir

import (
	"crypto/tls"
	"fmt"
	"net"
)

type transportType int

const (
	typeUdp transportType = iota
	typeTcp
	typeTls
	typeTotalCount // Dummy type
)

func stringToTransportType(s string) transportType {
	switch s {
	case "udp":
		return typeUdp
	case "tcp":
		return typeTcp
	case "tcp-tls":
		return typeTls
	}

	log.Warningf("Unknown protocol %q, fallback to UDP", s)
	return typeUdp
}

func (t *Transport) transportTypeFromConn(pc *persistConn) transportType {
	if _, ok := pc.c.Conn.(net.PacketConn); ok {
		return typeUdp
	}

	if t.tlsConfig == nil {
		if _, ok := pc.c.Conn.(*net.TCPConn); !ok {
			panic(fmt.Sprintf("Expected TCP connection, got %T", pc.c.Conn))
		}
		return typeTcp
	}

	if _, ok := pc.c.Conn.(*tls.Conn); !ok {
		panic(fmt.Sprintf("Expected TLS connection, got %T", pc.c.Conn))
	}
	return typeTls
}
