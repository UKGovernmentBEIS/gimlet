package protocol

import (
	"net"
	"time"
)

// TCPDialer abstracts TCP connection dialing for testing
type TCPDialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

// DefaultTCPDialer uses the standard net package for TCP connections
type DefaultTCPDialer struct{}

// DialTimeout connects to a TCP address with a timeout
func (d *DefaultTCPDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}
