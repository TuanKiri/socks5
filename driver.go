package socks5

import (
	"net"
	"time"
)

type Driver interface {
	Listen(network, address string) (net.Listener, error)
	ListenPacket(network, address string) (net.PacketConn, error)
	Dial(network, address string) (net.Conn, error)
}

type netDriver struct {
	timeout time.Duration
}

func (d *netDriver) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (d *netDriver) ListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (d *netDriver) Dial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, d.timeout)
}
