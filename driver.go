package socks5

import (
	"net"
	"time"
)

type Driver interface {
	Listen() (net.Listener, error)
	ListenPacket() (net.PacketConn, error)
	Dial(network, address string) (net.Conn, error)
}

type netDriver struct {
	listenAddress string
	bindAddress   string
	dialTimeout   time.Duration
}

func (d *netDriver) Listen() (net.Listener, error) {
	return net.Listen("tcp", d.listenAddress)
}

func (d *netDriver) ListenPacket() (net.PacketConn, error) {
	return net.ListenPacket("udp", d.bindAddress)
}

func (d *netDriver) Dial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, d.dialTimeout)
}
