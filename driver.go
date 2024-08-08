package socks5

import (
	"errors"
	"net"
	"time"
)

type Driver interface {
	Listen(network, address string) (net.Listener, error)
	ListenPacket(network, address string) (net.PacketConn, error)
	Dial(network, address string) (net.Conn, error)
	Resolve(network, address string) (net.Addr, error)
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

func (d *netDriver) Resolve(network, address string) (net.Addr, error) {
	switch network {
	case "udp":
		return net.ResolveUDPAddr(network, address)
	default:
		return nil, errors.New("bad network")
	}
}
