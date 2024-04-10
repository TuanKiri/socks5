package socks5

import (
	"net"
	"time"
)

type Driver interface {
	Listen() (net.Listener, error)
	Dial(address string) (net.Conn, error)
}

type defaultDriver struct {
	listenAddress string
	dialTimeout   time.Duration
}

func (d defaultDriver) Listen() (net.Listener, error) {
	return net.Listen("tcp", d.listenAddress)
}

func (d defaultDriver) Dial(address string) (net.Conn, error) {
	return net.DialTimeout("tcp", address, d.dialTimeout)
}
