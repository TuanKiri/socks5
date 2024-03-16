package socks5

import (
	"net"
	"time"
)

type Driver interface {
	Listen() (net.Listener, error)
	Dial(addr string) (net.Conn, error)
}

type defaultDriver struct {
	listenAddr  string
	dialTimeout time.Duration
}

func (d defaultDriver) Listen() (net.Listener, error) {
	return net.Listen("tcp", d.listenAddr)
}

func (d defaultDriver) Dial(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, d.dialTimeout)
}
