package socks5

import (
	"bufio"
	"net"
)

type connection interface {
	ReadByte() (byte, error)
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	IsActive() bool
	RemoteAddress() string
}

type connWrapper struct {
	net.Conn
	reader *bufio.Reader
	done   chan struct{}
}

func newConnection(conn net.Conn) *connWrapper {
	return &connWrapper{
		Conn:   conn,
		reader: bufio.NewReader(conn),
		done:   make(chan struct{}),
	}
}

func (c *connWrapper) ReadByte() (byte, error) {
	return c.reader.ReadByte()
}

func (c *connWrapper) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *connWrapper) IsActive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *connWrapper) RemoteAddress() string {
	return c.RemoteAddr().String()
}
