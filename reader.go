package socks5

import (
	"bufio"
	"io"
)

type reader interface {
	ReadByte() (byte, error)
	Read(p []byte) (int, error)
	IsActive() bool
}

type connReader struct {
	reader *bufio.Reader
	done   chan struct{}
}

func newReader(rd io.Reader) *connReader {
	return &connReader{
		reader: bufio.NewReader(rd),
		done:   make(chan struct{}),
	}
}

func (c *connReader) ReadByte() (byte, error) {
	b, err := c.reader.ReadByte()
	if err != nil && c.IsActive() {
		close(c.done)
	}

	return b, err
}
func (c *connReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err != nil && c.IsActive() {
		close(c.done)
	}

	return n, err
}
func (c *connReader) IsActive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
