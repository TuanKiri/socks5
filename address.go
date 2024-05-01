package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

type address struct {
	Type      byte
	IP        net.IP
	Port      port
	Domain    []byte
	DomainLen byte
}

func (a address) String() string {
	if a.IP != nil {
		host := a.IP.String()
		port := a.Port.String()

		return net.JoinHostPort(host, port)
	}

	return fmt.Sprintf("%s:%s", a.Domain, a.Port)
}

type port []byte

func (p port) String() string {
	return fmt.Sprintf("%d", binary.BigEndian.Uint16(p))
}

func (p *port) fromAddress(address net.Addr) {
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return
	}

	i, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return
	}

	*p = make([]byte, 2)
	binary.BigEndian.PutUint16(*p, uint16(i))
}
