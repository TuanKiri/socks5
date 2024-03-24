package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
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
