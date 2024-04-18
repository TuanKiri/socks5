package socks5

import (
	"encoding/binary"
	"fmt"
	"math/big"
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

// If s is not a valid, parsePort returns nil.
func parsePort(s string) port {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}

	bigInt := big.NewInt(i)

	return bigInt.Bytes()
}
