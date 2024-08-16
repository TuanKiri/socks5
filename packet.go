package socks5

import (
	"bytes"
	"errors"
	"net"
)

type payload []byte

func (p *payload) reset() {
	*p = nil
}

func (p payload) len() int64 {
	return int64(len(p))
}

type packet struct {
	address *address
	payload payload
}

func (p *packet) decode(data []byte) error {
	buffer := bytes.NewBuffer(data)

	// Reserved 2 bytes: 0x00, 0x00
	if _, err := buffer.Read(make([]byte, 2)); err != nil {
		return errors.New("failed to read reserved bytes")
	}

	// Current fragment number
	frag, err := buffer.ReadByte()
	if err != nil {
		return errors.New("failed to read current fragment number")
	}

	// If not support fragmentation must drop any datagram whose FRAG field is other than 0x00
	if frag != 0x00 {
		return errors.New("not support fragmentation")
	}

	var address address

	address.Type, err = buffer.ReadByte()
	if err != nil {
		return errors.New("failed to read address type")
	}

	switch address.Type {
	case addressTypeIPv4:
		address.IP = make(net.IP, net.IPv4len)
		if _, err := buffer.Read(address.IP); err != nil {
			return errors.New("failed to read IPv4 address")
		}
	case addressTypeFQDN:
		address.DomainLen, err = buffer.ReadByte()
		if err != nil {
			return errors.New("failed to read domain length")
		}

		address.Domain = make([]byte, address.DomainLen)
		if _, err := buffer.Read(address.Domain); err != nil {
			return errors.New("failed to read domain")
		}
	case addressTypeIPv6:
		address.IP = make(net.IP, net.IPv6len)
		if _, err := buffer.Read(address.IP); err != nil {
			return errors.New("failed to read IPv6 address")
		}
	default:
		return errors.New("not support address type")
	}

	address.Port = make([]byte, 2)

	if _, err := buffer.Read(address.Port); err != nil {
		return errors.New("failed to read port")
	}

	p.address = &address
	p.payload = buffer.Bytes()

	return nil
}

func (p *packet) encode(data []byte) {
	p.payload = []byte{
		0x00, // Reserved byte
		0x00, // Reserved byte
		0x00, // Current fragment number
		p.address.Type,
	}

	switch p.address.Type {
	case addressTypeIPv4:
		p.payload = append(p.payload, p.address.IP.To4()...)
	case addressTypeFQDN:
		p.payload = append(p.payload, p.address.DomainLen)
		p.payload = append(p.payload, p.address.Domain...)
	case addressTypeIPv6:
		p.payload = append(p.payload, p.address.IP.To16()...)
	}

	p.payload = append(p.payload, p.address.Port...)
	p.payload = append(p.payload, data...)
}
