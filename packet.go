package socks5

import (
	"bytes"
	"errors"
	"net"
)

type packet struct {
	address *address
	payload []byte
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

	return nil
}

func (p *packet) encode(payload []byte) []byte {
	data := []byte{
		0x00, // Reserved byte
		0x00, // Reserved byte
		0x00, // Current fragment number
		p.address.Type,
	}

	switch p.address.Type {
	case addressTypeIPv4:
		data = append(data, p.address.IP.To4()...)
	case addressTypeFQDN:
		data = append(data, p.address.DomainLen)
		data = append(data, p.address.Domain...)
	case addressTypeIPv6:
		data = append(data, p.address.IP.To16()...)
	}

	data = append(data, p.address.Port...)
	data = append(data, payload...)

	return data
}
