package socks5

import (
	"bytes"
	"errors"
	"net"
)

type payload struct {
	address *address
	data    []byte
}

type packetInfo struct {
	clientAddress net.Addr
	payload       []byte
}

func (p *packetInfo) decode() (*payload, error) {
	reader := bytes.NewBuffer(p.payload)

	// Reserved 2 bytes: 0x00, 0x00
	if _, err := reader.Read(make([]byte, 2)); err != nil {
		return nil, errors.New("failed to read reserved bytes")
	}

	// Current fragment number
	frag, err := reader.ReadByte()
	if err != nil {
		return nil, errors.New("failed to read current fragment number")
	}

	// If not support fragmentation must drop any datagram whose FRAG field is other than 0x00
	if frag != 0x00 {
		return nil, errors.New("not support fragmentation")
	}

	var addr address

	addr.Type, err = reader.ReadByte()
	if err != nil {
		return nil, errors.New("failed to read address type")
	}

	switch addr.Type {
	case addressTypeIPv4:
		addr.IP = make(net.IP, net.IPv4len)
		if _, err := reader.Read(addr.IP); err != nil {
			return nil, errors.New("failed to read IPv4 address")
		}
	case addressTypeFQDN:
		addr.DomainLen, err = reader.ReadByte()
		if err != nil {
			return nil, errors.New("failed to read domain length")
		}

		addr.Domain = make([]byte, addr.DomainLen)
		if _, err := reader.Read(addr.Domain); err != nil {
			return nil, errors.New("failed to read domain")
		}
	case addressTypeIPv6:
		addr.IP = make(net.IP, net.IPv6len)
		if _, err := reader.Read(addr.IP); err != nil {
			return nil, errors.New("failed to read IPv6 address")
		}
	default:
		return nil, errors.New("not support address type")
	}

	addr.Port = make([]byte, 2)

	if _, err := reader.Read(addr.Port); err != nil {
		return nil, errors.New("failed to read port")
	}

	return &payload{
		address: &addr,
		data:    reader.Bytes(),
	}, nil
}

func (p *packetInfo) encode(payload *payload) {
	res := []byte{
		0x00, // Reserved byte
		0x00, // Reserved byte
		0x00, // Current fragment number
		payload.address.Type,
	}

	switch payload.address.Type {
	case addressTypeIPv4:
		res = append(res, payload.address.IP.To4()...)
	case addressTypeFQDN:
		res = append(res, payload.address.DomainLen)
		res = append(res, payload.address.Domain...)
	case addressTypeIPv6:
		res = append(res, payload.address.IP.To16()...)
	}

	res = append(res, payload.address.Port...)
	res = append(res, payload.data...)

	p.payload = res
}

func readFromQueue(queue <-chan *packetInfo) (*packetInfo, bool) {
	select {
	case packet, ok := <-queue:
		return packet, ok
	default:
		return nil, false
	}
}

func writeToQueue(queue chan<- *packetInfo, packet *packetInfo) bool {
	select {
	case queue <- packet:
		return true
	default:
		return false
	}
}

func readFromPacketConn(packetConn net.PacketConn) (*packetInfo, error) {
	datagram := make([]byte, 65507)

	n, clientAddress, err := packetConn.ReadFrom(datagram)
	if err != nil {
		return nil, err
	}

	return &packetInfo{
		clientAddress: clientAddress,
		payload:       datagram[:n],
	}, nil
}

func writeToPacketConn(packetConn net.PacketConn, packet *packetInfo) error {
	_, err := packetConn.WriteTo(packet.payload, packet.clientAddress)
	return err
}
