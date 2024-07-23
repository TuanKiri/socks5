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
	buffer := bytes.NewBuffer(p.payload)

	// Reserved 2 bytes: 0x00, 0x00
	if _, err := buffer.Read(make([]byte, 2)); err != nil {
		return nil, errors.New("failed to read reserved bytes")
	}

	// Current fragment number
	frag, err := buffer.ReadByte()
	if err != nil {
		return nil, errors.New("failed to read current fragment number")
	}

	// If not support fragmentation must drop any datagram whose FRAG field is other than 0x00
	if frag != 0x00 {
		return nil, errors.New("not support fragmentation")
	}

	var address address

	address.Type, err = buffer.ReadByte()
	if err != nil {
		return nil, errors.New("failed to read address type")
	}

	switch address.Type {
	case addressTypeIPv4:
		address.IP = make(net.IP, net.IPv4len)
		if _, err := buffer.Read(address.IP); err != nil {
			return nil, errors.New("failed to read IPv4 address")
		}
	case addressTypeFQDN:
		address.DomainLen, err = buffer.ReadByte()
		if err != nil {
			return nil, errors.New("failed to read domain length")
		}

		address.Domain = make([]byte, address.DomainLen)
		if _, err := buffer.Read(address.Domain); err != nil {
			return nil, errors.New("failed to read domain")
		}
	case addressTypeIPv6:
		address.IP = make(net.IP, net.IPv6len)
		if _, err := buffer.Read(address.IP); err != nil {
			return nil, errors.New("failed to read IPv6 address")
		}
	default:
		return nil, errors.New("not support address type")
	}

	address.Port = make([]byte, 2)

	if _, err := buffer.Read(address.Port); err != nil {
		return nil, errors.New("failed to read port")
	}

	return &payload{
		address: &address,
		data:    buffer.Bytes(),
	}, nil
}

func (p *packetInfo) encode(payload *payload) {
	p.payload = []byte{
		0x00, // Reserved byte
		0x00, // Reserved byte
		0x00, // Current fragment number
		payload.address.Type,
	}

	switch payload.address.Type {
	case addressTypeIPv4:
		p.payload = append(p.payload, payload.address.IP.To4()...)
	case addressTypeFQDN:
		p.payload = append(p.payload, payload.address.DomainLen)
		p.payload = append(p.payload, payload.address.Domain...)
	case addressTypeIPv6:
		p.payload = append(p.payload, payload.address.IP.To16()...)
	}

	p.payload = append(p.payload, payload.address.Port...)
	p.payload = append(p.payload, payload.data...)
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

func readFromPacketConn(packetConn net.PacketConn, bytePool *bytePool) (*packetInfo, error) {
	datagram := bytePool.getBytes()
	defer bytePool.putBytes(datagram)

	n, clientAddress, err := packetConn.ReadFrom(datagram)
	if err != nil {
		return nil, err
	}

	packet := &packetInfo{
		clientAddress: clientAddress,
		payload:       make([]byte, n),
	}

	copy(packet.payload, datagram[:n])

	return packet, nil
}

func writeToPacketConn(packetConn net.PacketConn, packet *packetInfo) error {
	_, err := packetConn.WriteTo(packet.payload, packet.clientAddress)
	return err
}
