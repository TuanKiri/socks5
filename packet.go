package socks5

import (
	"net"
)

type packetInfo struct {
	clientAddress net.Addr
	payload       []byte
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
