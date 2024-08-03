// Package socks5 a fully featured implementation of the SOCKS 5 protocol in golang.
package socks5

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sync/errgroup"
)

const (
	version5 byte = 0x05

	noAuthenticationRequired       byte = 0x00
	usernamePasswordAuthentication byte = 0x02
	noAcceptableMethods            byte = 0xff

	usernamePasswordVersion byte = 0x01
	usernamePasswordSuccess byte = 0x00
	usernamePasswordFailure byte = 0x01

	addressTypeIPv4 byte = 0x01
	addressTypeFQDN byte = 0x03
	addressTypeIPv6 byte = 0x04

	connect      byte = 0x01
	bind         byte = 0x02
	udpAssociate byte = 0x03

	connectionSuccessful          byte = 0x00
	generalSOCKSserverFailure     byte = 0x01
	connectionNotAllowedByRuleSet byte = 0x02
	networkUnreachable            byte = 0x03
	hostUnreachable               byte = 0x04
	connectionRefused             byte = 0x05
	commandNotSupported           byte = 0x07
	addressTypeNotSupported       byte = 0x08
)

func (s *Server) handshake(ctx context.Context, conn *connection) {
	version, err := conn.readByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	numMethods, err := conn.readByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read number of authentication methods: "+err.Error())
		return
	}

	methods := make([]byte, numMethods)
	if _, err := conn.read(methods); err != nil {
		s.logger.Error(ctx, "failed to read authentication methods: "+err.Error())
		return
	}

	method := s.choiceAuthenticationMethod(methods)
	switch method {
	case noAuthenticationRequired:
		s.response(ctx, conn, version5, noAuthenticationRequired)

		s.acceptRequest(ctx, conn)
	case usernamePasswordAuthentication:
		s.response(ctx, conn, version5, usernamePasswordAuthentication)

		s.usernamePasswordAuthenticate(ctx, conn)
	default:
		s.response(ctx, conn, version5, noAcceptableMethods)
	}
}

func (s *Server) acceptRequest(ctx context.Context, conn *connection) {
	version, err := conn.readByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	command, err := conn.readByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read command: "+err.Error())
		return
	}

	// Reserved byte: 0x00
	if _, err := conn.readByte(); err != nil {
		s.logger.Error(ctx, "failed to read reserved byte: "+err.Error())
		return
	}

	var addr address

	addr.Type, err = conn.readByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read address type: "+err.Error())
		return
	}

	switch addr.Type {
	case addressTypeIPv4:
		addr.IP = make(net.IP, net.IPv4len)
		if _, err := conn.read(addr.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv4 address: "+err.Error())
			return
		}
	case addressTypeFQDN:
		addr.DomainLen, err = conn.readByte()
		if err != nil {
			s.logger.Error(ctx, "failed to read domain length: "+err.Error())
			return
		}

		addr.Domain = make([]byte, addr.DomainLen)
		if _, err := conn.read(addr.Domain); err != nil {
			s.logger.Error(ctx, "failed to read domain: "+err.Error())
			return
		}
	case addressTypeIPv6:
		addr.IP = make(net.IP, net.IPv6len)
		if _, err := conn.read(addr.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv6 address: "+err.Error())
			return
		}
	default:
		s.replyRequest(ctx, conn, addressTypeNotSupported, &addr)
		return
	}

	addr.Port = make([]byte, 2)
	if _, err := conn.read(addr.Port); err != nil {
		s.logger.Error(ctx, "failed to read port: "+err.Error())
		return
	}

	if !s.rules.IsAllowDestination(ctx, addr.getDomainOrIP()) {
		s.replyRequest(ctx, conn, connectionNotAllowedByRuleSet, &addr)
		return
	}

	switch command {
	case connect:
		if !s.rules.IsAllowCommand(ctx, connect) {
			s.replyRequest(ctx, conn, connectionNotAllowedByRuleSet, &addr)
			return
		}

		s.connect(ctx, conn, &addr)
	case udpAssociate:
		if !s.rules.IsAllowCommand(ctx, udpAssociate) {
			s.replyRequest(ctx, conn, connectionNotAllowedByRuleSet, &addr)
			return
		}

		s.udpAssociate(ctx, conn, &addr)
	default:
		s.replyRequest(ctx, conn, commandNotSupported, &addr)
	}
}

func (s *Server) connect(ctx context.Context, conn *connection, addr *address) {
	target, err := s.driver.Dial("tcp", addr.String())
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, addr)

		s.logger.Error(ctx, "dial "+addr.String()+": "+err.Error())
		return
	}
	defer target.Close()

	s.replyRequest(ctx, conn, connectionSuccessful, addr)

	s.logger.Info(ctx, "dial "+addr.String())

	var g errgroup.Group

	g.Go(func() error {
		n, err := relay(target, conn)
		s.metrics.UploadBytes(ctx, n)
		return err
	})

	g.Go(func() error {
		n, err := relay(conn, target)
		s.metrics.DownloadBytes(ctx, n)
		return err
	})

	if err = g.Wait(); err != nil {
		s.logger.Error(ctx, "error sync wait group: "+err.Error())
	}
}

func (s *Server) udpAssociate(ctx context.Context, conn *connection, addr *address) {
	packetConn, err := s.driver.ListenPacket("udp", net.JoinHostPort(s.config.host, "0"))
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, addr)

		s.logger.Error(ctx, "error listen udp: "+err.Error())
		return
	}

	conn.onClose(func() {
		if err := packetConn.Close(); err != nil {
			s.logger.Error(ctx, "error close udp listener: "+err.Error())
		}
	})

	go conn.keepAlive()

	var port port

	port.fromAddress(packetConn.LocalAddr())

	s.replyRequest(ctx, conn, connectionSuccessful, &address{
		Type: addressTypeIPv4,
		IP:   s.config.publicIP,
		Port: port,
	})

	s.logger.Info(ctx, "start of udp datagram forwarding")

	dstAddresses := make(map[string]*packetInfo)

	for conn.isActive() {
		datagram := make([]byte, 1500)

		n, clientAddress, err := packetConn.ReadFrom(datagram)
		if err != nil {
			if !isClosedListenerError(err) {
				s.logger.Error(ctx, "packetConn.ReadFrom")
			}
			continue
		}

		if conn.equalAddresses(clientAddress) {
			payload, err := decode(datagram[:n])
			if err != nil {
				s.logger.Error(ctx, "decode(datagram[:n")
				continue
			}

			address, err := net.ResolveUDPAddr("udp", payload.address.String())
			if err != nil {
				s.logger.Error(ctx, "net.ResolveUDPAddr")
				continue
			}

			fmt.Println("resolve: ", address)

			if _, err := packetConn.WriteTo(payload.data, address); err != nil {
				if !isClosedListenerError(err) {
					s.logger.Error(ctx, "packetConn.WriteTo")
				}
				continue
			}

			dstAddresses[address.String()] = &packetInfo{
				clientAddress: clientAddress,
				dstAddress:    addr,
			}
		}

		if packetInfo, ok := dstAddresses[clientAddress.String()]; ok {
			fmt.Println("receive: ", clientAddress)
			delete(dstAddresses, clientAddress.String())

			address := packetInfo.dstAddress

			data := []byte{
				0x00, // Reserved byte
				0x00, // Reserved byte
				0x00, // Current fragment number
				address.Type,
			}

			switch address.Type {
			case addressTypeIPv4:
				data = append(data, address.IP.To4()...)
			case addressTypeFQDN:
				data = append(data, address.DomainLen)
				data = append(data, address.Domain...)
			case addressTypeIPv6:
				data = append(data, address.IP.To16()...)
			}

			data = append(data, address.Port...)
			data = append(data, datagram[:n]...)

			if _, err := packetConn.WriteTo(data, packetInfo.clientAddress); err != nil {
				if !isClosedListenerError(err) {
					s.logger.Error(ctx, "packetConn.WriteTo")
					continue
				}
			}
		}
	}

	s.logger.Info(ctx, "udp datagram forwarding complete")
}

func (s *Server) replyRequestWithError(ctx context.Context, conn *connection, err error, addr *address) {
	switch {
	case isNetworkUnreachableError(err):
		s.replyRequest(ctx, conn, networkUnreachable, addr)
	case isNoSuchHostError(err):
		s.replyRequest(ctx, conn, hostUnreachable, addr)
	case isConnectionRefusedError(err):
		s.replyRequest(ctx, conn, connectionRefused, addr)
	default:
		s.replyRequest(ctx, conn, generalSOCKSserverFailure, addr)
	}
}

func (s *Server) replyRequest(ctx context.Context, conn *connection, status byte, addr *address) {
	fields := []byte{
		0x00, // Reserved byte
		addr.Type,
	}

	switch addr.Type {
	case addressTypeIPv4:
		fields = append(fields, addr.IP.To4()...)
	case addressTypeFQDN:
		fields = append(fields, addr.DomainLen)
		fields = append(fields, addr.Domain...)
	case addressTypeIPv6:
		fields = append(fields, addr.IP.To16()...)
	}

	fields = append(fields, addr.Port...)

	s.response(ctx, conn, version5, status, fields...)
}

func (s *Server) response(ctx context.Context, conn *connection, version, status byte, fields ...byte) {
	res := []byte{
		version,
		status,
	}

	res = append(res, fields...)

	if _, err := conn.write(res); err != nil {
		s.logger.Error(ctx, "failed to send a response to the client: "+err.Error())
	}
}
