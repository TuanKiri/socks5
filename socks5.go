package socks5

import (
	"context"
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
	udpAssociate byte = 0x03

	connectionSuccessful      byte = 0x00
	generalSOCKSserverFailure byte = 0x01
	networkUnreachable        byte = 0x03
	hostUnreachable           byte = 0x04
	connectionRefused         byte = 0x05
	commandNotSupported       byte = 0x07
	addressTypeNotSupported   byte = 0x08
)

func (s *Server) handshake(ctx context.Context, conn connection) {
	version, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	numMethods, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read number of authentication methods: "+err.Error())
		return
	}

	methods := make([]byte, numMethods)
	if _, err := conn.Read(methods); err != nil {
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
		return
	}
}

func (s *Server) acceptRequest(ctx context.Context, conn connection) {
	version, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	command, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read command: "+err.Error())
		return
	}

	// Reserved byte: 0x00
	if _, err := conn.ReadByte(); err != nil {
		s.logger.Error(ctx, "failed to read reserved byte: "+err.Error())
		return
	}

	var address address

	address.Type, err = conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read address type: "+err.Error())
		return
	}

	switch address.Type {
	case addressTypeIPv4:
		address.IP = make(net.IP, net.IPv4len)
		if _, err := conn.Read(address.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv4 address: "+err.Error())
			return
		}
	case addressTypeFQDN:
		address.DomainLen, err = conn.ReadByte()
		if err != nil {
			s.logger.Error(ctx, "failed to read domain length: "+err.Error())
			return
		}

		address.Domain = make([]byte, address.DomainLen)
		if _, err := conn.Read(address.Domain); err != nil {
			s.logger.Error(ctx, "failed to read domain: "+err.Error())
			return
		}
	case addressTypeIPv6:
		address.IP = make(net.IP, net.IPv6len)
		if _, err := conn.Read(address.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv6 address: "+err.Error())
			return
		}
	default:
		s.replyRequest(ctx, conn, addressTypeNotSupported, &address)
		return
	}

	address.Port = make([]byte, 2)
	if _, err := conn.Read(address.Port); err != nil {
		s.logger.Error(ctx, "failed to read port: "+err.Error())
		return
	}

	switch command {
	case connect:
		s.connect(ctx, conn, &address)
	case udpAssociate:
		s.udpAssociate(ctx, conn)
	default:
		s.replyRequest(ctx, conn, commandNotSupported, &address)
		return
	}
}

func (s *Server) connect(ctx context.Context, conn connection, address *address) {
	target, err := s.driver.Dial(address.String())
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, address)

		s.logger.Error(ctx, "dial "+address.String()+": "+err.Error())
		return
	}
	defer target.Close()

	s.replyRequest(ctx, conn, connectionSuccessful, address)

	s.logger.Info(ctx, "dial "+address.String())

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

func (s *Server) udpAssociate(ctx context.Context, conn connection) {
	l, err := s.driver.ListenUDP()
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, &address{})

		s.logger.Error(ctx, "error listen udp: "+err.Error())
		return
	}

	var address address

	host, port, err := net.SplitHostPort(l.LocalAddr().String())
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, &address)

		s.logger.Error(ctx, "error split host port: "+err.Error())
		return
	}

	address.Type = addressTypeIPv4
	address.IP = net.ParseIP(host)
	address.Port = parsePort(port)

	s.replyRequest(ctx, conn, connectionSuccessful, &address)

	s.logger.Info(ctx, "start of udp datagram forwarding")

	// While tcp connection is active
	for conn.IsActive() {
		datagram := make([]byte, 65507)

		_, remoteAddress, err := l.ReadFromUDP(datagram)
		if err != nil {
			if !isClosedListenerError(err) {
				s.logger.Error(ctx, "error read datagram from udp: "+err.Error())
			}

			continue
		}

		if !equalHosts(conn.RemoteAddress(), remoteAddress.String()) {
			continue
		}
	}

	s.logger.Info(ctx, "udp datagram forwarding complete")
}

func (s *Server) replyRequestWithError(ctx context.Context, conn connection, err error, address *address) {
	switch {
	case isNetworkUnreachableError(err):
		s.replyRequest(ctx, conn, networkUnreachable, address)
	case isNoSuchHostError(err):
		s.replyRequest(ctx, conn, hostUnreachable, address)
	case isConnectionRefusedError(err):
		s.replyRequest(ctx, conn, connectionRefused, address)
	default:
		s.replyRequest(ctx, conn, generalSOCKSserverFailure, address)
	}
}

func (s *Server) replyRequest(ctx context.Context, conn connection, status byte, address *address) {
	fields := []byte{
		0x00, // Reserved byte
		address.Type,
	}

	switch address.Type {
	case addressTypeIPv4:
		fields = append(fields, address.IP.To4()...)
	case addressTypeIPv6:
		fields = append(fields, address.IP.To16()...)
	case addressTypeFQDN:
		fields = append(fields, address.DomainLen)
		fields = append(fields, address.Domain...)
	}

	fields = append(fields, address.Port...)

	s.response(ctx, conn, version5, status, fields...)
}

func (s *Server) response(ctx context.Context, conn connection, version, status byte, fields ...byte) {
	res := []byte{
		version,
		status,
	}

	res = append(res, fields...)

	if _, err := conn.Write(res); err != nil {
		s.logger.Error(ctx, "failed to send a response to the client: "+err.Error())
	}
}
