package socks5

import (
	"bufio"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

const (
	version5 byte = 0x05

	noAuthenticationRequired byte = 0x00
	methodUsernamePassword   byte = 0x02
	noAcceptableMethods      byte = 0xff

	usernamePasswordVersion byte = 0x01
	usernamePasswordSuccess byte = 0x00
	usernamePasswordFailure byte = 0x01

	addressTypeIPv4 byte = 0x01
	addressTypeFQDN byte = 0x03
	addressTypeIPv6 byte = 0x04

	commandConnect byte = 0x01

	connectionSuccessful      byte = 0x00
	generalSOCKSserverFailure byte = 0x01
	networkUnreachable        byte = 0x03
	hostUnreachable           byte = 0x04
	connectionRefused         byte = 0x05
	commandNotSupported       byte = 0x07
	addressTypeNotSupported   byte = 0x08
)

func (s *Server) handshake(writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read protocol version")
		return
	}

	if version != version5 {
		return
	}

	numMethods, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read number of authentication methods")
		return
	}

	methods := make([]byte, numMethods)
	if _, err := reader.Read(methods); err != nil {
		s.logger.LogErrorMessage(err, "failed to read authentication methods")
		return
	}

	method := s.choiceAuthenticationMethod(methods)
	switch method {
	case noAuthenticationRequired:
		s.response(writer, version5, noAuthenticationRequired)

		s.acceptRequest(writer, reader)
	case methodUsernamePassword:
		s.response(writer, version5, methodUsernamePassword)

		s.usernamePasswordAuthenticate(writer, reader)
	default:
		s.response(writer, version5, noAcceptableMethods)
		return
	}
}

func (s *Server) acceptRequest(writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read protocol version")
		return
	}

	if version != version5 {
		return
	}

	command, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read command")
		return
	}

	// Reserved byte: 0x00
	if _, err := reader.ReadByte(); err != nil {
		s.logger.LogErrorMessage(err, "failed to read reserved byte")
		return
	}

	var addr address

	addr.Type, err = reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read address type")
		return
	}

	switch addr.Type {
	case addressTypeIPv4:
		addr.IP = make(net.IP, net.IPv4len)
		if _, err := reader.Read(addr.IP); err != nil {
			s.logger.LogErrorMessage(err, "failed to read IPv4 address")
			return
		}
	case addressTypeFQDN:
		addr.DomainLen, err = reader.ReadByte()
		if err != nil {
			s.logger.LogErrorMessage(err, "failed to read domain length")
			return
		}

		addr.Domain = make([]byte, addr.DomainLen)
		if _, err := reader.Read(addr.Domain); err != nil {
			s.logger.LogErrorMessage(err, "failed to read domain")
			return
		}
	case addressTypeIPv6:
		addr.IP = make(net.IP, net.IPv6len)
		if _, err := reader.Read(addr.IP); err != nil {
			s.logger.LogErrorMessage(err, "failed to read IPv6 address")
			return
		}
	default:
		s.replyRequest(writer, addressTypeNotSupported, addr)
		return
	}

	addr.Port = make([]byte, 2)
	if _, err := reader.Read(addr.Port); err != nil {
		s.logger.LogErrorMessage(err, "failed to read port")
		return
	}

	switch command {
	case commandConnect:
		s.connect(writer, reader, addr)
	default:
		s.replyRequest(writer, commandNotSupported, addr)
		return
	}
}

func (s *Server) connect(writer io.Writer, reader *bufio.Reader, addr address) {
	target, err := s.driver.Dial(addr.String())
	if err != nil {
		s.replyRequestWithError(writer, err, addr)

		s.logger.LogErrorMessage(err, "error dial connection")
		return
	}
	defer target.Close()

	s.replyRequest(writer, connectionSuccessful, addr)

	var g errgroup.Group

	g.Go(func() error {
		return relay(target, reader)
	})

	g.Go(func() error {
		return relay(writer, target)
	})

	if err = g.Wait(); err != nil {
		s.logger.LogErrorMessage(err, "error sync wait group")
	}
}

func (s *Server) replyRequestWithError(writer io.Writer, err error, addr address) {
	switch {
	case networkUnreachableError(err):
		s.replyRequest(writer, networkUnreachable, addr)
	case noSuchHostError(err):
		s.replyRequest(writer, hostUnreachable, addr)
	case connectionRefusedError(err):
		s.replyRequest(writer, connectionRefused, addr)
	default:
		s.replyRequest(writer, generalSOCKSserverFailure, addr)
	}
}

func (s *Server) replyRequest(writer io.Writer, status byte, addr address) {
	fields := []byte{
		0x00, // Reserved byte
		addr.Type,
	}

	switch addr.Type {
	case addressTypeIPv4, addressTypeIPv6:
		fields = append(fields, addr.IP...)
	case addressTypeFQDN:
		fields = append(fields, addr.DomainLen)
		fields = append(fields, addr.Domain...)
	}

	fields = append(fields, addr.Port...)

	s.response(writer, version5, status, fields...)
}

func (s *Server) response(writer io.Writer, version, status byte, fields ...byte) {
	res := []byte{
		version,
		status,
	}

	res = append(res, fields...)

	if _, err := writer.Write(res); err != nil {
		s.logger.LogErrorMessage(err, "failed to send a response to the client")
	}
}
