package socks5

import (
	"bufio"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

const (
	protocolVersion5 byte = 0x05

	noAuthenticationRequired byte = 0x00
	methodUsernamePassword   byte = 0x02
	noAcceptableMethods      byte = 0xff

	usernamePasswordVersion byte = 0x01
	usernamePasswordSuccess byte = 0x00
	usernamePasswordFailure byte = 0x01

	addressTypeIPv4         byte = 0x01
	addressTypeFQDN         byte = 0x03
	addressTypeIPv6         byte = 0x04
	addressTypeNotSupported byte = 0x08

	commandConnect      byte = 0x01
	commandNotSupported byte = 0x07

	socksConnectSuccessful byte = 0x00
)

func (s *Server) handshake(writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read protocol version")
		return
	}

	if version != protocolVersion5 {
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
		if err := response(writer,
			protocolVersion5,
			noAuthenticationRequired,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
			return
		}

		s.acceptRequest(writer, reader)
	case methodUsernamePassword:
		if err := response(writer,
			protocolVersion5,
			methodUsernamePassword,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
			return
		}

		s.usernamePasswordAuthenticate(writer, reader)
	case noAcceptableMethods:
		if err := response(writer,
			protocolVersion5,
			noAcceptableMethods,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
		}

		return
	default:
		return
	}
}

func (s *Server) acceptRequest(writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read protocol version")
		return
	}

	if version != protocolVersion5 {
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

	var dstAddr address

	dstAddr.Type, err = reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read address type")
		return
	}

	switch dstAddr.Type {
	case addressTypeIPv4:
		dstAddr.IP = make(net.IP, net.IPv4len)
		if _, err := reader.Read(dstAddr.IP); err != nil {
			s.logger.LogErrorMessage(err, "failed to read IPv4 address")
			return
		}
	case addressTypeFQDN:
		dstAddr.DomainLen, err = reader.ReadByte()
		if err != nil {
			s.logger.LogErrorMessage(err, "failed to read domain length")
			return
		}

		dstAddr.Domain = make([]byte, dstAddr.DomainLen)
		if _, err := reader.Read(dstAddr.Domain); err != nil {
			s.logger.LogErrorMessage(err, "failed to read domain")
			return
		}
	case addressTypeIPv6:
		if err := replyRequest(writer,
			protocolVersion5,
			addressTypeNotSupported,
			dstAddr,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
		}

		return
	}

	dstAddr.Port = make([]byte, 2)
	if _, err := reader.Read(dstAddr.Port); err != nil {
		s.logger.LogErrorMessage(err, "failed to read port")
		return
	}

	switch command {
	case commandConnect:
		if err := replyRequest(writer,
			protocolVersion5,
			socksConnectSuccessful,
			dstAddr,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
			return
		}

		s.connect(writer, reader, dstAddr)
	default:
		if err := replyRequest(writer,
			protocolVersion5,
			commandNotSupported,
			dstAddr,
		); err != nil {
			s.logger.LogErrorMessage(err, "failed to send a response to the client")
		}

		return
	}
}

func (s *Server) connect(writer io.Writer, reader *bufio.Reader, addr address) {
	target, err := s.driver.Dial(addr.String())
	if err != nil {
		s.logger.LogErrorMessage(err, "error dial connection")
		return
	}
	defer target.Close()

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

func relay(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)

	if tcpConn, ok := dst.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}

	return err
}

func replyRequest(writer io.Writer, version byte, status byte, addr address) error {
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

	return response(writer, version, status, fields...)
}

func response(writer io.Writer, version, status byte, fields ...byte) error {
	res := []byte{
		version,
		status,
	}

	res = append(res, fields...)

	_, err := writer.Write(res)

	return err
}
