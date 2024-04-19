package socks5

import (
	"bufio"
	"context"
	"io"
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

	commandConnect byte = 0x01

	connectionSuccessful      byte = 0x00
	generalSOCKSserverFailure byte = 0x01
	networkUnreachable        byte = 0x03
	hostUnreachable           byte = 0x04
	connectionRefused         byte = 0x05
	commandNotSupported       byte = 0x07
	addressTypeNotSupported   byte = 0x08
)

func (s *Server) handshake(ctx context.Context, writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	numMethods, err := reader.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read number of authentication methods: "+err.Error())
		return
	}

	methods := make([]byte, numMethods)
	if _, err := reader.Read(methods); err != nil {
		s.logger.Error(ctx, "failed to read authentication methods: "+err.Error())
		return
	}

	method := s.choiceAuthenticationMethod(methods)
	switch method {
	case noAuthenticationRequired:
		s.response(ctx, writer, version5, noAuthenticationRequired)

		s.acceptRequest(ctx, writer, reader)
	case usernamePasswordAuthentication:
		s.response(ctx, writer, version5, usernamePasswordAuthentication)

		s.usernamePasswordAuthenticate(ctx, writer, reader)
	default:
		s.response(ctx, writer, version5, noAcceptableMethods)
		return
	}
}

func (s *Server) acceptRequest(ctx context.Context, writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read protocol version: "+err.Error())
		return
	}

	if version != version5 {
		return
	}

	command, err := reader.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read command: "+err.Error())
		return
	}

	// Reserved byte: 0x00
	if _, err := reader.ReadByte(); err != nil {
		s.logger.Error(ctx, "failed to read reserved byte: "+err.Error())
		return
	}

	var address address

	address.Type, err = reader.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read address type: "+err.Error())
		return
	}

	switch address.Type {
	case addressTypeIPv4:
		address.IP = make(net.IP, net.IPv4len)
		if _, err := reader.Read(address.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv4 address: "+err.Error())
			return
		}
	case addressTypeFQDN:
		address.DomainLen, err = reader.ReadByte()
		if err != nil {
			s.logger.Error(ctx, "failed to read domain length: "+err.Error())
			return
		}

		address.Domain = make([]byte, address.DomainLen)
		if _, err := reader.Read(address.Domain); err != nil {
			s.logger.Error(ctx, "failed to read domain: "+err.Error())
			return
		}
	case addressTypeIPv6:
		address.IP = make(net.IP, net.IPv6len)
		if _, err := reader.Read(address.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv6 address: "+err.Error())
			return
		}
	default:
		s.replyRequest(ctx, writer, addressTypeNotSupported, &address)
		return
	}

	address.Port = make([]byte, 2)
	if _, err := reader.Read(address.Port); err != nil {
		s.logger.Error(ctx, "failed to read port: "+err.Error())
		return
	}

	switch command {
	case commandConnect:
		s.connect(ctx, writer, reader, &address)
	default:
		s.replyRequest(ctx, writer, commandNotSupported, &address)
		return
	}
}

func (s *Server) connect(ctx context.Context, writer io.Writer, reader *bufio.Reader, address *address) {
	target, err := s.driver.Dial(address.String())
	if err != nil {
		s.replyRequestWithError(ctx, writer, err, address)

		s.logger.Error(ctx, "dial "+address.String()+": "+err.Error())
		return
	}
	defer target.Close()

	s.replyRequest(ctx, writer, connectionSuccessful, address)

	s.logger.Info(ctx, "dial "+address.String())

	var g errgroup.Group

	g.Go(func() error {
		n, err := relay(target, reader)
		s.metrics.UploadBytes(ctx, n)
		return err
	})

	g.Go(func() error {
		n, err := relay(writer, target)
		s.metrics.DownloadBytes(ctx, n)
		return err
	})

	if err = g.Wait(); err != nil {
		s.logger.Error(ctx, "error sync wait group: "+err.Error())
	}
}

func (s *Server) replyRequestWithError(ctx context.Context, writer io.Writer, err error, address *address) {
	switch {
	case networkUnreachableError(err):
		s.replyRequest(ctx, writer, networkUnreachable, address)
	case noSuchHostError(err):
		s.replyRequest(ctx, writer, hostUnreachable, address)
	case connectionRefusedError(err):
		s.replyRequest(ctx, writer, connectionRefused, address)
	default:
		s.replyRequest(ctx, writer, generalSOCKSserverFailure, address)
	}
}

func (s *Server) replyRequest(ctx context.Context, writer io.Writer, status byte, address *address) {
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

	s.response(ctx, writer, version5, status, fields...)
}

func (s *Server) response(ctx context.Context, writer io.Writer, version, status byte, fields ...byte) {
	res := []byte{
		version,
		status,
	}

	res = append(res, fields...)

	if _, err := writer.Write(res); err != nil {
		s.logger.Error(ctx, "failed to send a response to the client: "+err.Error())
	}
}
