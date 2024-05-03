package socks5

import (
	"bytes"
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
		return
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

	switch command {
	case connect:
		s.connect(ctx, conn, &addr)
	case udpAssociate:
		s.udpAssociate(ctx, conn, &addr)
	default:
		s.replyRequest(ctx, conn, commandNotSupported, &addr)
		return
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
	l, err := s.driver.ListenPacket()
	if err != nil {
		s.replyRequestWithError(ctx, conn, err, addr)

		s.logger.Error(ctx, "error listen udp: "+err.Error())
		return
	}

	conn.onClose(func() {
		if l == nil {
			return
		}

		if err := l.Close(); err != nil {
			s.logger.Error(ctx, "error close udp listener: "+err.Error())
		}
	})

	go conn.keepAlive()

	var port port

	port.fromAddress(l.LocalAddr())

	s.replyRequest(ctx, conn, connectionSuccessful, &address{
		Type: addressTypeIPv4,
		IP:   s.config.publicIP,
		Port: port,
	})

	s.logger.Info(ctx, "start of udp datagram forwarding")

	// While tcp connection is active
	for conn.isActive() {
		//  The actual limit for the data length, which is imposed by the underlying IPv4 protocol, is 65507 bytes
		datagram := make([]byte, 65507)

		n, remoteAddress, err := l.ReadFrom(datagram)
		if err != nil {
			if !isClosedListenerError(err) {
				s.logger.Error(ctx, "error read datagram from udp connection: "+err.Error())
			}

			continue
		}

		if !conn.equalAddresses(remoteAddress) {
			continue
		}

		go s.serveDatagram(ctx, l, remoteAddress, datagram[:n])
	}

	s.logger.Info(ctx, "udp datagram forwarding complete")
}

func (s *Server) serveDatagram(ctx context.Context, l net.PacketConn, remoteAddress net.Addr, data []byte) {
	buf := bytes.NewBuffer(data)

	// Reserved 2 bytes: 0x00, 0x00
	if _, err := buf.Read(make([]byte, 2)); err != nil {
		s.logger.Error(ctx, "failed to read reserved bytes: "+err.Error())
		return
	}

	// Current fragment number
	frag, err := buf.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read current fragment number: "+err.Error())
		return
	}

	// If not support fragmentation must drop any datagram whose FRAG field is other than 0x00
	if frag != 0x00 {
		return
	}

	var addr address

	addr.Type, err = buf.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read address type: "+err.Error())
		return
	}

	switch addr.Type {
	case addressTypeIPv4:
		addr.IP = make(net.IP, net.IPv4len)
		if _, err := buf.Read(addr.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv4 address: "+err.Error())
			return
		}
	case addressTypeFQDN:
		addr.DomainLen, err = buf.ReadByte()
		if err != nil {
			s.logger.Error(ctx, "failed to read domain length: "+err.Error())
			return
		}

		addr.Domain = make([]byte, addr.DomainLen)
		if _, err := buf.Read(addr.Domain); err != nil {
			s.logger.Error(ctx, "failed to read domain: "+err.Error())
			return
		}
	case addressTypeIPv6:
		addr.IP = make(net.IP, net.IPv6len)
		if _, err := buf.Read(addr.IP); err != nil {
			s.logger.Error(ctx, "failed to read IPv6 address: "+err.Error())
			return
		}
	default:
		return
	}

	addr.Port = make([]byte, 2)
	if _, err := buf.Read(addr.Port); err != nil {
		s.logger.Error(ctx, "failed to read port: "+err.Error())
		return
	}

	target, err := s.driver.Dial("udp", addr.String())
	if err != nil {
		s.logger.Error(ctx, "dial udp "+addr.String()+": "+err.Error())
		return
	}
	defer target.Close()

	if _, err := target.Write(buf.Bytes()); err != nil {
		s.logger.Error(ctx, "failed to write data: "+err.Error())
		return
	}

	datagram := make([]byte, 65507)

	n, err := target.Read(datagram)
	if err != nil {
		s.logger.Error(ctx, "failed to read datagram: "+err.Error())
		return
	}

	response := []byte{
		0x00, // Reserved byte
		0x00, // Reserved byte
		0x00, // Current fragment number
		addr.Type,
	}

	switch addr.Type {
	case addressTypeIPv4:
		response = append(response, addr.IP.To4()...)
	case addressTypeFQDN:
		response = append(response, addr.DomainLen)
		response = append(response, addr.Domain...)
	case addressTypeIPv6:
		response = append(response, addr.IP.To16()...)
	}

	response = append(response, addr.Port...)
	response = append(response, datagram[:n]...)

	if _, err := l.WriteTo(response, remoteAddress); err != nil {
		if !isClosedListenerError(err) {
			s.logger.Error(ctx, "error write datagram to udp connection: "+err.Error())
		}
	}
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
