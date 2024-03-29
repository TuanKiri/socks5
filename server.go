package socks5

import (
	"bufio"
	"context"
	"net"
	"time"
)

type config struct {
	readTimeout        time.Duration
	writeTimeout       time.Duration
	getPasswordTimeout time.Duration
	authMethods        map[byte]struct{}
}

type Server struct {
	config *config
	logger Logger
	store  Store
	driver Driver
}

func New(opts *Options) *Server {
	opts = optsWithDefaults(opts)

	return &Server{
		config: &config{
			readTimeout:        opts.ReadTimeout,
			writeTimeout:       opts.WriteTimeout,
			getPasswordTimeout: opts.GetPasswordTimeout,
			authMethods:        opts.authMethods(),
		},
		logger: opts.Logger,
		store:  opts.Store,
		driver: opts.Driver,
	}
}

func (s *Server) ListenAndServe() error {
	l, err := s.driver.Listen()
	if err != nil {
		return err
	}
	defer l.Close()

	s.logger.Info(context.Background(), "Server starting...")

	for {
		conn, err := l.Accept()
		if err != nil {
			s.logger.Error(context.Background(), "failed to accept connection: "+err.Error())
			continue
		}

		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()

	s.setConnDeadline(conn)

	reader := bufio.NewReader(conn)
	ctx := contextWithRemoteAddress(context.Background(), conn.RemoteAddr().String())

	s.handshake(ctx, conn, reader)
}

func (s *Server) setConnDeadline(conn net.Conn) {
	currentTime := time.Now().Local()

	if s.config.readTimeout != 0 {
		conn.SetReadDeadline(currentTime.Add(s.config.readTimeout))
	}

	if s.config.writeTimeout != 0 {
		conn.SetWriteDeadline(currentTime.Add(s.config.writeTimeout))
	}
}
