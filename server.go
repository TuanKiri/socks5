package socks5

import (
	"bufio"
	"net"
	"time"
)

type config struct {
	readTimeout         time.Duration
	writeTimeout        time.Duration
	connDatabaseTimeout time.Duration
	authMethods         map[byte]struct{}
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
			readTimeout:         opts.ReadTimeout,
			writeTimeout:        opts.WriteTimeout,
			connDatabaseTimeout: opts.ConnDatabaseTimeout,
			authMethods:         opts.authMethods(),
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

	for {
		conn, err := l.Accept()
		if err != nil {
			s.logger.LogErrorMessage(err, "failed to accept connection")
			continue
		}

		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()

	s.setConnDeadline(conn)

	reader := bufio.NewReader(conn)

	s.handshake(conn, reader)
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
