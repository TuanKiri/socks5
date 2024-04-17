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
	config        *config
	logger        Logger
	store         Store
	driver        Driver
	metrics       Metrics
	active        chan struct{}
	done          chan struct{}
	closeListener func() error
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
		logger:  opts.Logger,
		store:   opts.Store,
		driver:  opts.Driver,
		metrics: opts.Metrics,
		active:  make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (s *Server) ListenAndServe() error {
	l, err := s.driver.Listen()
	if err != nil {
		return err
	}
	s.setListener(l)

	ctx := context.Background()

	s.logger.Info(ctx, "server starting...")

	for s.isActive() {
		conn, err := l.Accept()
		if err != nil {
			if !closedListenerError(err) {
				s.logger.Error(ctx, "failed to accept connection: "+err.Error())
			}

			continue
		}

		go s.serve(conn)
	}

	s.logger.Info(ctx, "server stopping...")

	close(s.done)

	return nil
}

func (s *Server) Shutdown() error {
	if !s.isActive() {
		return nil
	}

	close(s.active)
	err := s.closeListener()

	<-s.done

	return err
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

func (s *Server) isActive() bool {
	select {
	case <-s.active:
		return false
	default:
		return true
	}
}

func (s *Server) setListener(l net.Listener) {
	s.closeListener = func() error {
		if l == nil {
			return nil
		}

		return l.Close()
	}
}
