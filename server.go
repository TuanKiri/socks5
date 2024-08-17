package socks5

import (
	"context"
	"net"
	"time"
)

type config struct {
	host               string
	address            string
	readTimeout        time.Duration
	writeTimeout       time.Duration
	getPasswordTimeout time.Duration
	authMethods        map[byte]struct{}
	publicIP           net.IP
	packetWriteTimeout time.Duration
	ttlPacket          time.Duration
	natCleanupPeriod   time.Duration
}

type Server struct {
	config        *config
	logger        Logger
	store         Store
	driver        Driver
	metrics       Metrics
	rules         Rules
	bytePool      *bytePool
	active        chan struct{}
	done          chan struct{}
	closeListener func() error
}

func New(opts ...Option) *Server {
	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	options = optsWithDefaults(options)

	return &Server{
		config: &config{
			host:               options.host,
			address:            options.listenAddress(),
			readTimeout:        options.readTimeout,
			writeTimeout:       options.writeTimeout,
			getPasswordTimeout: options.getPasswordTimeout,
			authMethods:        options.authMethods(),
			publicIP:           options.publicIP,
			packetWriteTimeout: options.packetWriteTimeout,
			ttlPacket:          options.ttlPacket,
			natCleanupPeriod:   options.natCleanupPeriod,
		},
		logger:   options.logger,
		store:    options.store,
		driver:   options.driver,
		metrics:  options.metrics,
		rules:    options.rules,
		bytePool: newBytePool(options.maxPacketSize),
		active:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (s *Server) ListenAndServe() error {
	l, err := s.driver.Listen("tcp", s.config.address)
	if err != nil {
		return err
	}

	s.closeListener = closeListenerFn(l)

	ctx := context.Background()

	s.logger.Info(ctx, "server starting...")

	for s.isActive() {
		conn, err := l.Accept()
		if err != nil {
			if !isClosedListenerError(err) {
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

	remoteAddr := conn.RemoteAddr()

	if !s.rules.IsAllowConnection(remoteAddr) {
		return
	}

	conn.SetReadDeadline(newDeadline(s.config.readTimeout))
	conn.SetWriteDeadline(newDeadline(s.config.writeTimeout))

	ctx := contextWithRemoteAddress(context.Background(), remoteAddr)

	s.handshake(ctx, newConnection(conn))
}

func (s *Server) isActive() bool {
	select {
	case <-s.active:
		return false
	default:
		return true
	}
}

func closeListenerFn(l net.Listener) func() error {
	return func() error {
		return l.Close()
	}
}

func newDeadline(d time.Duration) time.Time {
	if d > 0 {
		return time.Now().Local().Add(d)
	}

	return time.Time{}
}
