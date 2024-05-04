package socks5

import (
	"log"
	"net"
	"os"
	"time"
)

type Options struct {
	ListenAddress      string            // default: 127.0.0.1:1080
	PublicIP           net.IP            // default: 127.0.0.1. Only IPv4 address that is visible to the external connections. Port is assigned automatically.
	ReadTimeout        time.Duration     // default: none
	WriteTimeout       time.Duration     // default: none
	DialTimeout        time.Duration     // default: none
	GetPasswordTimeout time.Duration     // default: none
	Authentication     bool              // default: no authentication required
	StaticCredentials  map[string]string // default: root / password
	Logger             Logger            // default: stdoutLogger
	Store              Store             // default: mapStore
	Driver             Driver            // default: netDriver
	Metrics            Metrics           // default: nopMetrics
}

func (o Options) authMethods() map[byte]struct{} {
	methods := make(map[byte]struct{})

	switch {
	case o.Authentication:
		methods[usernamePasswordAuthentication] = struct{}{}
	default:
		methods[noAuthenticationRequired] = struct{}{}
	}

	return methods
}

func optsWithDefaults(opts *Options) *Options {
	if opts == nil {
		opts = &Options{}
	}

	if opts.Logger == nil {
		opts.Logger = &stdoutLogger{
			log: log.New(os.Stdout, "[socks5] - ", log.Ldate|log.Ltime),
		}
	}

	if opts.Store == nil {
		if opts.StaticCredentials == nil {
			opts.StaticCredentials = map[string]string{
				"root": "password",
			}
		}

		opts.Store = &mapStore{
			db: opts.StaticCredentials,
		}
	}

	if opts.Driver == nil {
		if opts.ListenAddress == "" {
			opts.ListenAddress = "127.0.0.1:1080"
		}

		host, _, err := net.SplitHostPort(opts.ListenAddress)
		if err != nil {
			host = "127.0.0.1"
		}

		opts.Driver = &netDriver{
			listenAddress: opts.ListenAddress,
			bindAddress:   host + ":0",
			dialTimeout:   opts.DialTimeout,
		}
	}

	if opts.PublicIP == nil {
		opts.PublicIP = net.ParseIP("127.0.0.1")
	}

	if opts.Metrics == nil {
		opts.Metrics = &nopMetrics{}
	}

	return opts
}
