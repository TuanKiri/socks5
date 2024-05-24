package socks5

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	Connect Command = iota + 1
	Bind
	UDPAssociate
)

type Command int

type Option func(*options)

type options struct {
	host                   string
	port                   int
	publicIP               net.IP
	readTimeout            time.Duration
	writeTimeout           time.Duration
	dialTimeout            time.Duration
	getPasswordTimeout     time.Duration
	passwordAuthentication bool
	staticCredentials      map[string]string
	allowCommands          map[byte]struct{}
	blockListHosts         map[string]struct{}
	allowIPs               []net.IP
	logger                 Logger
	store                  Store
	driver                 Driver
	metrics                Metrics
	rules                  Rules
}

func (o options) authMethods() map[byte]struct{} {
	methods := make(map[byte]struct{})

	switch {
	case o.passwordAuthentication:
		methods[usernamePasswordAuthentication] = struct{}{}
	default:
		methods[noAuthenticationRequired] = struct{}{}
	}

	return methods
}

func (o options) listenAddress() string {
	return fmt.Sprintf("%s:%d", o.host, o.port)
}

func optsWithDefaults(opts *options) *options {
	if opts.port == 0 {
		opts.port = 1080
	}

	if opts.publicIP == nil {
		opts.publicIP = net.ParseIP("127.0.0.1")
	}

	if opts.logger == nil {
		opts.logger = &stdoutLogger{
			log: log.New(os.Stdout, "[socks5] - ", log.Ldate|log.Ltime),
		}
	}

	if opts.store == nil {
		if opts.staticCredentials == nil {
			opts.staticCredentials = map[string]string{
				"root": "password",
			}
		}

		opts.store = &mapStore{
			db: opts.staticCredentials,
		}
	}

	if opts.driver == nil {
		opts.driver = &netDriver{
			timeout: opts.dialTimeout,
		}
	}

	if opts.metrics == nil {
		opts.metrics = &nopMetrics{}
	}

	if opts.rules == nil {
		if opts.allowCommands == nil {
			opts.allowCommands = permitAllCommands()
		}

		opts.rules = &serverRules{
			allowCommands:  opts.allowCommands,
			blockListHosts: opts.blockListHosts,
			allowIPs:       opts.allowIPs,
		}
	}

	return opts
}

func WithHost(val string) Option {
	return func(o *options) {
		o.host = val
	}
}

func WithPort(val int) Option {
	return func(o *options) {
		o.port = val
	}
}

func WithPublicIP(val net.IP) Option {
	return func(o *options) {
		o.publicIP = val
	}
}

func WithReadTimeout(val time.Duration) Option {
	return func(o *options) {
		o.readTimeout = val
	}
}

func WithWriteTimeout(val time.Duration) Option {
	return func(o *options) {
		o.writeTimeout = val
	}
}

func WithDialTimeout(val time.Duration) Option {
	return func(o *options) {
		o.dialTimeout = val
	}
}

func WithGetPasswordTimeout(val time.Duration) Option {
	return func(o *options) {
		o.getPasswordTimeout = val
	}
}

func WithPasswordAuthentication() Option {
	return func(o *options) {
		o.passwordAuthentication = true
	}
}

func WithStaticCredentials(val map[string]string) Option {
	return func(o *options) {
		o.staticCredentials = val
	}
}

func WithLogger(val Logger) Option {
	return func(o *options) {
		o.logger = val
	}
}

func WithStore(val Store) Option {
	return func(o *options) {
		o.store = val
	}
}

func WithDriver(val Driver) Option {
	return func(o *options) {
		o.driver = val
	}
}

func WithMetrics(val Metrics) Option {
	return func(o *options) {
		o.metrics = val
	}
}

func WithRules(val Rules) Option {
	return func(o *options) {
		o.rules = val
	}
}

func WithAllowCommands(commands ...Command) Option {
	allowCommands := map[byte]struct{}{}

	for _, command := range commands {
		allowCommands[byte(command)] = struct{}{}
	}

	return func(o *options) {
		o.allowCommands = allowCommands
	}
}

func WithWhiteListIPs(IPs ...net.IP) Option {
	return func(o *options) {
		o.allowIPs = IPs
	}
}

func WithBlockListHosts(hosts ...string) Option {
	blockListHosts := map[string]struct{}{}

	for _, host := range hosts {
		blockListHosts[host] = struct{}{}
	}

	return func(o *options) {
		o.blockListHosts = blockListHosts
	}
}
