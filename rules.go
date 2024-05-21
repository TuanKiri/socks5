package socks5

import (
	"context"
	"net"
)

type Rules interface {
	IsAllowConnection(addr net.Addr) bool
	IsAllowCommand(ctx context.Context, cmd byte) bool
}

type serverRules struct {
	allowCommands map[byte]struct{}
	allowIPs      []net.IP
}

func (r *serverRules) IsAllowCommand(ctx context.Context, cmd byte) bool {
	_, ok := r.allowCommands[cmd]
	return ok
}

func (r *serverRules) IsAllowConnection(addr net.Addr) bool {
	if r.allowIPs == nil {
		return true
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}

	for _, allowIP := range r.allowIPs {
		if allowIP.Equal(tcpAddr.IP) {
			return true
		}
	}

	return false
}

func permitAllCommands() map[byte]struct{} {
	return map[byte]struct{}{
		connect:      {},
		bind:         {},
		udpAssociate: {},
	}
}
