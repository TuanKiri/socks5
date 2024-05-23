package socks5

import (
	"context"
	"net"
)

type Rules interface {
	IsAllowCommand(ctx context.Context, cmd byte) bool
	IsAllowConnection(addr net.Addr) bool
	IsAllowDestination(ctx context.Context, host string) bool
}

type serverRules struct {
	allowCommands map[byte]struct{}
	blockList     map[string]struct{}
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

func (r *serverRules) IsAllowDestination(ctx context.Context, host string) bool {
	if r.blockList == nil {
		return true
	}

	_, ok := r.blockList[host]
	return !ok
}

func permitAllCommands() map[byte]struct{} {
	return map[byte]struct{}{
		connect:      {},
		bind:         {},
		udpAssociate: {},
	}
}
