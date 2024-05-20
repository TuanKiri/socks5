package socks5

import "context"

type Rules interface {
	AllowCommand(ctx context.Context, cmd byte) bool
}

type serverRules struct {
	allowCommands map[byte]struct{}
}

func (r *serverRules) AllowCommand(ctx context.Context, cmd byte) bool {
	_, ok := r.allowCommands[cmd]
	return ok
}

func permitAllCommands() map[byte]struct{} {
	return map[byte]struct{}{
		connect:      {},
		bind:         {},
		udpAssociate: {},
	}
}
