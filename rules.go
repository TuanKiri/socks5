package socks5

import "context"

type RuleSet interface {
	AllowCommand(ctx context.Context, cmd byte) bool
}
