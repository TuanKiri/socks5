package socks5

import (
	"context"
	"net"
)

type ctxKey int

const (
	remoteAddressKey ctxKey = iota
	usernameKey
)

func contextWithRemoteAddress(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, remoteAddressKey, addr)
}

func RemoteAddressFromContext(ctx context.Context) (net.Addr, bool) {
	value, ok := ctx.Value(remoteAddressKey).(net.Addr)
	return value, ok
}

func contextWithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

func UsernameFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(usernameKey).(string)
	return value, ok
}
