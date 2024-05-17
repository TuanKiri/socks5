package socks5

import "context"

type ctxKey int

const (
	remoteAddressKey ctxKey = iota
	usernameKey
)

func contextWithRemoteAddress(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, remoteAddressKey, address)
}

func RemoteAddressFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(remoteAddressKey).(string)
	return value, ok
}

func contextWithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username)
}

func UsernameFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(usernameKey).(string)
	return value, ok
}
