package socks5

import "context"

type ctxKey int

const remoteAddressKey ctxKey = iota

func contextWithRemoteAddress(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, remoteAddressKey, address)
}

func RemoteAddressFromContext(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(remoteAddressKey).(string)
	return value, ok
}
