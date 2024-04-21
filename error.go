package socks5

import (
	"errors"
	"net"
	"strings"
	"syscall"
)

func isNoSuchHostError(err error) bool {
	return strings.Contains(err.Error(), "no such host")
}

func isNetworkUnreachableError(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH)
}

func isConnectionRefusedError(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}

	// For example error: https://github.com/golang/go/issues/45621
	return strings.Contains(err.Error(), "refused")
}

func isClosedListenerError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
