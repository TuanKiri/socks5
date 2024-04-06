package socks5

import (
	"errors"
	"net"
	"strings"
	"syscall"
)

func noSuchHostError(err error) bool {
	return strings.Contains(err.Error(), "no such host")
}

func networkUnreachableError(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH)
}

func connectionRefusedError(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}

	// for example error: https://github.com/golang/go/issues/45621
	return strings.Contains(err.Error(), "refused")
}

func isClosedError(e error) bool {
	return errors.Is(e, net.ErrClosed)
}
