package socks5

import (
	"errors"
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
	return errors.Is(err, syscall.ECONNREFUSED)
}
