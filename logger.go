package socks5

import "log"

type Logger interface {
	LogErrorMessage(err error, message string)
}

type stdoutLogger struct {
	errorLogger *log.Logger
}

func (l *stdoutLogger) LogErrorMessage(err error, message string) {
	l.errorLogger.Printf("level: ERROR message: %s error: %s", message, err)
}

// Silent logger, produces no output
type NoOutputLogger struct{}

func (l *NoOutputLogger) LogErrorMessage(err error, message string) {}
