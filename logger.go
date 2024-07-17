package socks5

import (
	"context"
	"fmt"
	"log"
)

type Logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

type stdoutLogger struct {
	log *log.Logger
}

func (l *stdoutLogger) Info(ctx context.Context, msg string, args ...any) {
	l.print(ctx, "INFO", msg, args...)
}

func (l *stdoutLogger) Warn(ctx context.Context, msg string, args ...any) {
	l.print(ctx, "WARN", msg, args...)
}

func (l *stdoutLogger) Error(ctx context.Context, msg string, args ...any) {
	l.print(ctx, "ERROR", msg, args...)
}

func (l *stdoutLogger) print(ctx context.Context, level, msg string, args ...any) {
	output := fmt.Sprintf("- %s - %s %s", level, msg, fmt.Sprintln(args...))

	if remoteAddress, ok := RemoteAddressFromContext(ctx); ok {
		output = fmt.Sprintf("- %s %s", remoteAddress, output)
	}

	l.log.Print(output)
}

type nopLogger struct{}

func (l *nopLogger) Info(_ context.Context, _ string, _ ...any)  {}
func (l *nopLogger) Warn(_ context.Context, _ string, _ ...any)  {}
func (l *nopLogger) Error(_ context.Context, _ string, _ ...any) {}

// Silent logger, produces no output.
var NopLogger *nopLogger
