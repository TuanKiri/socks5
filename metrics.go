package socks5

import "context"

type Metrics interface {
	UploadBytes(ctx context.Context, n int64)
	DownloadBytes(ctx context.Context, n int64)
}

type nopMetrics struct{}

func (m *nopMetrics) UploadBytes(_ context.Context, _ int64)   {}
func (m *nopMetrics) DownloadBytes(_ context.Context, _ int64) {}
