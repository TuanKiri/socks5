package socks5

import "context"

type Store interface {
	GetPassword(ctx context.Context, username string) (string, error)
}

type mapStore struct {
	db map[string]string
}

func (s mapStore) GetPassword(ctx context.Context, username string) (string, error) {
	return s.db[username], nil
}
