package socks5

import "context"

type Store interface {
	GetPassword(ctx context.Context, username string) (string, error)
}

type defaultStore struct {
	db map[string]string
}

func (s defaultStore) GetPassword(ctx context.Context, username string) (string, error) {
	return s.db[username], nil
}
