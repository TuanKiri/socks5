package socks5

import "sync"

type bytePool struct {
	*sync.Pool
}

func newBytePool(size int) *bytePool {
	return &bytePool{
		Pool: &sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

func (p *bytePool) get() []byte {
	return *(p.Get().(*[]byte))
}

func (p *bytePool) put(v []byte) {
	clear(v)
	p.Put(&v)
}
