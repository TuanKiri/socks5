package socks5

import (
	"net"
	"sync"
	"time"
)

type natEntry struct {
	src       net.Addr
	packet    *packet
	timestamp time.Time
}

type natTable struct {
	mutex sync.RWMutex
	table map[string]*natEntry
}

func newNatTable() *natTable {
	return &natTable{table: make(map[string]*natEntry)}
}

func (n *natTable) set(src, dst net.Addr, packet *packet) {
	n.mutex.Lock()
	n.table[dst.String()] = &natEntry{
		src:       src,
		packet:    packet,
		timestamp: time.Now(),
	}
	n.mutex.Unlock()
}

func (n *natTable) get(dst net.Addr) (net.Addr, *packet, bool) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	val, ok := n.table[dst.String()]
	if !ok {
		return nil, nil, ok
	}

	return val.src, val.packet, ok
}

func (n *natTable) delete(dst net.Addr) {
	n.mutex.Lock()
	delete(n.table, dst.String())
	n.mutex.Unlock()
}

func (n *natTable) Cleanup(period, ttl time.Duration) func() {
	if period <= 0 || ttl <= 0 {
		return func() {}
	}

	ticker := time.NewTicker(period)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case <-ticker.C:
				n.mutex.Lock()
				for key, val := range n.table {
					if time.Since(val.timestamp) >= ttl {
						delete(n.table, key)
					}
				}
				n.mutex.Unlock()
			}
		}
	}()

	return func() {
		close(done)
	}
}
