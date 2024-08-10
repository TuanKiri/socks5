package socks5

import (
	"net"
	"sync"
	"time"
)

type natPacket struct {
	src       net.Addr
	packet    *packet
	timestamp time.Time
}

type natTable struct {
	sync.RWMutex
	table map[string]*natPacket
}

func newNatTable() *natTable {
	return &natTable{
		table: make(map[string]*natPacket),
	}
}

func (m *natTable) set(src, dst net.Addr, packet *packet) {
	m.Lock()
	m.table[dst.String()] = &natPacket{
		src:       src,
		packet:    packet,
		timestamp: time.Now().Add(15 * time.Second),
	}
	m.Unlock()
}

func (m *natTable) get(dst net.Addr) (net.Addr, *packet, bool) {
	m.RLock()
	defer m.RUnlock()

	val, ok := m.table[dst.String()]
	if !ok {
		return nil, nil, ok
	}

	return val.src, val.packet, ok
}

func (m *natTable) delete(dst net.Addr) {
	m.Lock()
	delete(m.table, dst.String())
	m.Unlock()
}

func (m *natTable) cleanUp() {
	for now := range time.Tick(1 * time.Minute) {
		m.Lock()
		for key, val := range m.table {
			if now.After(val.timestamp) {
				delete(m.table, key)
			}
		}
		m.Unlock()
	}
}
