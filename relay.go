package socks5

import (
	"io"
	"net"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

func relay(dst io.Writer, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, src)

	if writer, ok := dst.(closeWriter); ok {
		// Send EOF for next io.Copy
		writer.CloseWrite()
	}

	return n, err
}

type packetInfo struct {
	src       net.Addr
	packet    *packet
	timestamp time.Time
}

type UDPRelayMapper struct {
	sync.RWMutex
	storage map[string]*packetInfo
}

func newUDPRelayMapper() *UDPRelayMapper {
	return &UDPRelayMapper{
		storage: make(map[string]*packetInfo),
	}
}

func (m *UDPRelayMapper) save(src, dst net.Addr, packet *packet) {
	m.Lock()
	m.storage[dst.String()] = &packetInfo{
		src:       src,
		packet:    packet,
		timestamp: time.Now().Add(15 * time.Second),
	}
	m.Unlock()
}

func (m *UDPRelayMapper) get(dst net.Addr) (net.Addr, *packet, bool) {
	m.RLock()
	defer m.RUnlock()

	packetInfo, ok := m.storage[dst.String()]
	if ok {
		return packetInfo.src, packetInfo.packet, ok
	}

	return nil, nil, false
}

func (m *UDPRelayMapper) delete(dst net.Addr) {
	m.Lock()
	delete(m.storage, dst.String())
	m.Unlock()
}

func (m *UDPRelayMapper) cleanUp() {
	timer := time.NewTimer(1 * time.Minute)

	for {
		<-timer.C
		m.Lock()
		now := time.Now()
		for key, val := range m.storage {
			if now.After(val.timestamp) {
				delete(m.storage, key)
			}
		}
		m.Unlock()
		timer.Reset(1 * time.Minute)
	}
}
