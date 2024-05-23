package socks5

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPRules(t *testing.T) {
	cases := map[string]struct {
		allowIPs []net.IP
		address  net.Addr
		allow    bool
	}{
		"allow_connection": {
			allowIPs: []net.IP{
				net.ParseIP("192.168.0.100"),
			},
			address: &net.TCPAddr{
				IP: net.ParseIP("192.168.0.100"),
			},
			allow: true,
		},
		"not_allow_connection": {
			allowIPs: []net.IP{},
			address: &net.TCPAddr{
				IP: net.ParseIP("192.168.0.101"),
			},
			allow: false,
		},
		"incorrect_address_type": {
			allowIPs: []net.IP{},
			address:  &net.UDPAddr{},
			allow:    false,
		},
		"without_allow_IPs": {
			allow: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rules := &serverRules{
				allowIPs: tc.allowIPs,
			}

			assert.Equal(t, rules.IsAllowConnection(tc.address), tc.allow)
		})
	}
}
