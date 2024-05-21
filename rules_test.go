package socks5

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPRules(t *testing.T) {
	cases := map[string]struct {
		rules   *serverRules
		address net.Addr
		allow   bool
	}{
		"allow_connection": {
			rules: &serverRules{
				allowIPs: []net.IP{
					net.ParseIP("192.168.0.100"),
				},
			},
			address: &net.TCPAddr{
				IP: net.ParseIP("192.168.0.100"),
			},
			allow: true,
		},
		"not_allow_connection": {
			rules: &serverRules{
				allowIPs: []net.IP{},
			},
			address: &net.TCPAddr{
				IP: net.ParseIP("192.168.0.101"),
			},
			allow: false,
		},
		"incorrect_address_type": {
			rules: &serverRules{
				allowIPs: []net.IP{},
			},
			address: &net.UDPAddr{
				IP: net.ParseIP("192.168.0.101"),
			},
			allow: false,
		},
		"without_allow_IPs": {
			rules: &serverRules{},
			allow: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.rules.IsAllowConnection(tc.address), tc.allow)
		})
	}
}
