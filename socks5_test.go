package socks5_test

import (
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	"github.com/JC5LZiy3HVfV5ux/socks5"
)

func TestProxyConnect(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		proxyAddress      string
		proxyOpts         []socks5.Option
		destinationUrl    string
		clientCredentials *proxy.Auth
		wait              []byte
		errString         string
	}{
		"IPv4_address": {
			proxyAddress: "127.0.0.1:1151",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1151),
			},
			destinationUrl: "http://127.0.0.1:5444/ping",
			wait:           []byte("pong!"),
		},
		"FQDN_address": {
			proxyAddress: "127.0.0.1:1152",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1152),
			},
			destinationUrl: "http://localhost:5444/ping",
			wait:           []byte("pong!"),
		},
		"authenticate_by_username_password": {
			proxyAddress: "127.0.0.1:1153",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1153),
				socks5.WithPasswordAuthentication(),
			},
			destinationUrl: "http://localhost:5444/ping",
			clientCredentials: &proxy.Auth{
				User:     "root",
				Password: "password",
			},
			wait: []byte("pong!"),
		},
		"wrong_authenticate_by_username_password": {
			proxyAddress: "127.0.0.1:1154",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1154),
				socks5.WithPasswordAuthentication(),
				socks5.WithStaticCredentials(map[string]string{
					"root": "password123",
				}),
			},
			destinationUrl: "http://localhost:5444",
			clientCredentials: &proxy.Auth{
				User:     "root",
				Password: "password",
			},
			errString: "Get \"http://localhost:5444\": socks connect " +
				"tcp 127.0.0.1:1154->localhost:5444: username/password authentication failed",
		},
		"over_tls": {
			proxyAddress: "127.0.0.1:1155",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1155),
				socks5.WithDriver(&testTLSDriver{
					tlsConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
					},
				}),
			},
			destinationUrl: "https://localhost:6444/ping",
			wait:           []byte("pong!"),
		},
		"connection_refused": {
			proxyAddress: "127.0.0.1:1156",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1156),
			},
			destinationUrl: "http://localhost:4000",
			errString: "Get \"http://localhost:4000\": socks connect " +
				"tcp 127.0.0.1:1156->localhost:4000: unknown error connection refused",
		},
		"IPv6_address": {
			proxyAddress: "127.0.0.1:1157",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1157),
			},
			destinationUrl: "http://[::1]:5444/ping",
			wait:           []byte("pong!"),
		},
		"host_unreachable": {
			proxyAddress: "127.0.0.1:1158",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1158),
			},
			destinationUrl: "http://no_such_host.test",
			errString: "Get \"http://no_such_host.test\": socks connect " +
				"tcp 127.0.0.1:1158->no_such_host.test:80: unknown error host unreachable",
		},
		"not_allowed_command": {
			proxyAddress: "127.0.0.1:1159",
			proxyOpts: []socks5.Option{
				socks5.WithAllowCommands(),
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1159),
			},
			destinationUrl: "http://localhost:4000",
			errString: "Get \"http://localhost:4000\": socks connect " +
				"tcp 127.0.0.1:1159->localhost:4000: unknown error connection not allowed by ruleset",
		},
		"not_allowed_host": {
			proxyAddress: "127.0.0.1:1160",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1160),
				socks5.WithDriver(&testTLSDriver{
					tlsConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
					},
				}),
				socks5.WithBlockListHosts(
					"www.google.com",
				),
			},
			destinationUrl: "https://www.google.com",
			errString: "Get \"https://www.google.com\": socks connect " +
				"tcp 127.0.0.1:1160->www.google.com:443: unknown error connection not allowed by ruleset",
		},
		"not_allowed_ip": {
			proxyAddress: "127.0.0.1:1161",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1161),
				socks5.WithBlockListHosts(
					"173.194.222.102",
				),
			},
			destinationUrl: "http://173.194.222.102",
			errString: "Get \"http://173.194.222.102\": socks connect " +
				"tcp 127.0.0.1:1161->173.194.222.102:80: unknown error connection not allowed by ruleset",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			go runProxy(tc.proxyOpts)

			// Wait for socks5 proxy to start
			time.Sleep(100 * time.Millisecond)

			client, err := setupClient(tc.proxyAddress, tc.clientCredentials)
			assert.NoError(t, err)

			resp, err := client.Get(tc.destinationUrl)
			if err != nil {
				require.EqualError(t, err, tc.errString)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			require.Equal(t, tc.wait, body)
		})
	}
}
