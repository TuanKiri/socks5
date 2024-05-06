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
		remoteServerAddress string
		proxyAddress        string
		proxyOpts           []socks5.Option
		destinationUrl      string
		clientCredentials   *proxy.Auth
		useTLS              bool
		wait                []byte
		errString           string
	}{
		"IPv4_address": {
			remoteServerAddress: "127.0.0.1:9451",
			proxyAddress:        "127.0.0.1:1151",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1151),
			},
			destinationUrl: "http://127.0.0.1:9451/ping",
			wait:           []byte("pong!"),
		},
		"FQDN_address": {
			remoteServerAddress: "localhost:9452",
			proxyAddress:        "127.0.0.1:1152",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1152),
			},
			destinationUrl: "http://localhost:9452/ping",
			wait:           []byte("pong!"),
		},
		"authenticate_by_username_password": {
			remoteServerAddress: "127.0.0.1:9453",
			proxyAddress:        "127.0.0.1:1153",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1153),
				socks5.WithPasswordAuthentication(),
			},
			destinationUrl: "http://localhost:9453/ping",
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
			destinationUrl: "http://localhost:9454",
			clientCredentials: &proxy.Auth{
				User:     "root",
				Password: "password",
			},
			errString: "Get \"http://localhost:9454\": socks connect " +
				"tcp 127.0.0.1:1154->localhost:9454: username/password authentication failed",
		},
		"over_tls": {
			remoteServerAddress: "127.0.0.1:9455",
			proxyAddress:        "127.0.0.1:1155",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1155),
				socks5.WithPasswordAuthentication(),
				socks5.WithDriver(&testTLSDriver{
					tlsConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
					},
				}),
			},
			useTLS:         true,
			destinationUrl: "https://localhost:9455/ping",
			clientCredentials: &proxy.Auth{
				User:     "root",
				Password: "password",
			},
			wait: []byte("pong!"),
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
			remoteServerAddress: "[::1]:9457",
			proxyAddress:        "127.0.0.1:1157",
			proxyOpts: []socks5.Option{
				socks5.WithLogger(socks5.NopLogger),
				socks5.WithPort(1157),
			},
			destinationUrl: "http://[::1]:9457/ping",
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
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			go runRemoteServer(tc.remoteServerAddress, tc.useTLS)
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
