package socks5_test

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	"github.com/TuanKiri/socks5"
)

func TestProxyConnect(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
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
				socks5.WithBlockListHosts(
					"www.google.com",
				),
			},
			destinationUrl: "http://www.google.com",
			errString: "Get \"http://www.google.com\": socks connect " +
				"tcp 127.0.0.1:1160->www.google.com:80: unknown error connection not allowed by ruleset",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			go runProxy(tc.proxyOpts...)

			// Wait for socks5 proxy to start
			time.Sleep(100 * time.Millisecond)

			client, err := newHttpClient(tc.proxyAddress, tc.clientCredentials)
			require.NoError(t, err)

			response, err := client.Get(tc.destinationUrl)
			if err != nil {
				require.EqualError(t, err, tc.errString)
				return
			}
			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)

			assert.Equal(t, tc.wait, body)
		})
	}
}

func TestProxyUDPAssociate(t *testing.T) {
	testCase := struct {
		handshake     []byte
		response      []byte
		request       []byte
		acceptRequest []byte
		packets       map[string][]byte
	}{
		handshake: []byte{
			0x05, // version: 5
			0x01, // number of methods: 1
			0x00, // method: no authentication required
		},
		response: []byte{
			0x05, // version: 5
			0x00, // method: no authentication required
		},
		request: []byte{
			0x05,                   // version: 5
			0x03,                   // command: udp associate
			0x00,                   // reserved byte
			0x01,                   // address type: Ipv4
			0x00, 0x00, 0x00, 0x00, // address: 0.0.0.0
			0xB6, 0xD9, // port: 46809
		},
		acceptRequest: []byte{
			0x05,                   // version: 5
			0x00,                   // status: connection successful
			0x00,                   // reserved byte
			0x01,                   // address type: Ipv4
			0x7F, 0x00, 0x00, 0x01, // address: 127.0.0.1
			0xB6, 0xD9, // port: 46809
		},
		packets: map[string][]byte{
			"IPv4_address": {
				0x00, 0x00, // reserved 2 bytes
				0x00,                   // current fragment number: 0
				0x01,                   // address type: Ipv4
				0x7F, 0x00, 0x00, 0x01, // address: 127.0.0.1
				0x1D, 0x14, // port: 7444
				0x48, 0x45, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x4F, 0x52, 0x6C, 0x64, // payload: HEllo WORld
			},
			"FQDN_address": {
				0x00, 0x00, // reserved 2 bytes
				0x00,                                                 // current fragment number: 0
				0x03,                                                 // address type: FQDN
				0x09,                                                 // domain len: 9
				0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, // address: localhost
				0x1D, 0x14, // port: 7444
				0x48, 0x45, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x4F, 0x52, 0x6C, 0x64, // payload: HEllo WORld
			},
			"IPv6_address": {
				0x00, 0x00, // reserved 2 bytes
				0x00,                                                                                           // current fragment number: 0
				0x04,                                                                                           // address type: IPv6
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // address: ::1
				0x1D, 0x14, // port: 7444
				0x48, 0x45, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x4F, 0x52, 0x6C, 0x64, // payload: HEllo WORld
			},
		},
	}

	go runProxy(
		socks5.WithLogger(socks5.NopLogger),
	)

	// Wait for socks5 proxy to start
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", ":1080")
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	_, err = conn.Write(testCase.handshake)
	require.NoError(t, err)

	response := make([]byte, 2)
	_, err = conn.Read(response)
	require.NoError(t, err)

	require.Equal(t, testCase.response, response)

	_, err = conn.Write(testCase.request)
	require.NoError(t, err)

	acceptRequest := make([]byte, 10)
	_, err = conn.Read(acceptRequest)
	require.NoError(t, err)

	require.Equal(t, testCase.acceptRequest, acceptRequest)

	udpConn, err := net.Dial("udp", ":46809")
	require.NoError(t, err)

	t.Cleanup(func() {
		udpConn.Close()
	})

	for name, packet := range testCase.packets {
		udpConn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))

		_, err := udpConn.Write(packet)
		require.NoErrorf(t, err, name)

		udpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

		response := make([]byte, len(packet))
		_, err = udpConn.Read(response)
		require.NoErrorf(t, err, name)

		assert.Equalf(t, packet, response, name)
	}
}
