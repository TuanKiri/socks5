package socks5_test

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"

	"golang.org/x/net/proxy"

	"github.com/TuanKiri/socks5"
)

// openssl req -new -x509 -key server.key -out server.pem -addext "subjectAltName = IP:127.0.0.1"
const certPem = `-----BEGIN CERTIFICATE-----
MIIB8DCCAZagAwIBAgIUezJSnEIvoBkjS1w+3Re7uol2jRkwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAzMDcxNjEyMTlaFw0yNDA0MDYx
NjEyMTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATS8tgo3dl8pS/A8yJ8fNJ2W4CYE+cdRQab+R77egsKsV1vrrd+tmqU
9BMLi5bsADLBERnZ6R3xdRfwnB1MkeY+o2QwYjAdBgNVHQ4EFgQU8fu/z8bxM64M
nvI/zgrdylJ9MxgwHwYDVR0jBBgwFoAU8fu/z8bxM64MnvI/zgrdylJ9MxgwDwYD
VR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMCA0gAMEUC
IBDkOCj1Dn2FzNSHyVF4Uy50DDBNiba216mgfCpuMxKsAiEAr8utWKFRT+ZvjgmX
dKn36veVe7eVPpfhV9IeC1VejsY=
-----END CERTIFICATE-----
`

// openssl ecparam -genkey -name prime256v1 -out server.key
const keyPem = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJLgUlepvBWpmMlJqjPlLzEzjUKR/7CmcM2OD1LMKQ0uoAoGCCqGSM49
AwEHoUQDQgAE0vLYKN3ZfKUvwPMifHzSdluAmBPnHUUGm/ke+3oLCrFdb663frZq
lPQTC4uW7AAywREZ2ekd8XUX8JwdTJHmPg==
-----END EC PRIVATE KEY-----
`

var cert tls.Certificate

func init() {
	c, err := tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		panic(err)
	}
	cert = c

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "pong!")
	})

	go func() {
		if err := http.ListenAndServe(":5444", mux); err != nil {
			log.Fatalf("runRemoteServer: %v", err)
		}
	}()

	go func() {
		if err := listenAndServeTLS(":6444", mux); err != nil {
			log.Fatalf("runRemoteServer: %v", err)
		}
	}()
}

type testTLSDial struct{}

func (p testTLSDial) Dial(network, address string) (c net.Conn, err error) {
	return tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true})
}

type testTLSDriver struct {
	tlsConfig *tls.Config
}

func (d testTLSDriver) Listen(network, address string) (net.Listener, error) {
	return tls.Listen(network, address, d.tlsConfig)
}

func (d testTLSDriver) Dial(network, address string) (net.Conn, error) {
	return tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true})
}

func (d testTLSDriver) ListenPacket(network, address string) (net.PacketConn, error) {
	return nil, nil
}

func listenAndServeTLS(address string, handler http.Handler) error {
	server := http.Server{
		Addr: address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler: handler,
	}

	return server.ListenAndServeTLS("", "")
}

func runProxy(opts []socks5.Option) {
	srv := socks5.New(opts...)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("runProxy: %v", err)
	}
}

func setupClient(proxyAddress string, auth *proxy.Auth) (*http.Client, error) {
	socksProxy, err := proxy.SOCKS5(
		"tcp",
		proxyAddress,
		auth,
		proxy.Direct,
	)
	if err != nil {
		return nil, err
	}

	tlsSocksProxy, err := proxy.SOCKS5(
		"tcp",
		proxyAddress,
		auth,
		&testTLSDial{},
	)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Dial:    socksProxy.Dial,
			DialTLS: tlsSocksProxy.Dial,
		},
	}, nil
}
