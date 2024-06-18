<div align="center">

<img alt="Gopher socks logo" src="https://github.com/JC5LZiy3HVfV5ux/socks5-assets/blob/master/logo.png?raw=true" width="200">

<h1>SOCKS 5</h1>

[![license](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![go version](https://img.shields.io/github/go-mod/go-version/JC5LZiy3HVfV5ux/socks5)](go.mod)
[![go doc](https://godoc.org/github.com/JC5LZiy3HVfV5ux/socks5?status.svg)](https://pkg.go.dev/github.com/JC5LZiy3HVfV5ux/socks5)
[![go report](https://goreportcard.com/badge/github.com/JC5LZiy3HVfV5ux/socks5)](https://goreportcard.com/report/github.com/JC5LZiy3HVfV5ux/socks5)
[![tests](https://github.com/JC5LZiy3HVfV5ux/socks5/workflows/Test/badge.svg)](https://github.com/JC5LZiy3HVfV5ux/socks5/actions?workflow=Test)

<strong>[Report Bug](https://github.com/JC5LZiy3HVfV5ux/socks5/issues/new?assignees=&labels=bug&projects=&template=bug_report.yml&title=%5BBug%5D%3A+)</strong> | <strong>[Request Feature](https://github.com/JC5LZiy3HVfV5ux/socks5/issues/new?assignees=&labels=enhancement&projects=&template=feature_request.yml&title=%5BEnhancement%5D%3A+)</strong>

A fully featured implementation of the SOCKS 5 protocol in golang.

| CONNECT | BIND | UDP ASSOCIATE |
| :---: | :---: | :---: |
| ✅ - implemented | 🛠 - in progress | ✅ - implemented | 

<img alt="Gopher socks logo" src="https://github.com/JC5LZiy3HVfV5ux/socks5-assets/blob/master/preview.gif?raw=true" width="480">

</div>

## Installation

    go get github.com/JC5LZiy3HVfV5ux/socks5

## Getting Started

Create your `.go` file. For example: `main.go`.

```go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/JC5LZiy3HVfV5ux/socks5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := socks5.New()

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()

	if err := srv.Shutdown(); err != nil {
		log.Fatal(err)
	}
}
```

Run your server:

    go run main.go

The following curl example shows how to use the proxy server:

    curl -x socks5://127.0.0.1:1080 http://example.com

See the [tests](socks5_test.go) and [examples](examples) for more information about package.

## FAQ

* Why can't connect to socks proxy server?

    Not all applications and browsers support socks authentication or socks protocol. You may need [extension](https://github.com/txthinking/socks5-configurator) for Chrome or another browser.

If you have any questions, you can ask in [GitHub Discussions](https://github.com/JC5LZiy3HVfV5ux/socks5/discussions/new?category=q-a).

## Note

* The proof of work for the UDP association was done using [qBittorrent](https://github.com/qbittorrent/qBittorrent) - a BitTorrent client.

## Contributing
Feel free to open tickets or send pull requests with improvements. Thanks in advance for your help!

Please follow the [contribution guidelines](.github/CONTRIBUTING.md).

## References

* [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.txt) SOCKS Protocol Version 5
* [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.txt) Username/Password Authentication for SOCKS V5

## Licenses

* All source code is licensed under the [MIT License](LICENSE).

* Logo is based on the Go Gopher mascot originally designed by [Egon Elbre](https://github.com/egonelbre/gophers) and which is also licensed under the [CC0 1.0 Universal License](https://creativecommons.org/publicdomain/zero/1.0/).