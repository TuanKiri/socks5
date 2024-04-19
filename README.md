<div align="center">

<img alt="Gopher socks logo" src="https://github.com/JC5LZiy3HVfV5ux/assets/blob/master/socks5/logo.png?raw=true" width="200">

<h1>SOCKS 5 proxy</h1>

[![license](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![go version](https://img.shields.io/github/go-mod/go-version/JC5LZiy3HVfV5ux/socks5)](go.mod)
[![go doc](https://godoc.org/github.com/JC5LZiy3HVfV5ux/socks5?status.svg)](https://pkg.go.dev/github.com/JC5LZiy3HVfV5ux/socks5)
[![go report](https://goreportcard.com/badge/github.com/JC5LZiy3HVfV5ux/socks5)](https://goreportcard.com/report/github.com/JC5LZiy3HVfV5ux/socks5)
[![tests](https://github.com/JC5LZiy3HVfV5ux/socks5/workflows/Test/badge.svg)](https://github.com/JC5LZiy3HVfV5ux/socks5/actions?workflow=Test)

<strong>[Report Bug](https://github.com/JC5LZiy3HVfV5ux/socks5/issues/new?assignees=&labels=bug&projects=&template=bug_report.yml&title=%5BBug%5D%3A+)</strong> | <strong>[Request Feature](https://github.com/JC5LZiy3HVfV5ux/socks5/issues/new?assignees=&labels=enhancement&projects=&template=feature_request.yml&title=%5BEnhancement%5D%3A+)</strong>

Golang package for implementing a SOCKS 5 proxy server.

| CONNECT | BIND | ASSOCIATE |
| :---: | :---: | :---: |
| ✅ - implemented | ❌ - not implemented | 🛠 - in progress | 

<img alt="Gopher socks logo" src="https://github.com/JC5LZiy3HVfV5ux/assets/blob/master/socks5/preview.gif?raw=true" width="480">

</div>

## Installation

    go get github.com/JC5LZiy3HVfV5ux/socks5

## Getting Started

Create your `.go` file. For example: `main.go`.

```go
package main

import (
	"log"

	"github.com/JC5LZiy3HVfV5ux/socks5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Options allowed as nil. Example options: 
	// &socks5.Options{
	//     Authentication: true,
	//     ListenAddress:  "0.0.0.0:1080",
	// }
	srv := socks5.New(nil)

	go func() {
		// Default address: 127.0.0.1:1080
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

See the [tests](socks5_test.go) for more information about package.

## FAQ

* Why can't connect to socks proxy server?

    Not all applications and browsers support socks authentication or socks protocol. You may need [extension](https://github.com/txthinking/socks5-configurator) for Chrome or another browser.

If you have any questions, you can ask in [GitHub Discussions](https://github.com/JC5LZiy3HVfV5ux/socks5/discussions/new?category=q-a).

## References

* [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.txt) SOCKS Protocol Version 5
* [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.txt) Username/Password Authentication for SOCKS V5

## Licenses

All source code is licensed under the [MIT License](LICENSE).

## Credits

Original gophers design by [@Egon Elbre](https://github.com/egonelbre/gophers).