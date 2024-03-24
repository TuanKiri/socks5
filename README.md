# Go SOCKS 5 proxy

[![license](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![go version](https://img.shields.io/github/go-mod/go-version/JC5LZiy3HVfV5ux/socks5)](go.mod)

Golang package for implementing a socks 5 proxy server.

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
	// Options allowed as nil. Example options: 
	// &socks5.Options{
	//     ListenAddr: 127.0.0.1:5000,
    // }
	srv := socks5.New(nil)

	// Default addr: 127.0.0.1:1080
	if err := srv.ListenAndServe(); err != nil {
	    log.Fatal(err)
	}
}
```

Run your server:

    go run main.go

The following curl example shows how to use the proxy server:

    curl -x socks5://127.0.0.1:1080 http://example.com

See the [tests](socks5_test.go) for more information about package.

## References

* [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.txt) SOCKS Protocol Version 5
* [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.txt) Username/Password Authentication for SOCKS V5

## Licenses

All source code is licensed under the [MIT License](LICENSE).