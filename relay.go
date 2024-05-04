package socks5

import "io"

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
