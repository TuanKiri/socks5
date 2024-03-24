package socks5

import "io"

type closeWriter interface {
	CloseWrite() error
}

func relay(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)

	if writer, ok := dst.(closeWriter); ok {
		writer.CloseWrite()
	}

	return err
}
