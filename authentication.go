package socks5

import (
	"bufio"
	"context"
	"io"
)

func (s *Server) choiceAuthenticationMethod(methods []byte) byte {
	for _, method := range methods {
		if _, ok := s.config.authMethods[method]; ok {
			return method
		}
	}

	return noAcceptableMethods
}

func (s *Server) usernamePasswordAuthenticate(writer io.Writer, reader *bufio.Reader) {
	version, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read authentication version")
		return
	}

	if version != usernamePasswordVersion {
		return
	}

	usernameLen, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read username length")
		return
	}

	username := make([]byte, usernameLen)
	if _, err := reader.Read(username); err != nil {
		s.logger.LogErrorMessage(err, "failed to read username")
		return
	}

	passwordLen, err := reader.ReadByte()
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to read password length")
		return
	}

	password := make([]byte, passwordLen)
	if _, err := reader.Read(password); err != nil {
		s.logger.LogErrorMessage(err, "failed to read password")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.connDatabaseTimeout)
	defer cancel()

	passwordFromStore, err := s.store.GetPassword(ctx, string(username))
	if err != nil {
		s.logger.LogErrorMessage(err, "failed to get user password from store")
		return
	}

	if string(password) != passwordFromStore {
		s.response(writer, usernamePasswordVersion, usernamePasswordFailure)
		return
	}

	s.response(writer, usernamePasswordVersion, usernamePasswordSuccess)

	s.acceptRequest(writer, reader)
}
