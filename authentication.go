package socks5

import "context"

func (s *Server) choiceAuthenticationMethod(methods []byte) byte {
	for _, method := range methods {
		if _, ok := s.config.authMethods[method]; ok {
			return method
		}
	}

	return noAcceptableMethods
}

func (s *Server) usernamePasswordAuthenticate(ctx context.Context, conn connection) {
	version, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read authentication version: "+err.Error())
		return
	}

	if version != usernamePasswordVersion {
		return
	}

	usernameLen, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read username length: "+err.Error())
		return
	}

	username := make([]byte, usernameLen)
	if _, err := conn.Read(username); err != nil {
		s.logger.Error(ctx, "failed to read username: "+err.Error())
		return
	}

	ctx = contextWithUsername(ctx, string(username))

	passwordLen, err := conn.ReadByte()
	if err != nil {
		s.logger.Error(ctx, "failed to read password length: "+err.Error())
		return
	}

	password := make([]byte, passwordLen)
	if _, err := conn.Read(password); err != nil {
		s.logger.Error(ctx, "failed to read password: "+err.Error())
		return
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, s.config.getPasswordTimeout)
	defer cancel()

	passwordFromStore, err := s.store.GetPassword(ctxTimeout, string(username))
	if err != nil {
		s.logger.Error(ctx, "failed to get user password from store: "+err.Error())
		return
	}

	if string(password) != passwordFromStore {
		s.logger.Warn(ctx, "failed to authenticate user ["+string(username)+"]")

		s.response(ctx, conn, usernamePasswordVersion, usernamePasswordFailure)
		return
	}

	s.response(ctx, conn, usernamePasswordVersion, usernamePasswordSuccess)

	s.acceptRequest(ctx, conn)
}
