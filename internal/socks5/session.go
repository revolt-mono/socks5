package socks5

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"
)

var (
	errNoAuthMethod   = errors.New("client offered no username/password auth")
	errBadCredentials = errors.New("bad credentials")
	errCommand        = errors.New("command not supported")
)

type session struct {
	conn   net.Conn
	cmd    string
	target string
	up     int64
	down   int64
}

func (s *server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	start := time.Now()
	sess := &session{conn: conn}
	err := s.run(ctx, sess)

	attrs := []any{
		"client", conn.RemoteAddr().String(),
		"cmd", sess.cmd,
		"target", sess.target,
		"up", sess.up,
		"down", sess.down,
		"duration", time.Since(start).Round(time.Millisecond),
	}
	if err != nil {
		s.cfg.Logger.Warn("session", append(attrs, "error", err.Error())...)
		return
	}
	s.cfg.Logger.Info("session", attrs...)
}

func (s *server) run(ctx context.Context, sess *session) error {
	conn := sess.conn
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	if err := s.authenticate(conn); err != nil {
		return err
	}
	cmd, dst, err := readRequest(conn)
	if errors.Is(err, errAddrType) {
		return errors.Join(err, writeReply(conn, repAddrTypeNotSupported, address{}))
	}
	if err != nil {
		return err
	}
	// the handshake is done; dialing and relaying get their own timeouts.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	switch cmd {
	case cmdConnect:
		sess.cmd = "connect"
		sess.target = dst.String()
		return s.connect(ctx, sess, dst)
	case cmdUDPAssociate:
		sess.cmd = "udp"
		return s.udpAssociate(ctx, sess, dst)
	}
	sess.cmd = fmt.Sprintf("0x%02x", cmd)
	return errors.Join(errCommand, writeReply(conn, repCommandNotSupported, address{}))
}

func (s *server) authenticate(conn net.Conn) error {
	methods, err := readMethods(conn)
	if err != nil {
		return err
	}
	if !slices.Contains(methods, byte(methodUserPass)) {
		_, err := conn.Write([]byte{version, methodNoAcceptable})
		return errors.Join(errNoAuthMethod, err)
	}
	if _, err := conn.Write([]byte{version, methodUserPass}); err != nil {
		return err
	}
	user, pass, err := readUserPass(conn)
	if err != nil {
		return err
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.Username))
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.Password))
	if userOK&passOK != 1 {
		_, err := conn.Write([]byte{userPassVersion, 0x01})
		return errors.Join(errBadCredentials, err)
	}
	_, err = conn.Write([]byte{userPassVersion, 0x00})
	return err
}
