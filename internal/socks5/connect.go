package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

func (s *server) connect(ctx context.Context, sess *session, dst address) error {
	conn := sess.conn
	remote, err := s.dialer.DialContext(ctx, "tcp4", dst.String())
	if err != nil {
		return errors.Join(err, writeReply(conn, replyCode(err), address{}))
	}
	defer remote.Close()
	defer context.AfterFunc(ctx, func() { remote.Close() })()

	if err := writeReply(conn, repSucceeded, addressFrom(remote.LocalAddr())); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Go(func() { sess.up = pipe(conn, remote) })
	sess.down = pipe(remote, conn)
	wg.Wait()
	return nil
}

// pipe copies src to dst until eof or failure. A clean eof half-closes dst so its own data can still drain; a failure on either side closes both.
func pipe(src, dst net.Conn) int64 {
	n, err := io.Copy(dst, src)
	if err != nil {
		src.Close()
		dst.Close()
		return n
	}
	if hc, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	} else {
		dst.Close()
	}
	return n
}
