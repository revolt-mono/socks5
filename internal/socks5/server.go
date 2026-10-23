// Package socks5 serves a password-protected socks5 proxy that supports the
// connect and udp associate commands and dials destinations directly over ipv4.
package socks5

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	handshakeTimeout = 10 * time.Second
	maxCredentialLen = 255 // rfc 1929 wire limit
)

type Config struct {
	Username string
	Password string
	// AllowPrivate permits private, loopback, and link-local destinations.
	AllowPrivate bool
	Logger       *slog.Logger
}

type server struct {
	cfg    Config
	dialer net.Dialer
}

// Serve accepts socks5 clients on ln until ctx is cancelled, then closes the listener and every active session before returning.
// Transient accept errors are retried with backoff; Serve returns early only if ln is closed by the caller.
// Each session is logged once when it ends.
// ln must be an ipv4 listener: udp relays are ipv4 sockets advertised on the address the control connection arrived on.
func Serve(ctx context.Context, ln net.Listener, cfg Config) error {
	if cfg.Username == "" || cfg.Password == "" {
		return errors.New("socks5: username and password are required")
	}
	if len(cfg.Username) > maxCredentialLen || len(cfg.Password) > maxCredentialLen {
		return errors.New("socks5: username and password must be at most 255 bytes")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &server{cfg: cfg}
	s.dialer = net.Dialer{Timeout: handshakeTimeout, ControlContext: s.control}
	cfg.Logger.Info("listening", "addr", ln.Addr().String(), "allow_private", cfg.AllowPrivate)

	defer context.AfterFunc(ctx, func() { ln.Close() })()
	var wg sync.WaitGroup
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			if ctx.Err() == nil {
				return err
			}
			wg.Wait()
			return nil
		}
		if err != nil {
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			cfg.Logger.Warn("accept", "error", err.Error(), "retry_in", delay)
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		wg.Go(func() { s.handle(ctx, conn) })
	}
}
