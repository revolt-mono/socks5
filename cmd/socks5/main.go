// Command socks5 runs the proxy configured from environment variables:
// SOCKS5_LISTEN (default 0.0.0.0:5000), SOCKS5_USERNAME, SOCKS5_PASSWORD,
// SOCKS5_ALLOW_PRIVATE (default false).
package main

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/revolt-mono/socks5/internal/socks5"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("exit", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	allowPrivate := false
	if v := os.Getenv("SOCKS5_ALLOW_PRIVATE"); v != "" {
		var err error
		if allowPrivate, err = strconv.ParseBool(v); err != nil {
			return err
		}
	}
	cfg := socks5.Config{
		Username:     os.Getenv("SOCKS5_USERNAME"),
		Password:     os.Getenv("SOCKS5_PASSWORD"),
		AllowPrivate: allowPrivate,
		Logger:       log,
	}

	ln, err := net.Listen("tcp4", cmp.Or(os.Getenv("SOCKS5_LISTEN"), "0.0.0.0:5000"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return socks5.Serve(ctx, ln, cfg)
}
