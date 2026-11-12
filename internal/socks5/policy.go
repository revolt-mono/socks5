package socks5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

var errNotAllowed = errors.New("destination not allowed by ruleset")

func (s *server) allowed(ip netip.Addr) bool {
	return s.cfg.AllowPrivate || (ip.IsGlobalUnicast() && !ip.IsPrivate())
}

// control enforces the destination rule on every tcp dial, after dns resolution.
func (s *server) control(_ context.Context, _, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if !s.allowed(ap.Addr()) {
		return errNotAllowed
	}
	return nil
}

// resolve returns the first permitted ipv4 address of host, or the zero Addr when the lookup fails or nothing is permitted.
func (s *server) resolve(ctx context.Context, host string) netip.Addr {
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	for _, ip := range ips {
		if ip = ip.Unmap(); s.allowed(ip) {
			return ip
		}
	}
	return netip.Addr{}
}

func replyCode(err error) byte {
	_, isDNS := errors.AsType[*net.DNSError](err)
	switch {
	case errors.Is(err, errNotAllowed):
		return repNotAllowed
	case isDNS, errors.Is(err, syscall.EHOSTUNREACH):
		return repHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetworkUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnectionRefused
	}
	return repGeneralFailure
}
