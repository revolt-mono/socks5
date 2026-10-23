package socks5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

var errNotAllowed = errors.New("destination not allowed by ruleset")

// allowed reports whether traffic may be sent to ip: without AllowPrivate only global unicast addresses outside rfc1918 pass.
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

// resolve turns a udp destination into a permitted ipv4 ip:port.
func (s *server) resolve(ctx context.Context, a address) (netip.AddrPort, error) {
	ips := []netip.Addr{a.ip}
	if a.domain != "" {
		var err error
		if ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", a.domain); err != nil {
			return netip.AddrPort{}, err
		}
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); s.allowed(ip) {
			return netip.AddrPortFrom(ip, a.port), nil
		}
	}
	return netip.AddrPort{}, errNotAllowed
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
