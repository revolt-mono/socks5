package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
)

const maxDatagram = 65535

// udpAssociate relays datagrams for one client for as long as the control connection lives.
// Two sockets keep the roles apart: front binds the ip the control connection arrived on so the client sees replies from the advertised address, back binds the wildcard so egress follows the default route.
// The client is always the authenticated peer ip; the port comes from the request or, when the request left it zero, from the first datagram the peer sends.
// Only replies from destinations the client contacted are relayed back.
func (s *server) udpAssociate(ctx context.Context, sess *session, dst address) error {
	conn := sess.conn
	front, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrPort(conn.LocalAddr()).Addr(), 0)))
	if err != nil {
		return errors.Join(err, writeReply(conn, repGeneralFailure, netip.AddrPort{}))
	}
	defer front.Close()
	back, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return errors.Join(err, writeReply(conn, repGeneralFailure, netip.AddrPort{}))
	}
	defer back.Close()
	if err := writeReply(conn, repSucceeded, addrPort(front.LocalAddr())); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		_ = front.Close()
		_ = back.Close()
	}()

	r := &udpRelay{
		server:  s,
		peer:    addrPort(conn.RemoteAddr()).Addr(),
		targets: map[netip.AddrPort]struct{}{},
		names:   map[string]netip.Addr{},
	}
	if dst.port != 0 {
		r.client = netip.AddrPortFrom(r.peer, dst.port)
	}
	var wg sync.WaitGroup
	wg.Go(func() { sess.down = r.relayReplies(back, front) })
	sess.up, err = r.forward(ctx, front, back)
	_ = back.Close()
	wg.Wait()
	return err
}

type udpRelay struct {
	*server

	peer netip.Addr

	// mu guards what forward shares with relayReplies.
	mu      sync.Mutex
	client  netip.AddrPort
	targets map[netip.AddrPort]struct{}

	names map[string]netip.Addr // forward only; one lookup per domain for the whole association, failures included
}

func (r *udpRelay) forward(ctx context.Context, front, back *net.UDPConn) (int64, error) {
	var up int64
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := front.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return up, nil
		}
		if err != nil {
			return up, err
		}
		r.mu.Lock()
		if !r.client.IsValid() && from.Addr() == r.peer {
			r.client = from
		}
		fromClient := from == r.client
		r.mu.Unlock()
		if !fromClient {
			continue
		}
		dst, payload, err := parseDatagram(buf[:n])
		if err != nil {
			continue
		}
		to, ok := r.destination(ctx, dst)
		if !ok {
			continue
		}
		r.mu.Lock()
		r.targets[to] = struct{}{}
		r.mu.Unlock()
		if _, err := back.WriteToUDPAddrPort(payload, to); err == nil {
			up += int64(len(payload))
		}
	}
}

func (r *udpRelay) relayReplies(back, front *net.UDPConn) (down int64) {
	buf := make([]byte, maxDatagram)
	var out []byte
	for {
		n, from, err := back.ReadFromUDPAddrPort(buf)
		if err != nil {
			return down
		}
		r.mu.Lock()
		_, contacted := r.targets[from]
		client := r.client
		r.mu.Unlock()
		if !contacted {
			continue
		}
		out = appendDatagram(out[:0], from, buf[:n])
		if _, err := front.WriteToUDPAddrPort(out, client); err == nil {
			down += int64(n)
		}
	}
}

func (r *udpRelay) destination(ctx context.Context, a address) (netip.AddrPort, bool) {
	if a.domain == "" {
		return netip.AddrPortFrom(a.ip, a.port), r.allowed(a.ip)
	}
	ip, ok := r.names[a.domain]
	if !ok {
		ip = r.resolve(ctx, a.domain)
		r.names[a.domain] = ip
	}
	return netip.AddrPortFrom(ip, a.port), ip.IsValid()
}
