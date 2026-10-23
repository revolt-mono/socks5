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
	local := addressFrom(conn.LocalAddr())
	front, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.ip, 0)))
	if err != nil {
		return errors.Join(err, writeReply(conn, repGeneralFailure, address{}))
	}
	defer front.Close()
	back, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return errors.Join(err, writeReply(conn, repGeneralFailure, address{}))
	}
	defer back.Close()
	if err := writeReply(conn, repSucceeded, addressFrom(front.LocalAddr())); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		front.Close()
		back.Close()
	}()

	r := &udpRelay{
		server:  s,
		peer:    addressFrom(conn.RemoteAddr()).ip,
		targets: map[netip.AddrPort]struct{}{},
		names:   map[string]resolution{},
	}
	if dst.port != 0 {
		r.client = netip.AddrPortFrom(r.peer, dst.port)
	}
	var wg sync.WaitGroup
	wg.Go(func() { sess.down = r.relayReplies(back, front) })
	sess.up, err = r.forward(ctx, front, back)
	back.Close()
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

	names map[string]resolution // forward only; one lookup per domain for the whole association, failures included
}

type resolution struct {
	ip  netip.Addr
	err error
}

// forward unwraps client datagrams read from front and sends them out of back.
func (r *udpRelay) forward(ctx context.Context, front, back *net.UDPConn) (up int64, err error) {
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := front.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return up, nil
			}
			return up, err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		r.mu.Lock()
		if !r.client.IsValid() && from.Addr() == r.peer {
			r.client = from
		}
		fromClient := from == r.client
		r.mu.Unlock()
		if !fromClient {
			continue
		}
		target, payload, err := parseDatagram(buf[:n])
		if err != nil {
			continue
		}
		to, err := r.resolveCached(ctx, target)
		if err != nil {
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

// relayReplies wraps datagrams from contacted targets read from back and sends them to the client through front.
func (r *udpRelay) relayReplies(back, front *net.UDPConn) (down int64) {
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := back.ReadFromUDPAddrPort(buf)
		if err != nil {
			return down
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		r.mu.Lock()
		_, contacted := r.targets[from]
		client := r.client
		r.mu.Unlock()
		if !contacted {
			continue
		}
		out := appendDatagram(nil, address{ip: from.Addr(), port: from.Port()}, buf[:n])
		if _, err := front.WriteToUDPAddrPort(out, client); err == nil {
			down += int64(n)
		}
	}
}

func (r *udpRelay) resolveCached(ctx context.Context, a address) (netip.AddrPort, error) {
	if a.domain == "" {
		return r.resolve(ctx, a)
	}
	res, ok := r.names[a.domain]
	if !ok {
		to, err := r.resolve(ctx, a)
		res = resolution{ip: to.Addr(), err: err}
		r.names[a.domain] = res
	}
	if res.err != nil {
		return netip.AddrPort{}, res.err
	}
	return netip.AddrPortFrom(res.ip, a.port), nil
}
