package socks5_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/revolt-mono/socks5/internal/socks5"
)

const (
	user = "alice"
	pass = "s3cret"
)

func plain() socks5.Config {
	return socks5.Config{Username: user, Password: pass}
}

func allowAll() socks5.Config {
	return socks5.Config{Username: user, Password: pass, AllowPrivate: true}
}

// serve runs Serve on ln for the test lifetime and checks that it returns cleanly after cancellation.
func serve(t *testing.T, ln net.Listener, cfg socks5.Config) {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	done := make(chan error, 1)
	go func() { done <- socks5.Serve(t.Context(), ln, cfg) }()
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not return after cancel")
		}
	})
}

func start(t *testing.T, cfg socks5.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, ln, cfg)
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func exchange(t *testing.T, conn net.Conn, send []byte, n int) []byte {
	t.Helper()
	if _, err := conn.Write(send); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

func authenticate(t *testing.T, conn net.Conn, u, p string) byte {
	t.Helper()
	if got := exchange(t, conn, []byte{5, 1, 2}, 2); !bytes.Equal(got, []byte{5, 2}) {
		t.Fatalf("method selection = %v", got)
	}
	msg := append([]byte{1, byte(len(u))}, u...)
	msg = append(msg, byte(len(p)))
	msg = append(msg, p...)
	return exchange(t, conn, msg, 2)[1]
}

func connected(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn := dial(t, addr)
	if status := authenticate(t, conn, user, pass); status != 0 {
		t.Fatalf("auth status = %d", status)
	}
	return conn
}

func ipv4Target(ap netip.AddrPort) []byte {
	v4 := ap.Addr().As4()
	return binary.BigEndian.AppendUint16(append([]byte{1}, v4[:]...), ap.Port())
}

func ipv6Target(ap netip.AddrPort) []byte {
	v6 := ap.Addr().As16()
	return binary.BigEndian.AppendUint16(append([]byte{4}, v6[:]...), ap.Port())
}

func domainTarget(host string, port uint16) []byte {
	b := append([]byte{3, byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(b, port)
}

// request sends cmd for target and returns the reply code and bound address.
func request(t *testing.T, conn net.Conn, cmd byte, target []byte) (byte, netip.AddrPort) {
	t.Helper()
	reply := exchange(t, conn, append([]byte{5, cmd, 0}, target...), 10)
	if reply[0] != 5 || reply[3] != 1 {
		t.Fatalf("reply header = %v, want version 5 and an ipv4 bound address", reply[:4])
	}
	return reply[1], netip.AddrPortFrom(netip.AddrFrom4([4]byte(reply[4:8])), binary.BigEndian.Uint16(reply[8:]))
}

// associate opens a udp association announcing 0.0.0.0:0 and returns the relay address.
func associate(t *testing.T, conn net.Conn) netip.AddrPort {
	t.Helper()
	rep, relay := request(t, conn, 3, ipv4Target(netip.MustParseAddrPort("0.0.0.0:0")))
	if rep != 0 {
		t.Fatalf("udp associate reply = %d", rep)
	}
	return relay
}

func tcpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// udpServer answers every datagram on ip with reply(payload, from), skipping the test when ip cannot be bound.
func udpServer(t *testing.T, ip netip.Addr, reply func([]byte, netip.AddrPort) []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Skipf("cannot listen on %v: %v", ip, err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDPAddrPort(reply(buf[:n], from), from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	return udpServer(t, netip.MustParseAddr("127.0.0.1"), func(p []byte, _ netip.AddrPort) []byte { return p })
}

func udpClient(t *testing.T) *net.UDPConn {
	t.Helper()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client
}

// datagram wraps payload in a socks5 udp header for target.
func datagram(target []byte, payload string) []byte {
	return append(append([]byte{0, 0, 0}, target...), payload...)
}

func send(t *testing.T, client *net.UDPConn, out []byte, relay netip.AddrPort) {
	t.Helper()
	if _, err := client.WriteToUDPAddrPort(out, relay); err != nil {
		t.Fatal(err)
	}
}

// receive returns the payload and source of the next datagram the relay delivers for target.
func receive(t *testing.T, client *net.UDPConn, target netip.AddrPort) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 65535)
	n, from, err := client.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("no reply via relay for %v: %v", target, err)
	}
	header := datagram(ipv4Target(target), "")
	if !bytes.HasPrefix(buf[:n], header) {
		t.Fatalf("reply = %v, want header %v", buf[:n], header)
	}
	return buf[len(header):n], from
}

func expectNoReply(t *testing.T, client *net.UDPConn) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := client.ReadFromUDPAddrPort(make([]byte, 65535)); err == nil {
		t.Fatalf("relay answered %d bytes", n)
	}
}

// lanIPv4 returns a non-loopback ipv4 address of this host, or skips.
func lanIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			return p.Addr()
		}
	}
	t.Skip("no non-loopback ipv4 interface")
	return netip.Addr{}
}

// flakyListener fails the first accept so Serve must keep going.
type flakyListener struct {
	net.Listener
	failed bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed {
		l.failed = true
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

// logLines captures slog output one write per line.
type logLines chan string

func (l logLines) Write(p []byte) (int, error) {
	l <- string(p)
	return len(p), nil
}

func TestServeRequiresCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := socks5.Serve(t.Context(), ln, socks5.Config{Username: "u"}); err == nil {
		t.Fatal("serve accepted empty password")
	}
	long := socks5.Config{Username: strings.Repeat("u", 256), Password: "p"}
	if err := socks5.Serve(t.Context(), ln, long); err == nil {
		t.Fatal("serve accepted a username longer than the wire format allows")
	}
}

func TestServeSurvivesAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(t, &flakyListener{Listener: ln}, allowAll())
	conn := connected(t, ln.Addr().String())
	if rep, _ := request(t, conn, 1, ipv4Target(tcpEcho(t))); rep != 0 {
		t.Fatalf("reply = %d", rep)
	}
}

func TestConnectEcho(t *testing.T) {
	addr := start(t, allowAll())
	echo := tcpEcho(t)
	conn := connected(t, addr)
	if rep, _ := request(t, conn, 1, ipv4Target(echo)); rep != 0 {
		t.Fatalf("reply = %d", rep)
	}
	if got := exchange(t, conn, []byte("hello"), 5); string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
	// half-close: remaining data still flows back, then eof propagates.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(conn); err != nil || len(rest) != 0 {
		t.Fatalf("after half-close: %q, %v", rest, err)
	}
}

// a client reset must end the session even when the upstream stays idle and never closes.
func TestConnectResetClosesSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lines := make(logLines, 64)
	cfg := allowAll()
	cfg.Logger = slog.New(slog.NewTextHandler(lines, nil))
	serve(t, ln, cfg)

	idle, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	go func() {
		c, err := idle.Accept()
		if err != nil {
			return
		}
		<-t.Context().Done()
		c.Close()
	}()

	conn := connected(t, ln.Addr().String())
	if rep, _ := request(t, conn, 1, ipv4Target(netip.MustParseAddrPort(idle.Addr().String()))); rep != 0 {
		t.Fatalf("reply = %d", rep)
	}
	if err := conn.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case line := <-lines:
			if strings.Contains(line, "cmd=connect") {
				return
			}
		case <-deadline:
			t.Fatal("session did not end after client reset")
		}
	}
}

func TestConnectDomain(t *testing.T) {
	addr := start(t, allowAll())
	echo := tcpEcho(t)
	conn := connected(t, addr)
	if rep, _ := request(t, conn, 1, domainTarget("localhost", echo.Port())); rep != 0 {
		t.Fatalf("reply = %d", rep)
	}
	if got := exchange(t, conn, []byte("ping"), 4); string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestConnectRefused(t *testing.T) {
	addr := start(t, allowAll())
	// a freshly closed listener leaves a port nobody listens on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	conn := connected(t, addr)
	if rep, _ := request(t, conn, 1, ipv4Target(closed)); rep != 5 {
		t.Fatalf("reply = %d, want 5 (connection refused)", rep)
	}
}

func TestPrivateDestinationDenied(t *testing.T) {
	addr := start(t, plain())
	echo := tcpEcho(t)
	conn := connected(t, addr)
	if rep, _ := request(t, conn, 1, ipv4Target(echo)); rep != 2 {
		t.Fatalf("reply = %d, want 2 (not allowed)", rep)
	}
	conn = connected(t, addr)
	if rep, _ := request(t, conn, 1, domainTarget("localhost", echo.Port())); rep != 2 {
		t.Fatalf("domain reply = %d, want 2 (not allowed)", rep)
	}
}

func TestBindRejected(t *testing.T) {
	addr := start(t, allowAll())
	conn := connected(t, addr)
	if rep, _ := request(t, conn, 2, ipv4Target(netip.MustParseAddrPort("1.1.1.1:80"))); rep != 7 {
		t.Fatalf("reply = %d, want 7 (command not supported)", rep)
	}
}

func TestBadPassword(t *testing.T) {
	addr := start(t, allowAll())
	conn := dial(t, addr)
	if status := authenticate(t, conn, user, "wrong"); status == 0 {
		t.Fatal("wrong password accepted")
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection stayed open after auth failure: %v", err)
	}
}

func TestNoAuthRejected(t *testing.T) {
	addr := start(t, allowAll())
	conn := dial(t, addr)
	if got := exchange(t, conn, []byte{5, 1, 0}, 2); !bytes.Equal(got, []byte{5, 0xFF}) {
		t.Fatalf("method selection = %v", got)
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection stayed open: %v", err)
	}
}

func TestUDPAssociate(t *testing.T) {
	addr := start(t, allowAll())
	echo := udpEcho(t)
	conn := connected(t, addr)
	client := udpClient(t)
	relay := associate(t, conn)
	if relay.Addr() != netip.MustParseAddr("127.0.0.1") || relay.Port() == 0 {
		t.Fatalf("relay address = %v", relay)
	}

	out := datagram(ipv4Target(echo), "dgram")
	send(t, client, out, relay)
	payload, from := receive(t, client, echo)
	if from != relay {
		t.Fatalf("reply came from %v, want %v", from, relay)
	}
	if string(payload) != "dgram" {
		t.Fatalf("payload = %q", payload)
	}

	// closing the control connection tears the relay down; the write itself may already fail on a closed port.
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	_, _ = client.WriteToUDPAddrPort(out, relay)
	expectNoReply(t, client)
}

// the relay only talks to the authenticated peer: the ip in the client hint is ignored in favour of the peer ip,
// and datagrams from sources the client never contacted are dropped instead of being forwarded to the client.
func TestUDPOnlyRelaysBetweenPeerAndContactedTargets(t *testing.T) {
	addr := start(t, allowAll())
	echo := udpEcho(t)
	conn := connected(t, addr)
	client := udpClient(t)
	clientPort := netip.MustParseAddrPort(client.LocalAddr().String()).Port()
	hint := netip.AddrPortFrom(netip.MustParseAddr("10.1.2.3"), clientPort)
	rep, relay := request(t, conn, 3, ipv4Target(hint))
	if rep != 0 {
		t.Fatalf("reply = %d", rep)
	}

	send(t, udpClient(t), []byte("injected"), relay)
	expectNoReply(t, client)

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	send(t, client, datagram(ipv4Target(echo), "real"), relay)
	if payload, _ := receive(t, client, echo); string(payload) != "real" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestUDPPrivateDestinationDenied(t *testing.T) {
	addr := start(t, plain())
	echo := udpEcho(t)
	conn := connected(t, addr)
	client := udpClient(t)
	send(t, client, datagram(ipv4Target(echo), "x"), associate(t, conn))
	expectNoReply(t, client)
}

// egress must follow the default route even when the client reached the proxy through loopback: the target sees the host's lan ip.
func TestUDPEgressFollowsDefaultRoute(t *testing.T) {
	addr := start(t, allowAll())
	lan := lanIPv4(t)
	echo := udpServer(t, lan, func(_ []byte, from netip.AddrPort) []byte { return []byte(from.String()) })
	conn := connected(t, addr)
	client := udpClient(t)
	send(t, client, datagram(ipv4Target(echo), "x"), associate(t, conn))
	seen, _ := receive(t, client, echo)
	if src := netip.MustParseAddrPort(string(seen)); src.Addr().Unmap() != lan {
		t.Fatalf("target saw egress from %v, want %v", src, lan)
	}
}

// replies must come from the advertised relay address even when the route back to the client would pick another local ip.
func TestUDPReplySourceMatchesAdvertisedAddress(t *testing.T) {
	lan := lanIPv4(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(lan.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on %v: %v", lan, err)
	}
	serve(t, ln, allowAll())

	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	conn, err := dialer.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot reach %v from loopback: %v", ln.Addr(), err)
	}
	t.Cleanup(func() { conn.Close() })
	if status := authenticate(t, conn, user, pass); status != 0 {
		t.Fatalf("auth status = %d", status)
	}
	echo := udpEcho(t)
	client := udpClient(t)
	relay := associate(t, conn)
	if relay.Addr() != lan {
		t.Fatalf("relay advertised %v, want %v", relay, lan)
	}
	send(t, client, datagram(ipv4Target(echo), "x"), relay)
	if _, from := receive(t, client, echo); from != relay {
		t.Fatalf("reply came from %v, want advertised %v", from, relay)
	}
}

func TestUDPMappedIPv4Target(t *testing.T) {
	addr := start(t, allowAll())
	echo := udpEcho(t)
	conn := connected(t, addr)
	client := udpClient(t)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(echo.Addr().As16()), echo.Port())
	send(t, client, datagram(ipv6Target(mapped), "m"), associate(t, conn))
	if payload, _ := receive(t, client, echo); string(payload) != "m" {
		t.Fatalf("payload = %q", payload)
	}
}

// egress is ipv4 only: ipv6 literals are refused, names resolve to a records only, and udp datagrams for ipv6 targets are dropped.
func TestEgressIPv4Only(t *testing.T) {
	addr := start(t, allowAll())
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no ipv6 loopback: %v", err)
	}
	defer ln6.Close()
	go func() {
		for {
			c, err := ln6.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	echo6 := netip.MustParseAddrPort(ln6.Addr().String())

	conn := connected(t, addr)
	if rep, _ := request(t, conn, 1, ipv6Target(echo6)); rep != 8 {
		t.Fatalf("ipv6 literal reply = %d, want 8 (address type not supported)", rep)
	}
	// localhost resolves to ::1 as well, but only 127.0.0.1 may be dialed and nothing listens there.
	conn = connected(t, addr)
	if rep, _ := request(t, conn, 1, domainTarget("localhost", echo6.Port())); rep != 5 {
		t.Fatalf("localhost reply = %d, want 5 (connection refused)", rep)
	}

	udp6 := udpServer(t, netip.IPv6Loopback(), func(p []byte, _ netip.AddrPort) []byte { return p })
	conn = connected(t, addr)
	client := udpClient(t)
	send(t, client, datagram(ipv6Target(udp6), "x"), associate(t, conn))
	expectNoReply(t, client)
}

func TestCancelClosesSessions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := allowAll()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- socks5.Serve(ctx, ln, cfg) }()

	conn := connected(t, ln.Addr().String())
	if rep, _ := request(t, conn, 1, ipv4Target(tcpEcho(t))); rep != 0 {
		t.Fatalf("reply = %d", rep)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return while a session was active")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("session survived cancellation")
	}
}
