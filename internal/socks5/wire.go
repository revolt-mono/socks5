package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	version = 0x05

	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	userPassVersion = 0x01

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded            = 0x00
	repGeneralFailure       = 0x01
	repNotAllowed           = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

var (
	errVersion  = errors.New("unsupported socks version")
	errAddrType = errors.New("unsupported address type")
	errFragment = errors.New("udp fragmentation not supported")
)

// address is a socks5 destination: a domain name or an ipv4 address, plus a port.
type address struct {
	domain string
	ip     netip.Addr
	port   uint16
}

func (a address) String() string {
	if a.domain != "" {
		return net.JoinHostPort(a.domain, strconv.Itoa(int(a.port)))
	}
	return netip.AddrPortFrom(a.ip, a.port).String()
}

func addressFrom(addr net.Addr) address {
	ap, _ := netip.ParseAddrPort(addr.String())
	return address{ip: ap.Addr().Unmap(), port: ap.Port()}
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

// readPrefixed reads a one-byte length followed by that many bytes.
func readPrefixed(r io.Reader) ([]byte, error) {
	n, err := readByte(r)
	if err != nil {
		return nil, err
	}
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	return b, err
}

func readMethods(r io.Reader) ([]byte, error) {
	if ver, err := readByte(r); err != nil || ver != version {
		return nil, errors.Join(errVersion, err)
	}
	return readPrefixed(r)
}

func readUserPass(r io.Reader) (user, pass string, err error) {
	if ver, err := readByte(r); err != nil || ver != userPassVersion {
		return "", "", errors.Join(errVersion, err)
	}
	u, err := readPrefixed(r)
	if err != nil {
		return "", "", err
	}
	p, err := readPrefixed(r)
	return string(u), string(p), err
}

func readRequest(r io.Reader) (cmd byte, dst address, err error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, address{}, err
	}
	if head[0] != version {
		return 0, address{}, errVersion
	}
	dst, err = readAddress(r)
	return head[1], dst, err
}

// readAddress parses an address; ipv6 literals other than ipv4-mapped ones are rejected because egress is ipv4 only.
func readAddress(r io.Reader) (address, error) {
	atyp, err := readByte(r)
	if err != nil {
		return address{}, err
	}
	var a address
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return address{}, err
		}
		a.ip = netip.AddrFrom4(b)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return address{}, err
		}
		if a.ip = netip.AddrFrom16(b).Unmap(); !a.ip.Is4() {
			return address{}, errAddrType
		}
	case atypDomain:
		b, err := readPrefixed(r)
		if err != nil {
			return address{}, err
		}
		a.domain = string(b)
	default:
		return address{}, errAddrType
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return address{}, err
	}
	a.port = binary.BigEndian.Uint16(p[:])
	return a, nil
}

// appendAddress encodes an ipv4 address; the server only ever reports its own sockets or ipv4 reply sources.
func appendAddress(b []byte, a address) []byte {
	v4 := a.ip.As4()
	b = append(append(b, atypIPv4), v4[:]...)
	return binary.BigEndian.AppendUint16(b, a.port)
}

func writeReply(w io.Writer, rep byte, bound address) error {
	if !bound.ip.IsValid() {
		bound.ip = netip.IPv4Unspecified()
	}
	_, err := w.Write(appendAddress([]byte{version, rep, 0x00}, bound))
	return err
}

func parseDatagram(b []byte) (dst address, payload []byte, err error) {
	if len(b) < 3 {
		return address{}, nil, io.ErrUnexpectedEOF
	}
	if b[2] != 0 {
		return address{}, nil, errFragment
	}
	r := bytes.NewReader(b[3:])
	dst, err = readAddress(r)
	if err != nil {
		return address{}, nil, err
	}
	return dst, b[len(b)-r.Len():], nil
}

func appendDatagram(b []byte, src address, payload []byte) []byte {
	b = appendAddress(append(b, 0x00, 0x00, 0x00), src)
	return append(b, payload...)
}
