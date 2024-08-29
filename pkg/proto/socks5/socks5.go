package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/fatedier/golib/pool"
	"github.com/go-gost/gosocks5"
)

const (
	CmdUDPOverTCP = iota + 4
)

// NewAddrFromAddr creates an address object
func newAddrFromAddr(ln, conn net.Addr) (addr *gosocks5.Addr, err error) {
	_, sport, err := net.SplitHostPort(ln.String())
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(conn.String())
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}

	addr = newAddrFromPair(host, port)
	return
}

// NewAddrFromPair creates an address object from host and port pair
func newAddrFromPair(host string, port int) (addr *gosocks5.Addr) {
	addr = &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(port),
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addr.Type = gosocks5.AddrIPv4
		} else {
			addr.Type = gosocks5.AddrIPv6
		}
	}

	return
}

func readUDPDatagram(r io.Reader) (*gosocks5.UDPDatagram, error) {
	b := pool.GetBuf(64*1024 + 262)
	defer pool.PutBuf(b)

	// when r is a streaming (such as TCP connection), we may read more than the required data,
	// but we don't know how to handle it. So we use io.ReadFull to instead of io.ReadAtLeast
	// to make sure that no redundant data will be discarded.
	n, err := io.ReadFull(r, b[:5])
	if err != nil {
		return nil, err
	}

	header := &gosocks5.UDPHeader{
		Rsv:  binary.BigEndian.Uint16(b[:2]),
		Frag: b[2],
	}

	atype := b[3]
	hlen := 0
	switch atype {
	case gosocks5.AddrIPv4:
		hlen = 10
	case gosocks5.AddrIPv6:
		hlen = 22
	case gosocks5.AddrDomain:
		hlen = 7 + int(b[4])
	default:
		return nil, gosocks5.ErrBadAddrType
	}

	dlen := int(header.Rsv)
	if dlen == 0 { // standard SOCKS5 UDP datagram
		extra, err := io.ReadAll(r) // we assume no redundant data
		if err != nil {
			return nil, err
		}
		copy(b[n:], extra)
		n += len(extra) // total length
		dlen = n - hlen // data length
	} else { // extended feature, for UDP over TCP, using reserved field as data length
		if _, err := io.ReadFull(r, b[n:hlen+dlen]); err != nil {
			return nil, err
		}
		n = hlen + dlen
	}

	header.Addr = new(gosocks5.Addr)
	if err := header.Addr.Decode(b[3:hlen]); err != nil {
		return nil, err
	}

	data := make([]byte, dlen)
	copy(data, b[hlen:n])

	d := &gosocks5.UDPDatagram{
		Header: header,
		Data:   data,
	}

	return d, nil
}

// NegotiationRequest is the negotiation reqeust packet
//
// +-----+----------+---------------+
// | VER | NMETHODS |    METHODS    |
// +-----+----------+---------------+
// |  1  |     1    | X'00' - X'FF' |
// +-----+----------+---------------+
type NegotiationRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

// NewNegotiationRequest new negotiation request
func NewNegotiationRequest(medthods []byte) *NegotiationRequest {
	return &NegotiationRequest{
		gosocks5.Ver5,
		byte(len(medthods)),
		medthods,
	}
}

// ReadNegotiationRequest read negotiation requst packet
func ReadNegotiationRequest(r io.Reader) (*NegotiationRequest, error) {
	// memory strict
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != gosocks5.Ver5 {
		return nil, gosocks5.ErrBadVersion
	}
	if bb[1] == 0 {
		return nil, gosocks5.ErrBadMethod
	}
	ms := make([]byte, int(bb[1]))
	if _, err := io.ReadFull(r, ms); err != nil {
		return nil, err
	}

	return &NegotiationRequest{
		Ver:      bb[0],
		NMethods: bb[1],
		Methods:  ms,
	}, nil
}

// Write write negotiation reply packet
func (r *NegotiationRequest) Write(w io.Writer) error {
	b := make([]byte, 2+len(r.Methods))
	b[0] = gosocks5.Ver5
	b[1] = uint8(len(r.Methods))
	copy(b[2:], r.Methods)

	_, err := w.Write(b)
	return err
}

// NegotiationReply is the negotiation reply packet
//
//	+-----+--------+
//	| VER | METHOD |
//	+-----+--------+
//	|  1  |     1  |
//	+-----+--------+
type NegotiationReply struct {
	Ver    byte
	Method byte
}

// NewNegotiationReply return negotiation reply packet can be writed
func NewNegotiationReply(method byte) *NegotiationReply {
	return &NegotiationReply{
		Ver:    gosocks5.Ver5,
		Method: method,
	}
}

// ReadNegotiationReply read negotiation reply.
func ReadNegotiationReply(r io.Reader) (*NegotiationReply, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return &NegotiationReply{
		Ver:    b[0],
		Method: b[1],
	}, nil
}

// Write write negotiation reply packet
func (r *NegotiationReply) Write(w io.Writer) error {
	_, err := w.Write([]byte{r.Ver, r.Method})

	return err
}
