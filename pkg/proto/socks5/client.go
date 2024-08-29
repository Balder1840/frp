package socks5

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/fatedier/frp/pkg/util/xlog"
	libio "github.com/fatedier/golib/io"
	"github.com/fatedier/golib/pool"
	"github.com/go-gost/gosocks5"
)

// Client holds contexts of the client
type Client struct {
	xl *xlog.Logger
}

func NewClient(xlogger *xlog.Logger) *Client {
	c := &Client{
		xl: xlogger,
	}
	return c
}

func (c *Client) ServeConn(userConn net.Conn, workConn net.Conn) {
	// defer userConn.Close()

	// negotiate
	negotiateReply, err := c.negotiate(userConn, workConn)
	if err != nil {
		c.xl.Errorf(`[socks5] tunnel negotiate failed: %s`, err)
		return
	}

	// auth
	if negotiateReply.Method == gosocks5.MethodUserPass {
		if err := c.auth(userConn, workConn); err != nil {
			c.xl.Errorf(`[socks5] tunnel auth failed: %s`, err)
			return
		}
	}

	// read command
	request, err := gosocks5.ReadRequest(userConn)
	if err != nil {
		c.xl.Errorf(`[socks5] read command failed: %s`, err)
		return
	}
	switch request.Cmd {
	case gosocks5.CmdConnect:
		c.handleConnect(userConn, workConn, request)
	case gosocks5.CmdBind:
		c.handleBind(userConn, workConn, request)
	case gosocks5.CmdUdp:
		c.handleUDP(userConn, workConn)
	}
}

func (c *Client) handleConnect(userConn net.Conn, workConn net.Conn, req *gosocks5.Request) {
	var nextHop net.Conn
	var err error

	c.xl.Tracef(`[socks5] "connect" dial server to connect %s for %s`, req.Addr, userConn.RemoteAddr())
	nextHop = workConn
	// defer nextHop.Close()

	var dash rune
	if err = req.Write(nextHop); err != nil {
		c.xl.Errorf(`[socks5] "connect" send request failed: %s`, err)
		return
	}
	dash = '-'

	c.xl.Tracef(`[socks5] "connect" tunnel established %s <%c> %s`, userConn.RemoteAddr(), dash, req.Addr)
	if _, _, errs := libio.Join(userConn, nextHop); len(errs) > 0 {
		c.xl.Debugf(`[socks5] "connect" transport failed: %s`, errs)
	}
	c.xl.Tracef(`[socks5] "connect" tunnel disconnected %s >%c< %s`, userConn.RemoteAddr(), dash, req.Addr)
}

func (c *Client) handleBind(userConn net.Conn, workConn net.Conn, req *gosocks5.Request) {
	c.xl.Tracef(`[socks5] "bind" dial server to bind %s for %s`, req.Addr, userConn.RemoteAddr())

	ser := workConn
	defer ser.Close()
	if err := req.Write(ser); err != nil {
		c.xl.Errorf(`[socks5] "bind" send request failed: %s`, err)
		return
	}
	c.xl.Tracef(`[socks5] "bind" tunnel established %s <-> ?%s`, userConn.RemoteAddr(), req.Addr)
	if _, _, errs := libio.Join(userConn, ser); len(errs) > 0 {
		c.xl.Debugf(`[socks5] Transport failed: %s`, errs)
	}
	c.xl.Tracef(`[socks5] "bind" tunnel disconnected %s >-< ?%s`, userConn.RemoteAddr(), req.Addr)
}

func (c *Client) handleUDP(userConn net.Conn, workConn net.Conn) {
	c.xl.Tracef(`[socks5] "udp" associate UDP for %s`, userConn.RemoteAddr())
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		c.xl.Errorf(`[socks5] "udp" UDP associate failed on listen: %s`, err)
		if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(userConn); err != nil {
			c.xl.Errorf(`[socks5] "udp" write reply failed %s`, err)
		}
		return
	}
	defer udp.Close()

	ser, err := c.requestServer4UDP(workConn)
	if err != nil {
		c.xl.Errorf(`[socks5] "udp" UDP associate failed on request the server: %s`, err)
		if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(userConn); err != nil {
			c.xl.Errorf(`[socks5] "udp" Write reply failed %s`, err)
		}
		return
	}
	defer ser.Close()

	addr, _ := newAddrFromAddr(udp.LocalAddr(), userConn.LocalAddr())
	if err := gosocks5.NewReply(gosocks5.Succeeded, addr).Write(userConn); err != nil {
		c.xl.Errorf(`[socks5] "udp" write reply failed %s`, err)
		return
	}

	c.xl.Tracef(`[socks5] "udp" tunnel established (UDP)%s <-> %s`, udp.LocalAddr(), workConn.RemoteAddr().String())
	go c.tunnelUDP(udp, ser)
	if err := waiting4EOF(userConn); err != nil {
		c.xl.Errorf(`[socks5] "udp" waiting for EOF failed: %s`, err)
	}
	c.xl.Tracef(`[socks5] "udp" tunnel disconnected (UDP)%s >-< %s`, udp.LocalAddr(), workConn.RemoteAddr().String())
}

func (c *Client) requestServer4UDP(workConn net.Conn) (net.Conn, error) {
	ser := workConn

	if err := gosocks5.NewRequest(CmdUDPOverTCP, nil).Write(ser); err != nil {
		ser.Close()
		return nil, err
	}
	res, err := gosocks5.ReadReply(ser)
	if err != nil {
		ser.Close()
		return nil, err
	}
	if res.Rep != gosocks5.Succeeded {
		ser.Close()
		return nil, fmt.Errorf("request UDP over TCP associate failed: %q", res.Rep)
	}
	return ser, nil
}

func (c *Client) tunnelUDP(udp net.PacketConn, conn net.Conn) error {
	errc := make(chan error, 2)
	var clientAddr net.Addr

	go func() {
		b := pool.GetBuf(576)
		defer pool.PutBuf(b)

		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}

			dgram, err := readUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = addr
			}
			dgram.Header.Rsv = uint16(len(dgram.Data))
			if _, err := dgram.WriteTo(conn); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			dgram, err := readUDPDatagram(conn)
			if err != nil {
				errc <- err
				return
			}

			if clientAddr == nil {
				continue
			}
			dgram.Header.Rsv = 0
			buf := bytes.NewBuffer(nil)
			dgram.WriteTo(buf)
			if _, err := udp.WriteTo(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
}

func waiting4EOF(conn net.Conn) (err error) {
	b := pool.GetBuf(576)
	defer pool.PutBuf(b)
	for {
		_, err = conn.Read(b)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}
	return
}
