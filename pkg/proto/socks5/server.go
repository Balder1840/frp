package socks5

import (
	"fmt"
	"net"

	"github.com/fatedier/frp/pkg/util/xlog"
	libio "github.com/fatedier/golib/io"
	"github.com/fatedier/golib/pool"
	"github.com/go-gost/gosocks5"
)

// Config is the client configuration
type Config struct {
	Username string
	Password string

	Verify func(string, string) bool
}

// Server holds contexts of the server
type Server struct {
	cfg *Config
	xl  *xlog.Logger
}

func NewServer(cfg *Config, xlogger *xlog.Logger) *Server {
	s := &Server{cfg: cfg,
		xl: xlogger,
	}

	if cfg.Username != "" && cfg.Password != "" {
		s.cfg.Verify = verifyByMap(map[string]string{cfg.Username: cfg.Password})
	}
	return s
}

func (s *Server) ServeConn(conn net.Conn) {
	s.socksHandler(conn)
}

func (s *Server) socksHandler(conn net.Conn) {
	defer conn.Close()

	// select method
	methods, err := gosocks5.ReadMethods(conn)
	if err != nil {
		s.xl.Errorf(`[socks5] read methods failed: %s`, err)
		if err := gosocks5.WriteMethod(gosocks5.MethodNoAcceptable, conn); err != nil {
			s.xl.Errorf(`[socks5] write methods failed: %s`, err)
		}
		return
	}

	method := s.chooseMethod(methods)
	if err := gosocks5.WriteMethod(method, conn); err != nil || method == gosocks5.MethodNoAcceptable {
		if err != nil {
			s.xl.Errorf(`[socks5] write method failed: %s`, err)
		} else {
			s.xl.Warnf(`[socks5] methods is not acceptable`)
		}
		return
	}

	if err := method2Handler[method](s, conn); err != nil {
		s.xl.Errorf(`[socks5] authorization failed: %s`, err)
		return
	}

	// read command
	request, err := gosocks5.ReadRequest(conn)
	if err != nil {
		s.xl.Errorf(`[socks5] read command failed: %s`, err)
		return
	}
	switch request.Cmd {
	case gosocks5.CmdConnect:
		s.handleConnect(conn, request)
	case gosocks5.CmdBind:
		s.handleBind(conn)
	case gosocks5.CmdUdp:
		// unsupported, since the server based on TCP. using CmdUDPOverTCP instead.
		s.xl.Warnf(`[socks5] unsupported command CmdUDP`)
		if err := gosocks5.NewReply(gosocks5.CmdUnsupported, nil).Write(conn); err != nil {
			s.xl.Errorf(`[socks5] write reply failed: %s`, err)
		}
		return
	case CmdUDPOverTCP:
		s.handleUDPOverTCP(conn)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *gosocks5.Request) {
	s.xl.Tracef(`[socks5] "connect" connect %s for %s`, req.Addr, conn.RemoteAddr())
	newConn, err := net.Dial("tcp", req.Addr.String())
	if err != nil {
		s.xl.Errorf(`[socks5] "connect" dial remote failed: %s`, err)
		if err := gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(conn); err != nil {
			s.xl.Errorf(`[socks5] "connect" write reply failed: %s`, err)
		}
		return
	}
	defer newConn.Close()

	if err := gosocks5.NewReply(gosocks5.Succeeded, nil).Write(conn); err != nil {
		s.xl.Errorf(`[socks5] "connect" write reply failed: %s`, err)
		return
	}

	s.xl.Tracef(`[socks5] "connect" tunnel established %s <-> %s`, conn.RemoteAddr(), req.Addr)
	if _, _, errs := libio.Join(conn, newConn); len(errs) > 0 {
		s.xl.Debugf(`[socks5] "connect" transport failed: %s`, errs)
	}
	s.xl.Tracef(`[socks5] "connect" tunnel disconnected %s >-< %s`, conn.RemoteAddr(), req.Addr)
}

func (s *Server) handleBind(conn net.Conn) {
	s.xl.Tracef(`[socks5] "bind" bind for %s`, conn.RemoteAddr())
	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		s.xl.Errorf(`[socks5] "bind" bind failed on listen: %s`, err)
		if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(conn); err != nil {
			s.xl.Errorf(`[socks5] "bind" write reply failed %s`, err)
		}
		return
	}

	// first response: send listen address
	addr, _ := newAddrFromAddr(listener.Addr(), conn.LocalAddr())
	if err := gosocks5.NewReply(gosocks5.Succeeded, addr).Write(conn); err != nil {
		listener.Close()
		s.xl.Errorf(`[socks5] "bind" write reply failed %s`, err)
		return
	}

	newConn, err := listener.AcceptTCP()
	listener.Close()
	if err != nil {
		s.xl.Errorf(`[socks5] "bind" bind failed on accept: %s`, err)
		if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(conn); err != nil {
			s.xl.Errorf(`[socks5] "bind" write reply failed %s`, err)
		}
		return
	}
	defer newConn.Close()

	// second response: accepted address
	raddr, _ := gosocks5.NewAddr(newConn.RemoteAddr().String())
	if err := gosocks5.NewReply(gosocks5.Succeeded, raddr).Write(conn); err != nil {
		s.xl.Errorf(`[socks5] "bind" write reply failed %s`, err)
		return
	}

	s.xl.Tracef(`[socks5] "bind" tunnel established %s <-> %s`, conn.RemoteAddr(), newConn.RemoteAddr())
	if _, _, errs := libio.Join(conn, newConn); len(errs) > 0 {
		s.xl.Debugf(`[socks5] "bind" transport failed: %s`, errs)
	}
	s.xl.Tracef(`[socks5] "bind" tunnel disconnected %s >-< %s`, conn.RemoteAddr(), newConn.RemoteAddr())
}

func (s *Server) handleUDPOverTCP(conn net.Conn) {
	s.xl.Tracef(`[socks5] "udp-over-tcp" associate UDP for %s`, conn.RemoteAddr())
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		s.xl.Errorf(`[socks5] "udp-over-tcp" UDP associate failed on listen: %s`, err)
		if err := gosocks5.NewReply(gosocks5.Failure, nil).Write(conn); err != nil {
			s.xl.Errorf(`[socks5] "udp-over-tcp" write reply failed %s`, err)
		}
		return
	}
	defer udp.Close()

	addr, _ := newAddrFromAddr(udp.LocalAddr(), conn.LocalAddr())
	if err := gosocks5.NewReply(gosocks5.Succeeded, addr).Write(conn); err != nil {
		s.xl.Errorf(`[socks5] "udp-over-tcp" write reply failed %s`, err)
		return
	}

	s.xl.Tracef(`[socks5] "udp-over-tcp" tunnel established %s <-> (UDP)%s`, conn.RemoteAddr(), udp.LocalAddr())
	if err := tunnelUDP(conn, udp); err != nil {
		s.xl.Debugf(`[socks5] "udp-over-tcp" tunnel UDP failed: %s`, err)
	}
	s.xl.Tracef(`[socks5] "udp-over-tcp" tunnel disconnected %s >-< (UDP)%s`, conn.RemoteAddr(), udp.LocalAddr())
}

func tunnelUDP(conn net.Conn, udp net.PacketConn) error {
	errc := make(chan error, 2)

	go func() {
		b := pool.GetBuf(576)
		defer pool.PutBuf(b)

		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}

			saddr, _ := gosocks5.NewAddr(addr.String())
			dgram := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, saddr), b[:n])
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

			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue
			}
			if _, err := udp.WriteTo(dgram.Data, addr); err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
}

func (s *Server) chooseMethod(methods []uint8) uint8 {
	supportNoAuth := false
	supportUserPass := false

	for _, m := range methods {
		switch m {
		case gosocks5.MethodNoAuth:
			supportNoAuth = s.cfg.Verify == nil
		case gosocks5.MethodUserPass:
			supportUserPass = s.cfg.Verify != nil
		}
	}

	if supportUserPass {
		return gosocks5.MethodUserPass
	} else if supportNoAuth {
		return gosocks5.MethodNoAuth
	}
	return gosocks5.MethodNoAcceptable
}

var method2Handler = map[uint8]func(*Server, net.Conn) error{
	gosocks5.MethodNoAuth:   (*Server).authNoAuth,
	gosocks5.MethodUserPass: (*Server).authUserPass,
}

func (s *Server) authNoAuth(conn net.Conn) (err error) {
	return nil
}

func (s *Server) authUserPass(conn net.Conn) (err error) {
	req, err := gosocks5.ReadUserPassRequest(conn)
	if err != nil {
		return
	}

	if !s.cfg.Verify(req.Username, req.Password) {
		if e := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, 1).Write(conn); e != nil {
			s.xl.Errorf(`[socks5] write reply failed: %s`, e)
		}
		return fmt.Errorf(`verify user %s failed`, req.Username)
	}

	return gosocks5.NewUserPassResponse(gosocks5.UserPassVer, 0).Write(conn)
}
