package proxy

import (
	"io"
	"net"
	"reflect"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/socks5"
	"github.com/fatedier/frp/pkg/util/limit"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	libio "github.com/fatedier/golib/io"
)

type Socks5Proxy struct {
	*BaseProxy

	cfg *v1.Socks5ProxyConfig
}

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.Socks5ProxyConfig{}), NewSocks5Proxy)
}

func NewSocks5Proxy(baseProxy *BaseProxy, cfg v1.ProxyConfigurer) Proxy {
	unwrapped, ok := cfg.(*v1.Socks5ProxyConfig)
	if !ok {
		return nil
	}
	return &Socks5Proxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *Socks5Proxy) InWorkConn(conn net.Conn, _ *msg.StartWorkConn) {
	xl := pxy.xl
	xl.Infof("incoming a new work connection for socks5 proxy, %s", conn.RemoteAddr().String())
	// close resources related with old workConn
	pxy.Close()

	var rwc io.ReadWriteCloser = conn
	var err error
	if pxy.limiter != nil {
		rwc = libio.WrapReadWriteCloser(limit.NewReader(conn, pxy.limiter), limit.NewWriter(conn, pxy.limiter), func() error {
			return conn.Close()
		})
	}
	if pxy.cfg.Transport.UseEncryption {
		rwc, err = libio.WithEncryption(rwc, []byte(pxy.clientCfg.Auth.Token))
		if err != nil {
			conn.Close()
			xl.Errorf("create encryption stream error: %v", err)
			return
		}
	}
	if pxy.cfg.Transport.UseCompression {
		rwc = libio.WithCompression(rwc)
	}
	conn = netpkg.WrapReadWriteCloserToConn(rwc, conn)

	socksCfg := &socks5.Config{
		Username: pxy.cfg.Username,
		Password: pxy.cfg.Password,
	}
	socksServer := socks5.NewServer(socksCfg, pxy.xl)
	socksServer.ServeConn(conn)
}
