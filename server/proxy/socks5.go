// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/proto/socks5"
	"github.com/fatedier/frp/pkg/util/limit"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/metrics"
	libio "github.com/fatedier/golib/io"
)

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.Socks5ProxyConfig{}), NewSocks5Proxy)
}

type Socks5Proxy struct {
	*BaseProxy
	cfg *v1.Socks5ProxyConfig

	realBindPort int
}

func NewSocks5Proxy(baseProxy *BaseProxy) Proxy {
	unwrapped, ok := baseProxy.GetConfigurer().(*v1.Socks5ProxyConfig)
	if !ok {
		return nil
	}
	baseProxy.usedPortsNum = 1
	return &Socks5Proxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *Socks5Proxy) Run() (remoteAddr string, err error) {
	xl := pxy.xl
	if pxy.cfg.LoadBalancer.Group != "" {
		l, realBindPort, errRet := pxy.rc.TCPGroupCtl.Listen(pxy.name, pxy.cfg.LoadBalancer.Group, pxy.cfg.LoadBalancer.GroupKey,
			pxy.serverCfg.ProxyBindAddr, pxy.cfg.RemotePort)
		if errRet != nil {
			err = errRet
			return
		}
		defer func() {
			if err != nil {
				l.Close()
			}
		}()
		pxy.realBindPort = realBindPort
		pxy.listeners = append(pxy.listeners, l)
		xl.Infof("tcp proxy listen port [%d] in group [%s]", pxy.cfg.RemotePort, pxy.cfg.LoadBalancer.Group)
	} else {
		pxy.realBindPort, err = pxy.rc.TCPPortManager.Acquire(pxy.name, pxy.cfg.RemotePort)
		if err != nil {
			return
		}
		defer func() {
			if err != nil {
				pxy.rc.TCPPortManager.Release(pxy.realBindPort)
			}
		}()
		listener, errRet := net.Listen("tcp", net.JoinHostPort(pxy.serverCfg.ProxyBindAddr, strconv.Itoa(pxy.realBindPort)))
		if errRet != nil {
			err = errRet
			return
		}
		pxy.listeners = append(pxy.listeners, listener)
		xl.Infof("tcp proxy listen port [%d]", pxy.cfg.RemotePort)
	}

	pxy.cfg.RemotePort = pxy.realBindPort
	remoteAddr = fmt.Sprintf(":%d", pxy.realBindPort)
	pxy.startHandleListeners()
	return
}

func (pxy *Socks5Proxy) startHandleListeners() {
	xl := xlog.FromContextSafe(pxy.ctx)
	for _, listener := range pxy.listeners {
		go func(l net.Listener) {
			var tempDelay time.Duration // how long to sleep on accept failure

			for {
				// block
				// if listener is closed, err returned
				c, err := l.Accept()
				if err != nil {
					if err, ok := err.(interface{ Temporary() bool }); ok && err.Temporary() {
						if tempDelay == 0 {
							tempDelay = 5 * time.Millisecond
						} else {
							tempDelay *= 2
						}
						if max := 1 * time.Second; tempDelay > max {
							tempDelay = max
						}
						xl.Infof("met temporary error: %s, sleep for %s ...", err, tempDelay)
						time.Sleep(tempDelay)
						continue
					}

					xl.Warnf("listener is closed: %s", err)
					return
				}
				xl.Infof("get a user connection [%s]", c.RemoteAddr().String())
				go pxy.handleUserSocketConnection(c)
			}
		}(listener)
	}
}

func (pxy *Socks5Proxy) handleUserSocketConnection(userConn net.Conn) {
	xl := xlog.FromContextSafe(pxy.Context())
	defer userConn.Close()

	serverCfg := pxy.serverCfg
	cfg := pxy.configurer.GetBaseConfig()
	// server plugin hook
	rc := pxy.GetResourceController()
	content := &plugin.NewUserConnContent{
		User:       pxy.GetUserInfo(),
		ProxyName:  pxy.GetName(),
		ProxyType:  cfg.Type,
		RemoteAddr: userConn.RemoteAddr().String(),
	}
	_, err := rc.PluginManager.NewUserConn(content)
	if err != nil {
		xl.Warnf("the user conn [%s] was rejected, err:%v", content.RemoteAddr, err)
		return
	}

	// try all connections from the pool
	workConn, err := pxy.GetWorkConnFromPool(userConn.RemoteAddr(), userConn.LocalAddr())
	if err != nil {
		return
	}
	defer workConn.Close()

	var local io.ReadWriteCloser = workConn
	xl.Tracef("handler user tcp connection, use_encryption: %t, use_compression: %t",
		cfg.Transport.UseEncryption, cfg.Transport.UseCompression)
	if cfg.Transport.UseEncryption {
		local, err = libio.WithEncryption(local, []byte(serverCfg.Auth.Token))
		if err != nil {
			xl.Errorf("create encryption stream error: %v", err)
			return
		}
	}
	if cfg.Transport.UseCompression {
		var recycleFn func()
		local, recycleFn = libio.WithCompressionFromPool(local)
		defer recycleFn()
	}

	if pxy.GetLimiter() != nil {
		local = libio.WrapReadWriteCloser(limit.NewReader(local, pxy.GetLimiter()), limit.NewWriter(local, pxy.GetLimiter()), func() error {
			return local.Close()
		})
	}

	xl.Debugf("join connections, workConn(l[%s] r[%s]) userConn(l[%s] r[%s])", workConn.LocalAddr().String(),
		workConn.RemoteAddr().String(), userConn.LocalAddr().String(), userConn.RemoteAddr().String())

	workConn = netpkg.WrapReadWriteCloserToConn(local, workConn)
	workConn = netpkg.WrapStatsConn(workConn, pxy.updateStatsAfterClosedConn)
	metrics.Server.OpenConnection(pxy.GetName(), pxy.GetConfigurer().GetBaseConfig().Type)
	socksClient := socks5.NewClient(pxy.xl)
	socksClient.ServeConn(userConn, workConn)
}

func (pxy *Socks5Proxy) updateStatsAfterClosedConn(totalRead, totalWrite int64) {
	name := pxy.GetName()
	proxyType := pxy.GetConfigurer().GetBaseConfig().Type
	metrics.Server.CloseConnection(name, proxyType)
	metrics.Server.AddTrafficIn(name, proxyType, totalWrite)
	metrics.Server.AddTrafficOut(name, proxyType, totalRead)
}

func (pxy *Socks5Proxy) Close() {
	pxy.BaseProxy.Close()
	if pxy.cfg.LoadBalancer.Group == "" {
		pxy.rc.TCPPortManager.Release(pxy.realBindPort)
	}
}
