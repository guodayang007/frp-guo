// Copyright 2023 The frp Authors
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
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/xlog"
	"io"
	"net"
	"reflect"
	"time"

	fmux "github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/transport"
	utilnet "github.com/fatedier/frp/pkg/util/net"
)

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.XTCPProxyConfig{}), NewXTCPProxy)
}

type XTCPProxy struct {
	*BaseProxy

	cfg *v1.XTCPProxyConfig
}

func NewXTCPProxy(baseProxy *BaseProxy, cfg v1.ProxyConfigurer) Proxy {
	unwrapped, ok := cfg.(*v1.XTCPProxyConfig)
	if !ok {
		return nil
	}
	return &XTCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}
func (pxy *XTCPProxy) sendMessage(conn net.Conn, message *msg.P2pMessage) error {
	err := msg.WriteMsg(conn, message)
	if err != nil {
		pxy.xl.Error("[proxy] Failed to send message: %v", err)
	}
	return err
}

// InWorkConn 处理入站连接
func (pxy *XTCPProxy) InWorkConn(conn net.Conn, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	defer conn.Close()
	var natHoleSidMsg msg.NatHoleSid //这里就是读数据
	err := msg.ReadMsgInto(conn, &natHoleSidMsg)
	if err != nil {
		xl.Error("【proxy】xtcp read from workConn error: %v", err)
		return
	}
	xl.Info("【proxy】xtcp read from workConn success conn = %v: %+v", conn.RemoteAddr(), natHoleSidMsg)
	go pxy.listenForMessages(conn)
	xl.Warn("【proxy】nathole prepare start password: %s", natHoleSidMsg.Password)
	prepareResult, err := nathole.Prepare([]string{pxy.clientCfg.NatHoleSTUNServer})
	if err != nil {
		xl.Warn("【proxy】 nathole prepare error 1: %v", err)
		return
	}
	//这里做逻辑 TODO
	//看看怎么接数据。

	//这里就可以做 验证签名 就看怎么得到数据

	//现在先 随便发 123 看我能不能接  如果我能接 那么我这里可以改成 接受签名数据。？ 解析签名者  是否是我run这个程序配置的钱包  就能决定他们是否能连接。

	xl.Info("【proxy】 nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)
	defer prepareResult.ListenConn.Close()

	// send NatHoleClient msg to server
	transactionID := nathole.NewTransactionID()
	natHoleClientMsg := &msg.NatHoleClient{
		TransactionID: transactionID,
		ProxyName:     pxy.cfg.Name,
		Sid:           natHoleSidMsg.Sid,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	xl.Trace("【proxy】nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(pxy.ctx, pxy.msgTransporter, transactionID, natHoleClientMsg, 5*time.Second)
	if err != nil {
		xl.Warn("【proxy】nathole exchange info error: %v", err)
		return
	}
	if natHoleRespMsg.Password == "" {
		natHoleRespMsg.Password = "client fangfang InWorkConn"
	}
	xl.Info("【proxy】nathole exchange info start fangfang的密码 [%s] ", natHoleRespMsg.Password)

	xl.Info("【proxy】 get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	listenConn := prepareResult.ListenConn
	newListenConn, raddr, err := nathole.MakeHole(pxy.ctx, listenConn, natHoleRespMsg, []byte(pxy.cfg.Secretkey))
	if err != nil {
		listenConn.Close()
		xl.Warn("make hole error 2: %v", err)
		_ = pxy.msgTransporter.Send(&msg.NatHoleReport{
			Sid:     natHoleRespMsg.Sid,
			Success: false,
			Content: "client InWorkConn false fang",
		})
		return
	}
	listenConn = newListenConn
	xl.Info("【proxy】establishing nat hole connection successful------, sid [%s], remoteAddr [%s]", natHoleRespMsg.Sid, raddr)
	xl.Warn("【proxy】 make hole  2:")
	err = pxy.msgTransporter.Send(&msg.NatHoleReport{
		Sid:     natHoleRespMsg.Sid,
		Success: true,
		Content: "client InWorkConn true fang",
	})
	if err != nil {
		xl.Warn("【proxy】send NatHoleReport error: %v", err)
	}
	if natHoleRespMsg.Protocol == "kcp" {
		pxy.listenByKCP(listenConn, raddr, startWorkConnMsg)
		return
	}

	// default is quic
	pxy.listenByQUIC(listenConn, raddr, startWorkConnMsg)

	xl.Info("[proxy] raddr=%v ,startWorkConnMsg=%v", raddr, startWorkConnMsg)

	// 创建消息
	message := &msg.P2pMessage{
		Text:    "Hello, Frp P2P!",
		Content: "client proxy fang",
	}
	// 发送消息
	if err := pxy.sendMessage(conn, message); err != nil {
		xl.Error("【proxy】xtcp send message error: %v", err)
		return
	}

	xl.Info("【proxy】xtcp send message success")
}
func (pxy *XTCPProxy) listenForMessages(conn net.Conn) {
	xl := xlog.FromContextSafe(pxy.ctx)

	var (
		rawMsg msg.Message
		err    error
	)
	if rawMsg, err = msg.ReadMsg(conn); err != nil {
		log.Trace("Failed to read message: %v", err)
		conn.Close()
		return
	}
	switch m := rawMsg.(type) {
	case *msg.NatHoleSid:
		xl.Info("[proxy client ] NatHoleSid - [%s] -[%+v]", conn.RemoteAddr(), m)

	case *msg.P2pMessage:
		// 处理登录逻辑，你需要添加XTCP Proxy的登录逻辑

		xl.Info("[proxy client ] P2pMessage - [%s] -[%+v]", conn.RemoteAddr(), m)

	case *msg.P2pMessageProxy:

		xl.Info("[proxy  client ] P2pMessageProxy -  [%s] -[%+v]", conn.RemoteAddr(), m)

	case *msg.P2pMessageVisitor:

		xl.Info("[proxy client ] P2pMessageVisitor -  [%s] -[%+v]", conn.RemoteAddr(), m)
	default:
		log.Warn("Error message type for the new connection [%s] [%+v]", conn.RemoteAddr().String(), m)
		//conn.Close()
	}

}
func (pxy *XTCPProxy) listenByKCP(listenConn *net.UDPConn, raddr *net.UDPAddr, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	listenConn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
	lConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		xl.Warn("dial udp error: %v", err)
		return
	}
	defer lConn.Close()

	remote, err := utilnet.NewKCPConnFromUDP(lConn, true, raddr.String())
	if err != nil {
		xl.Warn("create kcp connection from udp connection error: %v", err)
		return
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = 10 * time.Second
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	fmuxCfg.LogOutput = io.Discard
	session, err := fmux.Server(remote, fmuxCfg)
	if err != nil {
		xl.Error("create mux session error: %v", err)
		return
	}
	defer session.Close()

	for {
		muxConn, err := session.Accept()
		if err != nil {
			xl.Error("accept connection error: %v", err)
			return
		}
		go pxy.HandleTCPWorkConnection(muxConn, startWorkConnMsg, []byte(pxy.cfg.Secretkey))

	}
}

func (pxy *XTCPProxy) listenByQUIC(listenConn *net.UDPConn, _ *net.UDPAddr, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	defer listenConn.Close()

	tlsConfig, err := transport.NewServerTLSConfig("", "", "")
	if err != nil {
		xl.Warn("create tls config error: %v", err)
		return
	}
	tlsConfig.NextProtos = []string{"frp"}
	quicListener, err := quic.Listen(listenConn, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(pxy.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(pxy.clientCfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(pxy.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		},
	)
	if err != nil {
		xl.Warn("dial quic error: %v", err)
		return
	}
	// only accept one connection from raddr
	c, err := quicListener.Accept(pxy.ctx)
	if err != nil {
		xl.Error("quic accept connection error: %v", err)
		return
	}
	for {
		stream, err := c.AcceptStream(pxy.ctx)
		if err != nil {
			xl.Debug("quic accept stream error: %v", err)
			_ = c.CloseWithError(0, "")
			return
		}
		go pxy.HandleTCPWorkConnection(utilnet.QuicStreamToNetConn(stream, c), startWorkConnMsg, []byte(pxy.cfg.Secretkey))
	}
}
