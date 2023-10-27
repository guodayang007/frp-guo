// Copyright 2017 fatedier, fatedier@gmail.com
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

package visitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	libio "github.com/fatedier/golib/io"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/transport"
	utilnet "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/xlog"
)

var ErrNoTunnelSession = errors.New("no tunnel session")

type XTCPVisitor struct {
	*BaseVisitor
	session       TunnelSession
	startTunnelCh chan struct{}
	retryLimiter  *rate.Limiter
	cancel        context.CancelFunc

	cfg *v1.XTCPVisitorConfig
}

func (sv *XTCPVisitor) Run() (err error) {
	sv.ctx, sv.cancel = context.WithCancel(sv.ctx)

	if sv.cfg.Protocol == "kcp" {
		sv.session = NewKCPTunnelSession()
	} else {
		sv.session = NewQUICTunnelSession(sv.clientCfg)
	}

	if sv.cfg.BindPort > 0 {
		sv.l, err = net.Listen("tcp", net.JoinHostPort(sv.cfg.BindAddr, strconv.Itoa(sv.cfg.BindPort)))
		if err != nil {
			return
		}
		go sv.worker()
	}

	go sv.internalConnWorker()
	go sv.processTunnelStartEvents()
	if sv.cfg.KeepTunnelOpen {
		sv.retryLimiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(sv.cfg.MaxRetriesAnHour)), sv.cfg.MaxRetriesAnHour)
		go sv.keepTunnelOpenWorker()
	}
	return
}

func (sv *XTCPVisitor) Close() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.BaseVisitor.Close()
	if sv.cancel != nil {
		sv.cancel()
	}
	if sv.session != nil {
		sv.session.Close()
	}
}

func (sv *XTCPVisitor) worker() {
	xl := xlog.FromContextSafe(sv.ctx)
	for {
		conn, err := sv.l.Accept()
		if err != nil {
			xl.Warn("xtcp local listener closed")
			return
		}
		go sv.handleConn(conn)
	}
}

func (sv *XTCPVisitor) internalConnWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	for {
		conn, err := sv.internalLn.Accept()
		if err != nil {
			xl.Warn("xtcp internal listener closed")
			return
		}
		go sv.handleConn(conn)
	}
}

func (sv *XTCPVisitor) processTunnelStartEvents() {
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-sv.startTunnelCh:
			start := time.Now()
			sv.makeNatHole()
			duration := time.Since(start)
			// avoid too frequently
			if duration < 10*time.Second {
				time.Sleep(10*time.Second - duration)
			}
		}
	}
}

func (sv *XTCPVisitor) keepTunnelOpenWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(time.Duration(sv.cfg.MinRetryInterval) * time.Second)
	defer ticker.Stop()

	sv.startTunnelCh <- struct{}{}
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-ticker.C:
			xl.Debug("keepTunnelOpenWorker try to check tunnel...")
			conn, err := sv.getTunnelConn()
			if err != nil {
				xl.Warn("keepTunnelOpenWorker get tunnel connection error: %v", err)
				_ = sv.retryLimiter.Wait(sv.ctx)
				continue
			}
			xl.Debug("keepTunnelOpenWorker check success")
			if conn != nil {
				conn.Close()
			}
		}
	}
}

// 在这里处理已建立的连接上的数据传输逻辑
// 例如，读取数据，解析消息，处理请求，发送响应等
func (sv *XTCPVisitor) handleConn(userConn net.Conn) {
	xl := xlog.FromContextSafe(sv.ctx)
	isConnTrasfered := false
	defer func() {
		if !isConnTrasfered {
			userConn.Close()
		}
	}()

	xl.Debug("get a new xtcp user connection")

	// Open a tunnel connection to the server. If there is already a successful hole-punching connection,
	// it will be reused. Otherwise, it will block and wait for a successful hole-punching connection until timeout.
	ctx := context.Background()
	if sv.cfg.FallbackTo != "" {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(sv.cfg.FallbackTimeoutMs)*time.Millisecond)
		defer cancel()
		ctx = timeoutCtx
	}
	tunnelConn, err := sv.openTunnel(ctx)
	if err != nil {
		xl.Error("open tunnel error: %v", err)
		// no fallback, just return
		if sv.cfg.FallbackTo == "" {
			return
		}

		xl.Debug("try to transfer connection to visitor: %s", sv.cfg.FallbackTo)
		if err := sv.helper.TransferConn(sv.cfg.FallbackTo, userConn); err != nil {
			xl.Error("transfer connection to visitor %s error: %v", sv.cfg.FallbackTo, err)
			return
		}
		isConnTrasfered = true
		return
	}

	var muxConnRWCloser io.ReadWriteCloser = tunnelConn
	if sv.cfg.Transport.UseEncryption {
		muxConnRWCloser, err = libio.WithEncryption(muxConnRWCloser, []byte(sv.cfg.SecretKey))
		if err != nil {
			xl.Error("create encryption stream error: %v", err)
			return
		}
	}
	if sv.cfg.Transport.UseCompression {
		var recycleFn func()
		muxConnRWCloser, recycleFn = libio.WithCompressionFromPool(muxConnRWCloser)
		defer recycleFn()
	}

	_, _, errs := libio.Join(userConn, muxConnRWCloser)
	xl.Debug("join connections closed")
	if len(errs) > 0 {
		xl.Trace("join connections errors: %v", errs)
	}
	messageCh := make(chan []byte)
	defer close(messageCh)
	// Goroutine to read data from userConn and send it to the tunnel connection
	go func() {
		buffer := make([]byte, 8192) // Adjust the buffer size as needed
		for {
			n, err := userConn.Read(buffer)
			if err != nil {
				xl.Debug("User connection closed: %v", err)
				return
			}
			message := P2pMessage{
				Text:    string(buffer[:n]),
				Content: "Additional Content", // Modify or set your content as needed
			}
			messageJSON, err := json.Marshal(message)
			if err != nil {
				xl.Error("Failed to marshal message: %v", err)
				return
			}
			messageCh <- messageJSON                  // Send the JSON-encoded message to the channel
			_, _ = muxConnRWCloser.Write(messageJSON) // Write data to the tunnel connection
		}
	}()

	// Goroutine to read data from the tunnel connection and send it to userConn
	go func() {
		buffer := make([]byte, 8192) // Adjust the buffer size as needed
		for {
			n, err := muxConnRWCloser.Read(buffer)
			if err != nil {
				xl.Debug("Tunnel connection closed: %v", err)
				return
			}
			var receivedMessage P2pMessage
			if err := json.Unmarshal(buffer[:n], &receivedMessage); err != nil {
				xl.Error("[visitor] Failed to unmarshal received data: %v", err)
				return
			}
			xl.Debug("Received message: %s, Content: %s", receivedMessage.Text, receivedMessage.Content)
			_, _ = userConn.Write(buffer[:n]) // Write data to the user connection
		}
	}()

}

type Message struct {
	Content string `json:"content,omitempty"`
	Sid     string `json:"sid,omitempty"`
}

// P2pMessage 代表要传输的消息
type P2pMessage struct {
	Text    string
	Content string `json:"content,omitempty"`
}

// openTunnel will open a tunnel connection to the target server. openTunnel 将打开与目标服务器的隧道连接。
func (sv *XTCPVisitor) openTunnel(ctx context.Context) (conn net.Conn, err error) {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeoutC := time.After(20 * time.Second)
	immediateTrigger := make(chan struct{}, 1)
	defer close(immediateTrigger)
	immediateTrigger <- struct{}{}

	for {
		select {
		case <-sv.ctx.Done():
			return nil, sv.ctx.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-immediateTrigger:
			conn, err = sv.getTunnelConn()
		case <-ticker.C:
			conn, err = sv.getTunnelConn()
		case <-timeoutC:
			return nil, fmt.Errorf("open tunnel timeout")
		}

		if err != nil {
			if err != ErrNoTunnelSession {
				xl.Warn("get tunnel connection error: %v", err)
			}
			continue
		}
		return conn, nil
	}
}

func (sv *XTCPVisitor) getTunnelConn() (net.Conn, error) {
	conn, err := sv.session.OpenConn(sv.ctx)
	if err == nil {
		return conn, nil
	}
	sv.session.Close()

	select {
	case sv.startTunnelCh <- struct{}{}:
	default:
	}
	return nil, err
}

// 0. PreCheck
// 1. Prepare
// 2. ExchangeInfo
// 3. MakeNATHole
// 4. Create a tunnel session using an underlying UDP connection.
func (sv *XTCPVisitor) makeNatHole() {
	xl := xlog.FromContextSafe(sv.ctx)
	xl.Trace("[visitor] makeNatHole start")
	if err := nathole.PreCheck(sv.ctx, sv.helper.MsgTransporter(), sv.cfg.ServerName, 5*time.Second); err != nil {
		xl.Warn("[visitor] nathole precheck error: %v", err)
		return
	}

	xl.Trace("[visitor] nathole prepare start")
	prepareResult, err := nathole.Prepare([]string{sv.clientCfg.NatHoleSTUNServer})
	if err != nil {
		xl.Warn("[visitor] nathole prepare error 2: %v", err)
		return
	}
	xl.Info("[visitor] nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)

	listenConn := prepareResult.ListenConn

	// send NatHoleVisitor to server
	now := time.Now().Unix()
	transactionID := nathole.NewTransactionID()
	natHoleVisitorMsg := &msg.NatHoleVisitor{
		TransactionID: transactionID,
		ProxyName:     sv.cfg.ServerName,
		Protocol:      sv.cfg.Protocol,
		SignKey:       util.GetAuthKey(sv.cfg.SecretKey, now),
		Timestamp:     now,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	xl.Trace("[visitor] nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(sv.ctx, sv.helper.MsgTransporter(), transactionID, natHoleVisitorMsg, 5*time.Second)
	if err != nil {
		listenConn.Close()
		xl.Warn("nathole exchange info error: %v", err)
		return
	}

	xl.Info("[visitor]  get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	natHoleRespMsg.Password = "123321"
	newListenConn, raddr, err := nathole.MakeHole(sv.ctx, listenConn, natHoleRespMsg, []byte(sv.cfg.SecretKey))
	if err != nil {
		listenConn.Close()
		xl.Warn("[visitor] make hole error 1: %v", err)
		return
	}
	listenConn = newListenConn
	xl.Info("[visitor] establishing nat hole connection successful, sid [%s], remoteAddr [%s]", natHoleRespMsg.Sid, raddr)

	if err := sv.session.Init(listenConn, raddr); err != nil {
		listenConn.Close()
		xl.Warn("[visitor] init tunnel session error: %v", err)
		return
	}
	// 打洞连接成功后，可以开始监听
	go sv.handleIncomingMessages(listenConn) // 假设有一个名为 handleIncomingMessages 的函数用于监听消息

	// 创建消息
	message := &P2pMessage{
		Text:    "Hello, Frp P2P!",
		Content: "client visitor fang",
	}

	// 发送消息
	if err := SendMessage(listenConn, raddr, message); err != nil {
		xl.Error("Failed to send message: %v", err)
	}

}
func (sv *XTCPVisitor) handleIncomingMessages(conn *net.UDPConn) {
	xl := xlog.FromContextSafe(sv.ctx)
	buffer := make([]byte, 1024)
	var receivedData []byte

	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			xl.Error("Failed to read data: %v", err)
			return
		}

		// 将接收到的数据追加到已接收数据
		receivedData = append(receivedData, buffer[:n]...)

		// 检查是否有完整消息
		for {
			// 查找消息分隔符，例如换行符
			if idx := bytes.Index(receivedData, []byte{'\n'}); idx >= 0 {
				// 提取一条完整的消息
				messageData := receivedData[:idx]
				receivedData = receivedData[idx+1:]

				var receivedMessage P2pMessage
				if err := json.Unmarshal(messageData, &receivedMessage); err != nil {
					xl.Error("[visitor] Failed to unmarshal received data: %v", err)
				} else {
					xl.Info("Received message: %s", receivedMessage.Text)
					// 处理接收到的消息，例如打印或执行其他操作
				}
			} else {
				// 没有更多完整的消息，退出循环
				break
			}
		}
	}
}

// SendMessage 用于向对端发送消息
func SendMessage(conn *net.UDPConn, addr *net.UDPAddr, msg *P2pMessage) error {
	encodedMsg, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = conn.WriteToUDP(encodedMsg, addr)
	return err
}

// receiveMessage 用于从对端接收消息
func receiveMessage(conn io.ReadWriteCloser) (*P2pMessage, error) {
	dec := json.NewDecoder(conn)
	var msg P2pMessage
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

type TunnelSession interface {
	Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error
	OpenConn(context.Context) (net.Conn, error)
	Close()
}

type KCPTunnelSession struct {
	session *fmux.Session
	lConn   *net.UDPConn
	mu      sync.RWMutex
}

func NewKCPTunnelSession() TunnelSession {
	return &KCPTunnelSession{}
}

func (ks *KCPTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	listenConn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
	lConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return fmt.Errorf("dial udp error: %v", err)
	}
	remote, err := utilnet.NewKCPConnFromUDP(lConn, true, raddr.String())
	if err != nil {
		return fmt.Errorf("create kcp connection from udp connection error: %v", err)
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = 10 * time.Second
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	fmuxCfg.LogOutput = io.Discard
	session, err := fmux.Client(remote, fmuxCfg)
	if err != nil {
		remote.Close()
		return fmt.Errorf("initial client session error: %v", err)
	}
	ks.mu.Lock()
	ks.session = session
	ks.lConn = lConn
	ks.mu.Unlock()
	return nil
}

func (ks *KCPTunnelSession) OpenConn(_ context.Context) (net.Conn, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	session := ks.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	return session.Open()
}

func (ks *KCPTunnelSession) Close() {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.session != nil {
		_ = ks.session.Close()
		ks.session = nil
	}
	if ks.lConn != nil {
		_ = ks.lConn.Close()
		ks.lConn = nil
	}
}

type QUICTunnelSession struct {
	session    quic.Connection
	listenConn *net.UDPConn
	mu         sync.RWMutex

	clientCfg *v1.ClientCommonConfig
}

func NewQUICTunnelSession(clientCfg *v1.ClientCommonConfig) TunnelSession {
	return &QUICTunnelSession{
		clientCfg: clientCfg,
	}
}

func (qs *QUICTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	tlsConfig, err := transport.NewClientTLSConfig("", "", "", raddr.String())
	if err != nil {
		return fmt.Errorf("create tls config error: %v", err)
	}
	tlsConfig.NextProtos = []string{"frp"}
	quicConn, err := quic.Dial(context.Background(), listenConn, raddr, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(qs.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(qs.clientCfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(qs.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		})
	if err != nil {
		return fmt.Errorf("dial quic error: %v", err)
	}
	qs.mu.Lock()
	qs.session = quicConn
	qs.listenConn = listenConn
	qs.mu.Unlock()
	return nil
}

func (qs *QUICTunnelSession) OpenConn(ctx context.Context) (net.Conn, error) {
	qs.mu.RLock()
	defer qs.mu.RUnlock()
	session := qs.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return utilnet.QuicStreamToNetConn(stream, session), nil
}

func (qs *QUICTunnelSession) Close() {
	qs.mu.Lock()
	defer qs.mu.Unlock()
	if qs.session != nil {
		_ = qs.session.CloseWithError(0, "")
		qs.session = nil
	}
	if qs.listenConn != nil {
		_ = qs.listenConn.Close()
		qs.listenConn = nil
	}
}
