// Copyright 2018 fatedier, fatedier@gmail.com
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

package msg

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/xlog"
	"io"
	"net"

	jsonMsg "github.com/fatedier/golib/msg/json"
)

type Message = jsonMsg.Message

var msgCtl *jsonMsg.MsgCtl

func init() {
	msgCtl = jsonMsg.NewMsgCtl()
	for typeByte, msg := range msgTypeMap {
		msgCtl.RegisterMsg(typeByte, msg)
	}
}

func ReadMsg(c io.Reader) (msg Message, err error) {
	return msgCtl.ReadMsg(c)
}

func ReadMsgInto(c io.Reader, msg Message) (err error) {
	return msgCtl.ReadMsgInto(c, msg)
}

func WriteMsg(c io.Writer, msg interface{}) (err error) {
	return msgCtl.WriteMsg(c, msg)
}

func Pack(msg interface{}) (data []byte, err error) {
	return msgCtl.Pack(msg)
}
func SendMessage(conn net.Conn, message Message) error {

	return WriteMsg(conn, message)
}

func SendUdpMessage(conn *net.UDPConn, raddr *net.UDPAddr, message Message) (int, error) {
	//err := msg.WriteMsg(conn, &message)
	marshal, err := json.Marshal(&message)
	if err != nil {
		return 0, err
	}
	n, err := conn.WriteToUDP(marshal, raddr)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func ListenForUdpMessages(ctx context.Context, conn *net.UDPConn) {
	xl := xlog.FromContextSafe(ctx)
	for {

		var (
			rawMsg Message
			err    error
		)
		var data [1024]byte
		n, addr, err := conn.ReadFromUDP(data[:]) // 接收数据
		if err != nil {
			fmt.Println("read udp failed, err:", err)
			xl.Error("[ListenForUdpMessages] read udp failed, err:", err)
		}
		fmt.Printf("[ListenForUdpMessages] data:%v addr:%v count:%v\n", string(data[:n]), addr, n)

		if rawMsg, err = ReadMsg(conn); err != nil {
			log.Trace("Failed to read message: %v", err)
			conn.Close()
			return
		}
		switch m := rawMsg.(type) {
		case *NatHoleSid:
			xl.Info("[proxy client ] NatHoleSid - [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessage:
			// 处理登录逻辑，你需要添加XTCP Proxy的登录逻辑

			xl.Info("[proxy client ] P2pMessage - [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessageProxy:

			xl.Info("[proxy  client ] P2pMessageProxy -  [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessageVisitor:

			xl.Info("[proxy client ] P2pMessageVisitor -  [%s] -[%+v]", conn.RemoteAddr(), m)
		default:
			log.Warn("Error message type for the new connection [%s] [%+v]", conn.RemoteAddr().String(), m)
			//conn.Close()
		}
	}

}

func ListenForMessages(ctx context.Context, conn net.Conn) {
	xl := xlog.FromContextSafe(ctx)

	for {
		var (
			rawMsg Message
			err    error
		)
		if rawMsg, err = ReadMsg(conn); err != nil {
			log.Trace("Failed to read message: %v", err)
			conn.Close()
			return
		}
		switch m := rawMsg.(type) {
		case *NatHoleSid:
			xl.Info("[proxy client ] NatHoleSid - [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessage:
			// 处理登录逻辑，你需要添加XTCP Proxy的登录逻辑

			xl.Info("[proxy client ] P2pMessage - [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessageProxy:

			xl.Info("[proxy  client ] P2pMessageProxy -  [%s] -[%+v]", conn.RemoteAddr(), m)

		case *P2pMessageVisitor:

			xl.Info("[proxy client ] P2pMessageVisitor -  [%s] -[%+v]", conn.RemoteAddr(), m)
		default:
			log.Warn("Error message type for the new connection [%s] [%+v]", conn.RemoteAddr().String(), m)
			//conn.Close()
		}
	}

}
