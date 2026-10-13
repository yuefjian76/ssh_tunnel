package sshserver

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/bridge"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// handleChannel 是 l3 channel 的处理器，由 gliderlabs/ssh 在客户端开通道时调用。
func (s *Server) handleChannel(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	remote := ctx.RemoteAddr().String()

	// 同一时刻只允许一个 l3 会话：配置里只有一个客户端隧道地址，
	// 两个会话会争抢同一个 10.9.0.2。
	select {
	case s.sessionSlot <- struct{}{}:
		defer func() { <-s.sessionSlot }()
	default:
		s.log.Warn("拒绝新的隧道会话：已有活动会话", "remote", remote)
		newChan.Reject(gossh.Prohibited, "已有活动的隧道会话")
		return
	}

	resp, err := s.negotiate(newChan.ExtraData())
	if err != nil {
		// 拒绝原因只回一句概括，细节留日志：拒绝消息会发到对端，
		// 不应成为探测服务端配置的信息渠道。
		s.log.Warn("隧道参数协商失败", "remote", remote, "err", err)
		newChan.Reject(gossh.Prohibited, "隧道参数不被接受")
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		s.log.Warn("接受隧道通道失败", "remote", remote, "err", err)
		return
	}
	// Accept 返回的请求通道必须被消费，否则该 channel 会永久挂住。
	go gossh.DiscardRequests(reqs)

	// 从这里开始，channel 的关闭权归 Bridge 独占（Attach 结束时统一关闭）：
	// channel.Close 不幂等——每次调用都会再发一条 channelCloseMsg——所以
	// 下面所有失败分支都必须自己关一次并直接 return，不能再交给 defer，
	// 否则一次失败会叠成两次关闭。
	if err := s.sendResponse(ch, resp); err != nil {
		s.log.Warn("发送隧道应答失败", "remote", remote, "err", err)
		_ = ch.Close()
		return
	}

	s.log.Info("隧道会话已建立",
		"remote", remote,
		"client_ip", resp.ClientIP,
		"mtu", resp.MTU,
		"prefix", fmt.Sprintf("%s/%d", resp.ServerIP, resp.PrefixLen))

	// Attach 阻塞到会话结束。上个会话残留的包由 Bridge 按「接入与否」过滤，
	// 不需要在这里显式排空队列（那种做法依赖读循环的执行时机，见 bridge 注释）。
	s.tunnel.Attach(bridge.NewChannelConn(ch, nil))

	s.log.Info("隧道会话已结束", "remote", remote)
}

// negotiate 校验客户端请求并构造应答。纯函数，便于离线单测。
func (s *Server) negotiate(extraData []byte) (proto.Response, error) {
	req, err := proto.DecodeRequest(extraData)
	if err != nil {
		return proto.Response{}, err
	}
	if want := s.cfg.ClientTunnelIP.String(); req.ClientIP != want {
		return proto.Response{}, fmt.Errorf("客户端申请隧道地址 %s，本服务端只提供 %s", req.ClientIP, want)
	}
	// MTU 由服务端单方决定：它必须与网卡实际 MTU 一致，否则会出现
	// 「告诉客户端的值」与「网卡生效的值」不一致这类隐蔽 bug。
	return proto.Response{
		Version:   proto.Version,
		ServerIP:  s.cfg.ServerTunnelIP.String(),
		ClientIP:  s.cfg.ClientTunnelIP.String(),
		PrefixLen: s.cfg.PrefixLen,
		MTU:       s.cfg.MTU,
	}, nil
}

// sendResponse 把协商结果作为第一帧写给客户端。
func (s *Server) sendResponse(ch gossh.Channel, resp proto.Response) error {
	payload, err := proto.EncodeResponse(resp)
	if err != nil {
		return err
	}
	return proto.WriteFrame(ch, payload)
}
