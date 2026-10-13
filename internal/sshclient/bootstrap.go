package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/yuefjian76/ssh_tunnel/internal/bridge"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// BootstrapTimeout 约束「外层握手 + 转发 + 内层握手 + 开通道 + 读应答」全过程。
const BootstrapTimeout = 20 * time.Second

// session 是一条已建立的隧道会话所持有的全部资源。
type session struct {
	// raw 是最底层的 TCP 连接，只用于在引导结束后清除握手期的 deadline。
	raw net.Conn
	// outer 是连到系统 sshd 的外层 SSH 连接。
	outer *gossh.Client
	// inner 是连到自研 server 的内层 SSH 连接。
	inner *gossh.Client
	// conn 是 l3 通道，包装成 PacketConn 后交给 bridge 搬运。
	conn *bridge.ChannelConn
	// resp 是服务端确认的隧道参数。
	resp proto.Response

	closeOnce sync.Once
	closeErr  error
}

// Close 释放会话持有的全部资源。可重复调用。
//
// 关闭顺序是刻意的：由内向外。内层连接跑在外层之上，先关内层能让两端的
// 读写协程尽早拿到确定的错误；最后关闭 raw 则保证「阻塞在某个读操作上的
// 协程一定会被唤醒」——这是 Attach 能返回的前提。
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.conn != nil {
			if err := s.conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.inner != nil {
			if err := s.inner.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.outer != nil {
			if err := s.outer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.raw != nil {
			if err := s.raw.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		// 越靠内的资源越先被关，外层随之级联关闭，此时再关一次会拿到
		// "use of closed network connection" 这类噪音——它们不代表真正的问题，
		// 但也不能丢弃，故一并返回由调用方决定是否记录。
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// connect 完成四步引导，返回一条就绪的隧道会话。
func (c *Client) connect(ctx context.Context) (*session, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 连接 %s 失败: %w", c.cfg.ServerAddr, err)
	}

	sess := &session{raw: raw}
	ready := false
	// 引导期间任一步失败，都要收回已经建立的资源（含这条 TCP 连接），
	// 否则每次重试都会泄漏一个 fd 与相应的握手协程。
	defer func() {
		if !ready {
			_ = sess.Close()
		}
	}()

	// 握手截止时间直接设在最底层的 TCP 连接上：外层、转发、内层三步共用
	// 同一个预算。不逐段设超时，是因为中间两层（chanConn / Channel）的
	// SetDeadline 对 SSH channel 未必生效，设在 TCP 上则一定能兜住。
	if err := raw.SetDeadline(time.Now().Add(BootstrapTimeout)); err != nil {
		return nil, fmt.Errorf("sshclient: 设置握手超时失败: %w", err)
	}

	sess.outer, err = handshake(raw, c.cfg.ServerAddr, c.outerConfig())
	if err != nil {
		return nil, fmt.Errorf("sshclient: 外层 SSH 握手失败（%s）: %w", c.cfg.ServerAddr, err)
	}

	// direct-tcpip：目标地址由服务端的 sshd 在本机解析，因此这里的
	// 127.0.0.1:8443 指的是「服务端上的 8443」——自研 server 无需暴露公网，
	// 也无需为此改动云安全组。
	forwarded, err := sess.outer.DialContext(ctx, "tcp", c.cfg.ForwardAddr)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 经 sshd 转发到 %s 失败: %w", c.cfg.ForwardAddr, err)
	}

	sess.inner, err = handshake(forwarded, c.cfg.ForwardAddr, c.innerConfig())
	if err != nil {
		return nil, fmt.Errorf("sshclient: 内层 SSH 握手失败（%s）: %w", c.cfg.ForwardAddr, err)
	}

	payload, err := proto.EncodeRequest(proto.Request{
		Version:  proto.Version,
		ClientIP: c.cfg.ClientTunnelIP.String(),
		MTU:      c.cfg.MTU,
	})
	if err != nil {
		return nil, err
	}

	ch, reqs, err := sess.inner.OpenChannel(proto.ChannelType, payload)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 打开 %s 通道失败: %w", proto.ChannelType, err)
	}
	// Accept 返回的请求通道必须被消费，否则该 channel 会永久挂住。
	go gossh.DiscardRequests(reqs)

	sess.conn = bridge.NewChannelConn(ch, nil)

	// 服务端在通道建立后立刻回写一帧协商结果；必须先读掉它，
	// 之后的字节流才都是 IP 包。
	respPayload, err := sess.conn.ReadPacket()
	if err != nil {
		return nil, fmt.Errorf("sshclient: 读取隧道协商应答失败: %w", err)
	}
	resp, err := proto.DecodeResponse(respPayload)
	if err != nil {
		return nil, err
	}
	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}
	sess.resp = resp

	// 引导结束，清除握手期的 deadline。数据面要长期运行，
	// 残留的截止时间会在隧道跑起来一段时间后把连接掐断。
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("sshclient: 清除握手超时失败: %w", err)
	}

	ready = true
	return sess, nil
}

// handshake 在既有的 net.Conn 上做一次 SSH 客户端握手。
// 外层与内层两次握手共用它（DRY）。
func handshake(conn net.Conn, addr string, cfg *gossh.ClientConfig) (*gossh.Client, error) {
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return gossh.NewClient(sshConn, chans, reqs), nil
}

// outerConfig 是外层（系统 sshd）握手配置：按 known_hosts 严格校验主机密钥。
func (c *Client) outerConfig() *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:            c.cfg.User,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(c.signer)},
		HostKeyCallback: c.hostKey,
	}
}

// innerConfig 是内层（自研 server）握手配置。
//
// 内层**不校验**主机密钥，理由不是省事：
//   - 内层的字节流完全跑在外层 SSH 的加密通道里，而外层已按 known_hosts
//     严格校验过服务端主机密钥；
//   - 能把 direct-tcpip 的目标引到别处的，只有在服务端主机上已有代码执行权
//     的人——而那时隧道内容对他本就是明文（他就是服务端本身）。
//
// 也就是说，为内层再引入一套主机密钥信任并没有对应的防护增益。若日后自研
// server 改为对外监听，这个前提就失效了，届时必须补上主机密钥固定。
func (c *Client) innerConfig() *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:            c.cfg.User,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(c.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
}

// checkResponse 确认服务端确认的隧道参数与本端配置一致。
//
// 三处都必须一致，不一致就直接失败，而不是「以对端为准」地自适应：
// 本端的网卡 MTU 与地址在连上之前就已按配置设好，若服务端给出不同的值，
// 继续跑下去就会形成两端对不上的隐蔽故障（例如大包被无声丢弃）。
// 宁可当场报错，让人去把两端配置对齐。
func (c *Client) checkResponse(resp proto.Response) error {
	if resp.ClientIP != c.cfg.ClientTunnelIP.String() {
		return fmt.Errorf("sshclient: 服务端分配的隧道地址 %s 与本端配置 %s 不一致",
			resp.ClientIP, c.cfg.ClientTunnelIP)
	}
	if resp.PrefixLen != c.cfg.PrefixLen {
		return fmt.Errorf("sshclient: 服务端隧道掩码 %d 与本端配置 %d 不一致",
			resp.PrefixLen, c.cfg.PrefixLen)
	}
	if resp.MTU != c.cfg.MTU {
		return fmt.Errorf("sshclient: 服务端隧道 MTU %d 与本端配置 %d 不一致，请用 --mtu %d 重跑",
			resp.MTU, c.cfg.MTU, resp.MTU)
	}
	return nil
}

// isFatal 判断错误是否为「重试也不会好转」的类型。
//
// 目前只认一种：主机密钥校验失败（known_hosts 与本端记录不符）。它意味着
// 要么服务端换了密钥，要么有人在做中间人——两种情况都必须人工介入，
// 反复重连只会把真正的原因淹没在日志里。
//
// 认证失败（私钥不对）在 x/crypto 里没有可判别的导出错误类型（是普通
// fmt.Errorf），因此不在此处拦截；但它会在每次重试时以 Warn 级别暴露出来。
func isFatal(err error) bool {
	var keyErr *knownhosts.KeyError
	return errors.As(err, &keyErr)
}
