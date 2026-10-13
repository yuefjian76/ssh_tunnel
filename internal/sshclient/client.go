// Package sshclient 实现隧道客户端：经「双层 SSH」建立到服务端的 l3 通道，
// 在本地隧道网卡与通道之间搬运 IP 包，并在断线后自动重连。
//
// 「双层」的由来：自研 server 只监听 127.0.0.1（因此无需改动云安全组），
// 客户端先连系统 sshd 的 22 端口，再用它的 direct-tcpip 转发能力跳到
// 127.0.0.1:8443，最后在这一跳之上做第二次 SSH 握手。
//
//	[client] ──ssh(pem)──> 系统 sshd :22
//	              └── direct-tcpip ──> 127.0.0.1:8443
//	                                     └── 内层 ssh(pem) ──> l3@ssh_tunnel
//
// 本包只负责「把包搬运起来」。地址、路由这类系统状态的配置在 netcfg，
// 由调用方在首条会话建立之后触发（见 Run 的 onReady 参数）。
package sshclient

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/bridge"
	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

const (
	// InitialBackoff 是首次重连前的等待时长。
	InitialBackoff = 1 * time.Second
	// MaxBackoff 是重连退避的上限。
	MaxBackoff = 30 * time.Second

	// StableSessionDuration 是「这条会话算稳定」的门槛。
	//
	// 只有活过这个时长的会话才允许把退避清零。否则服务端处于「连上就断」的
	// 状态时，退避会在每次短暂连上后被反复清零，等于完全没有退避，
	// 变成对服务端的持续冲击。
	StableSessionDuration = 30 * time.Second
)

// Deps 是 Client 运行所需的外部依赖。
//
// 与 sshserver.Deps 一样，加载交由调用方完成，New 本身不做 I/O，
// 从而把「环境有问题」与「构造逻辑有问题」分开定位。
type Deps struct {
	// Packets 是本端隧道网卡。所有权**不**转移：Client 只读写它，不关闭它——
	// 网卡的创建与销毁由调用方（cmd/client）掌握，以便先按配置建好再交进来。
	Packets proto.PacketConn
	// Signer 是用于两段 SSH 认证的私钥。
	Signer gossh.Signer
	// HostKeyCallback 校验外层主机密钥。必填：留空等同于放弃中间人防护。
	HostKeyCallback gossh.HostKeyCallback
	// Logger 为空时使用 slog.Default()。
	Logger *slog.Logger
}

// Client 维护到服务端的隧道，并在断线后自动重连。
type Client struct {
	cfg     config.Client
	signer  gossh.Signer
	hostKey gossh.HostKeyCallback
	log     *slog.Logger
	tunnel  *bridge.Bridge
}

// New 组装客户端。校验全部前置条件，任何一项不满足都立即返回错误。
func New(cfg config.Client, deps Deps) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Packets == nil {
		return nil, fmt.Errorf("sshclient: 缺少隧道网卡")
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("sshclient: 缺少私钥")
	}
	if deps.HostKeyCallback == nil {
		return nil, fmt.Errorf("sshclient: 缺少主机密钥校验回调，拒绝在无校验的情况下连接")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	tunnel, err := bridge.New(deps.Packets, bridge.DefaultQueueSize, logger)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 构造隧道搬运器失败: %w", err)
	}

	return &Client{
		cfg:     cfg,
		signer:  deps.Signer,
		hostKey: deps.HostKeyCallback,
		log:     logger,
		tunnel:  tunnel,
	}, nil
}

// Run 建立隧道并持续搬运 IP 包，断线后自动重连，直到 ctx 结束。
//
// onReady 若非 nil，会在**首条**会话建立之后、开始搬运之前调用一次，
// 用于执行「必须在隧道确实可用之后才能做」的动作（导入路由、设置地址）。
// 它返回错误会终止 Run——这类失败通常是配置问题，重试不会好转。
// 之所以只在首条会话时调用：路由必须在断线重连之间保持不变，
// 反复增删会制造流量黑洞与路由震荡。
//
// onReady 里装好路由后，内核会立刻开始往隧道网卡投包，而此时搬运尚未接上。
// 这些包不会被丢弃——bridge 会把它们排队并在接入后送达，因此启动瞬间不会
// 出现无谓丢包。
//
// 返回 nil 表示 ctx 被取消（含 Ctrl-C），这是正常退出路径。
func (c *Client) Run(ctx context.Context, onReady func(proto.Response) error) error {
	c.tunnel.Start()
	defer func() { _ = c.tunnel.Close() }()

	backoff := InitialBackoff
	ready := false

	for {
		sess, err := c.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isFatal(err) {
				return err
			}
			c.log.Warn("建立隧道失败，将重试", "err", err, "backoff", backoff)
		} else {
			c.log.Info("隧道已建立",
				"server_addr", c.cfg.ServerAddr,
				"client_ip", sess.resp.ClientIP,
				"server_ip", sess.resp.ServerIP,
				"mtu", sess.resp.MTU)
			startedAt := time.Now()

			if !ready && onReady != nil {
				if err := onReady(sess.resp); err != nil {
					_ = sess.Close()
					return err
				}
				ready = true
			}

			// Attach 阻塞到会话结束。ctx 结束时必须主动拆掉当前会话，
			// 否则这里会一直阻塞下去、Ctrl-C 退不掉。
			waitCtx := watchCtx(ctx, sess)
			c.tunnel.Attach(sess.conn)
			waitCtx()

			_ = sess.Close()

			if time.Since(startedAt) >= StableSessionDuration {
				backoff = InitialBackoff
			}
			c.log.Warn("隧道连接已断开，将重连", "backoff", backoff)
		}

		if !sleepCtx(ctx, backoff) {
			return nil
		}
		backoff = nextBackoff(backoff, MaxBackoff)
	}
}

// watchCtx 在 ctx 结束时关闭会话，返回一个停止监听的函数。
//
// 目的单一：让阻塞在 Attach 里的 Run 能被 ctx 打断。会话一旦关闭，
// 底层 SSH 连接随之断开，阻塞中的读操作即返回，Attach 也就跟着返回。
func watchCtx(ctx context.Context, sess *session) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// nextBackoff 返回下一个退避时长：翻倍，但不超过 max。纯函数，便于单测。
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// sleepCtx 等待 d；期间 ctx 结束则提前返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
