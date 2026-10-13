// Package sshserver 实现隧道服务端：把 tun 网卡与客户端的 l3 channel 对接起来。
//
// 设计约束：同一时刻只服务一个 l3 会话。这由配置模型决定——config.Server 里
// 只有一个 ClientTunnelIP（10.9.0.2），两个并发会话会争抢同一个隧道地址，
// 语义上无法同时成立。因此第二个连接会被明确拒绝，而不是静默地互相串包。
package sshserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/bridge"
	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// Deps 是 Server 运行所需的外部依赖。
//
// 由调用方（cmd/server）负责加载，New 本身不做 I/O——这样「配置或环境有问题」
// 与「构造逻辑有问题」可以分开定位，New 也因此能离线单测。
type Deps struct {
	// Packets 是服务端隧道网卡。New 成功后其所有权转移给 Server：
	// Server.Close 会关闭它，调用方不要再关一次。
	Packets proto.PacketConn
	// HostKey 是 SSH 主机密钥。
	HostKey gossh.Signer
	// AllowedKeys 是允许登录的公钥白名单。
	AllowedKeys KeyWhitelist
	// Logger 为空时使用 slog.Default()。
	Logger *slog.Logger
}

// Server 在 tun 网卡与客户端之间搬运 IP 包。
type Server struct {
	cfg     config.Server
	packets proto.PacketConn
	allowed KeyWhitelist
	log     *slog.Logger

	sshServer *ssh.Server

	// tunnel 负责「常驻网卡读循环 ↔ 当前会话」的搬运。网卡读循环的常驻性
	// 由它保证：断线重连只更换连接，网卡与读循环都不重建。
	tunnel *bridge.Bridge

	// sessionSlot 容量为 1，充当「同一时刻只允许一个 l3 会话」的信号量。
	sessionSlot chan struct{}

	closeOnce sync.Once
	// closeErr 缓存首次 Close 的错误：重复调用返回同一结果，
	// 而不是把「已关闭」当成新的失败。
	closeErr  error
	startOnce sync.Once
}

// New 组装服务端。校验全部前置条件，任何一项不满足都立即返回错误。
func New(cfg config.Server, deps Deps) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Packets == nil {
		return nil, fmt.Errorf("sshserver: 缺少隧道网卡")
	}
	if deps.HostKey == nil {
		return nil, fmt.Errorf("sshserver: 缺少主机密钥")
	}
	if len(deps.AllowedKeys) == 0 {
		return nil, fmt.Errorf("sshserver: 公钥白名单为空，将无人能登录")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	tunnel, err := bridge.New(deps.Packets, bridge.DefaultQueueSize, logger)
	if err != nil {
		return nil, fmt.Errorf("sshserver: 构造隧道搬运器失败: %w", err)
	}

	srv := &Server{
		cfg:         cfg,
		packets:     deps.Packets,
		allowed:     deps.AllowedKeys,
		log:         logger,
		tunnel:      tunnel,
		sessionSlot: make(chan struct{}, 1),
	}

	srv.sshServer = &ssh.Server{
		Addr:             cfg.ListenAddr,
		HostSigners:      []ssh.Signer{deps.HostKey},
		PublicKeyHandler: srv.authenticate,
		// 只注册 l3 一种 channel。注意 gliderlabs 仅在 ChannelHandlers 为 nil 时
		// 才填入默认值（server.go:104），所以显式给出这个 map 就等于不注册
		// "session"——客户端开 session 通道会被直接拒绝，暴露面最小。
		ChannelHandlers: map[string]ssh.ChannelHandler{
			proto.ChannelType: srv.handleChannel,
		},
	}
	return srv, nil
}

// ListenAndServe 在配置的地址上监听并开始服务，直到 Close 被调用或出错。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("sshserver: 监听 %s 失败: %w", s.cfg.ListenAddr, err)
	}
	s.log.Info("隧道服务端已监听",
		"addr", s.cfg.ListenAddr,
		"channel", proto.ChannelType,
		"server_ip", s.cfg.ServerTunnelIP,
		"client_ip", s.cfg.ClientTunnelIP,
		"mtu", s.cfg.MTU)
	return s.Serve(ln)
}

// Serve 在已有监听器上服务。正常关闭时返回 nil。
func (s *Server) Serve(ln net.Listener) error {
	// 网卡读循环必须常驻（跨会话复用同一张网卡），因此只启动一次。
	s.startOnce.Do(func() { s.tunnel.Start() })

	err := s.sshServer.Serve(ln)
	if errors.Is(err, ssh.ErrServerClosed) {
		return nil
	}
	return err
}

// Close 关闭服务端及其持有的隧道网卡。可重复调用。
//
// 关闭顺序有讲究：先停搬运、再停 SSH、最后关网卡。网卡读循环正阻塞在
// ReadPacket 上，只有网卡被关闭它才能返回——这也是 Close 之后读循环才
// 真正退出的原因。详见 bridge.Bridge 的生命周期约定。
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if err := s.tunnel.Close(); err != nil {
			errs = append(errs, fmt.Errorf("sshserver: 停止隧道搬运失败: %w", err))
		}
		if s.sshServer != nil {
			if err := s.sshServer.Close(); err != nil {
				errs = append(errs, fmt.Errorf("sshserver: 关闭 SSH 服务端失败: %w", err))
			}
		}
		if err := s.packets.Close(); err != nil {
			errs = append(errs, fmt.Errorf("sshserver: 关闭隧道网卡失败: %w", err))
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// authenticate 是公钥认证回调。白名单未命中即拒绝（fail closed）。
func (s *Server) authenticate(ctx ssh.Context, key ssh.PublicKey) bool {
	allowed := s.allowed.Allows(key)
	level := slog.LevelInfo
	if !allowed {
		level = slog.LevelWarn
	}
	// 记录指纹而非密钥内容：指纹是标准做法，公钥本身也是公开信息，
	// 但指纹更短、更适合放进日志。
	s.log.Log(ctx, level, "收到公钥认证请求",
		"user", ctx.User(),
		"remote", ctx.RemoteAddr().String(),
		"fingerprint", gossh.FingerprintSHA256(key),
		"allowed", allowed)
	return allowed
}
