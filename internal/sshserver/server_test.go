package sshserver

import (
	"fmt"
	"testing"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
)

// unitConfig 返回一份能通过 config.Validate 的服务端配置。
// 路径只做非空校验（Validate 不碰文件系统），所以不必真实存在。
func unitConfig() config.Server {
	cfg := config.DefaultServer()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.AuthorizedKeysPaths = []string{"/dev/null"}
	return cfg
}

// encodeRequest 是测试里构造请求载荷的便捷封装。
func encodeRequest(t *testing.T, clientIP string, mtu int) []byte {
	t.Helper()
	payload, err := proto.EncodeRequest(proto.Request{
		Version:  proto.Version,
		ClientIP: clientIP,
		MTU:      mtu,
	})
	if err != nil {
		t.Fatalf("构造请求载荷失败: %v", err)
	}
	return payload
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	signer := testutil.MustSigner()

	tests := []struct {
		name string
		deps Deps
	}{
		{"缺少隧道网卡", Deps{HostKey: signer, AllowedKeys: KeyWhitelist{signer.PublicKey()}}},
		{"缺少主机密钥", Deps{Packets: testutil.NewMemPacketConn(), AllowedKeys: KeyWhitelist{signer.PublicKey()}}},
		{"空白名单", Deps{Packets: testutil.NewMemPacketConn(), HostKey: signer}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			srv, err := New(unitConfig(), tc.deps)

			// Assert
			if err == nil {
				t.Fatal("依赖缺失时应当报错")
			}
			if srv != nil {
				t.Fatal("出错时不应返回服务端")
			}
		})
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	// Arrange：监听地址缺少端口
	cfg := unitConfig()
	cfg.ListenAddr = "127.0.0.1"
	signer := testutil.MustSigner()

	// Act
	_, err := New(cfg, Deps{
		Packets:     testutil.NewMemPacketConn(),
		HostKey:     signer,
		AllowedKeys: KeyWhitelist{signer.PublicKey()},
	})

	// Assert
	if err == nil {
		t.Fatal("非法配置应当被拒绝")
	}
}

func TestNegotiateAcceptsMatchingClientIP(t *testing.T) {
	// Arrange
	cfg := unitConfig()
	srv := &Server{cfg: cfg}
	request := encodeRequest(t, cfg.ClientTunnelIP.String(), cfg.MTU)

	// Act
	resp, err := srv.negotiate(request)

	// Assert
	if err != nil {
		t.Fatalf("negotiate 返回错误: %v", err)
	}
	if resp.ServerIP != cfg.ServerTunnelIP.String() {
		t.Fatalf("服务端地址 = %s，期望 %s", resp.ServerIP, cfg.ServerTunnelIP)
	}
	if resp.ClientIP != cfg.ClientTunnelIP.String() {
		t.Fatalf("客户端地址 = %s，期望 %s", resp.ClientIP, cfg.ClientTunnelIP)
	}
	if resp.PrefixLen != cfg.PrefixLen {
		t.Fatalf("掩码长度 = %d，期望 %d", resp.PrefixLen, cfg.PrefixLen)
	}
}

// TestNegotiateIgnoresClientMTUPreference 断言 MTU 由服务端单方决定：
// 它必须等于网卡实际 MTU，否则会出现「告诉客户端的值」与「网卡生效的值」
// 不一致这类隐蔽 bug。
func TestNegotiateIgnoresClientMTUPreference(t *testing.T) {
	// Arrange：客户端要求 1400，服务端配置为 1280
	cfg := unitConfig()
	srv := &Server{cfg: cfg}
	request := encodeRequest(t, cfg.ClientTunnelIP.String(), 1400)

	// Act
	resp, err := srv.negotiate(request)

	// Assert
	if err != nil {
		t.Fatalf("negotiate 返回错误: %v", err)
	}
	if resp.MTU != cfg.MTU {
		t.Fatalf("应答 MTU = %d，期望服务端配置值 %d", resp.MTU, cfg.MTU)
	}
}

func TestNegotiateRejectsBadRequests(t *testing.T) {
	cfg := unitConfig()
	srv := &Server{cfg: cfg}

	// 手工构造一个版本号不被支持的请求：EncodeRequest 自身会先做校验，
	// 所以没法用它产出这种载荷，只能直接写 JSON。
	incompatibleVersion := []byte(fmt.Sprintf(
		`{"version":999,"client_ip":%q,"mtu":%d}`, cfg.ClientTunnelIP.String(), cfg.MTU))

	tests := []struct {
		name string
		data []byte
	}{
		{"申请的隧道地址不属于本服务端", encodeRequest(t, "10.9.0.99", cfg.MTU)},
		{"协议版本不兼容", incompatibleVersion},
		{"请求不是合法 JSON", []byte("}}}garbage")},
		{"附加数据为空", nil},
		{"请求体被截断", encodeRequest(t, cfg.ClientTunnelIP.String(), cfg.MTU)[:5]},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, err := srv.negotiate(tc.data)

			// Assert
			if err == nil {
				t.Fatal("非法请求应当被拒绝")
			}
		})
	}
}
