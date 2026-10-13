package sshclient

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// unitClientConfig 返回一份能通过 config.Validate 的客户端配置。
// KeyPath 只做非空校验（Validate 不碰文件系统），因此不必真实存在。
func unitClientConfig() config.Client {
	cfg := config.DefaultClient()
	cfg.KeyPath = "/dev/null"
	return cfg
}

// validDeps 返回一组完整可用的依赖，供各用例按需替换其中一项。
func validDeps() Deps {
	signer := testutil.MustSigner()
	return Deps{
		Packets:         testutil.NewMemPacketConn(),
		Signer:          signer,
		HostKeyCallback: gossh.FixedHostKey(signer.PublicKey()),
		Logger:          testLogger(),
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	signer := testutil.MustSigner()

	tests := []struct {
		name string
		deps Deps
	}{
		{"缺少隧道网卡", Deps{Signer: signer, HostKeyCallback: gossh.InsecureIgnoreHostKey()}},
		{"缺少私钥", Deps{Packets: testutil.NewMemPacketConn(), HostKeyCallback: gossh.InsecureIgnoreHostKey()}},
		{"缺少主机密钥校验回调", Deps{Packets: testutil.NewMemPacketConn(), Signer: signer}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			cli, err := New(unitClientConfig(), tc.deps)

			// Assert
			if err == nil {
				t.Fatal("依赖缺失时应当报错")
			}
			if cli != nil {
				t.Fatal("出错时不应返回客户端")
			}
		})
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	// Arrange：私钥路径留空，config.Validate 会拒绝
	cfg := unitClientConfig()
	cfg.KeyPath = ""

	// Act
	_, err := New(cfg, validDeps())

	// Assert
	if err == nil {
		t.Fatal("非法配置应当被拒绝")
	}
}

func TestCheckResponseRequiresMatchingEnds(t *testing.T) {
	cfg := unitClientConfig()
	cli := &Client{cfg: cfg}

	base := proto.Response{
		Version:   proto.Version,
		ServerIP:  config.DefaultServerTunnelIP,
		ClientIP:  cfg.ClientTunnelIP.String(),
		PrefixLen: cfg.PrefixLen,
		MTU:       cfg.MTU,
	}

	tests := []struct {
		name    string
		mutate  func(proto.Response) proto.Response
		wantErr bool
	}{
		{"完全一致", func(r proto.Response) proto.Response { return r }, false},
		{
			"分配的隧道地址不同",
			func(r proto.Response) proto.Response { r.ClientIP = "10.9.0.77"; return r },
			true,
		},
		{
			"掩码长度不同",
			func(r proto.Response) proto.Response { r.PrefixLen = 16; return r },
			true,
		},
		{
			"MTU 不同",
			func(r proto.Response) proto.Response { r.MTU = 1400; return r },
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := cli.checkResponse(tc.mutate(base))

			// Assert
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkResponse 的 error = %v，期望出错 = %v", err, tc.wantErr)
			}
		})
	}
}

// TestIsFatalRecognizesHostKeyMismatch 守住「主机密钥不符时不再重试」：
// 那是需要人工介入的状态（换了密钥，或有人在做中间人），
// 无限重连只会把真正的原因刷进日志噪音里。
func TestIsFatalRecognizesHostKeyMismatch(t *testing.T) {
	hostKeyErr := &knownhosts.KeyError{}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"主机密钥不符", hostKeyErr, true},
		{"被包装的主机密钥不符", errors.Join(errors.New("外层握手失败"), hostKeyErr), true},
		{"连接被拒绝", errors.New("connection refused"), false},
		{"认证失败（x/crypto 无可判别类型）", errors.New("ssh: unable to authenticate"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := isFatal(tc.err)

			// Assert
			if got != tc.want {
				t.Fatalf("isFatal(%v) = %v，期望 %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNextBackoffDoublesUpToMaximum(t *testing.T) {
	tests := []struct {
		name    string
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{"翻倍", time.Second, 30 * time.Second, 2 * time.Second},
		{"接近上限时直接封顶", 20 * time.Second, 30 * time.Second, 30 * time.Second},
		{"已在上限时保持在上限", 30 * time.Second, 30 * time.Second, 30 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := nextBackoff(tc.current, tc.max)

			// Assert
			if got != tc.want {
				t.Fatalf("nextBackoff(%s, %s) = %s，期望 %s", tc.current, tc.max, got, tc.want)
			}
		})
	}
}

func TestSleepCtxReturnsFalseWhenContextEnds(t *testing.T) {
	// Arrange
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act：等待时间很长，但 ctx 已经结束，应当立刻返回
	start := time.Now()
	ok := sleepCtx(ctx, time.Hour)

	// Assert
	if ok {
		t.Fatal("ctx 已结束时 sleepCtx 应当返回 false")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ctx 已结束时不应当真的等待，实际耗时 %s", elapsed)
	}
}

func TestSleepCtxReturnsTrueAfterDuration(t *testing.T) {
	// Act
	ok := sleepCtx(context.Background(), time.Millisecond)

	// Assert
	if !ok {
		t.Fatal("ctx 未结束时 sleepCtx 应当在等待结束后返回 true")
	}
}

// TestIsFatalRejectsNil 记录一个容易踩的边界：errors.As(nil, ...) 返回 false，
// 不应把「没有错误」误判为致命错误。
func TestIsFatalRejectsNil(t *testing.T) {
	if isFatal(nil) {
		t.Fatal("nil 不应被判定为致命错误")
	}
}
