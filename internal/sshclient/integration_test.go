package sshclient

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/sshserver"
	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
)

// 本文件把整条客户端链路真的跑起来：
//
//	client ──ssh──> 假 sshd（只提供 direct-tcpip 转发）──> 真 sshserver ──> 内存网卡
//
// 外层用假 sshd 是因为真实场景里那一端是云主机的系统 sshd，不该进单测；
// 而它在这条链路上只承担「按 direct-tcpip 转发字节流」一个职责，
// 用 gliderlabs 现成的 DirectTCPIPHandler 即可如实替代。
//
// 这样做的好处是整个阶段 5 的目标——「证明 IP 包能穿过双层 SSH」——可以在
// 本机、无 root、无真实网卡、不改系统路由的前提下被持续验证。

const (
	// setupTimeout 是等待各层服务起好、隧道建好的上限。
	setupTimeout = 10 * time.Second
	// packetTimeout 是等待一个包穿过隧道的上限。
	packetTimeout = 5 * time.Second
)

// startInnerServer 起一个真实的隧道服务端，网卡用内存实现，
// 返回其监听地址与该内存网卡。
func startInnerServer(t *testing.T, signer gossh.Signer, mtu int) (string, *testutil.MemPacketConn) {
	t.Helper()

	cfg := config.DefaultServer()
	// 监听地址在这里无意义（Serve 用的是下面自建的 listener），
	// 但仍需合法以便通过配置校验。
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.AuthorizedKeysPaths = []string{"/dev/null"}
	cfg.MTU = mtu

	packets := testutil.NewMemPacketConn()
	srv, err := sshserver.New(cfg, sshserver.Deps{
		Packets:     packets,
		HostKey:     signer,
		AllowedKeys: sshserver.KeyWhitelist{signer.PublicKey()},
		Logger:      testLogger(),
	})
	if err != nil {
		t.Fatalf("构造隧道服务端失败: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = packets.Close()
	})
	return ln.Addr().String(), packets
}

// startFakeSSHD 起一个只做 direct-tcpip 转发的 SSH 服务端，充当云主机上的系统 sshd。
func startFakeSSHD(t *testing.T, signer gossh.Signer) string {
	t.Helper()

	srv := &gliderssh.Server{
		// 必须显式给出主机密钥：HostSigners 为空时 gliderlabs 会自己生成一枚
		// （server.go:84），那样客户端按预期主机密钥校验必然失败。
		HostSigners: []gliderssh.Signer{signer},
		PublicKeyHandler: func(_ gliderssh.Context, key gliderssh.PublicKey) bool {
			return gliderssh.KeysEqual(key, signer.PublicKey())
		},
		// 转发目标由配置决定，这里全部放行——它替代的是「云主机的 sshd 允许
		// 转发到本机 8443」这一既成事实，不是被测逻辑。
		LocalPortForwardingCallback: func(gliderssh.Context, string, uint32) bool { return true },
		// 只注册 direct-tcpip：显式给出 map 就等于不注册 "session"，
		// 与自研 server 的做法一致，暴露面最小。
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"direct-tcpip": gliderssh.DirectTCPIPHandler,
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestRunCarriesPacketsThroughDoubleSSH(t *testing.T) {
	// Arrange：两端的密钥都用同一枚，与「复用 soer.pem」的实际部署一致。
	signer := testutil.MustSigner()

	innerAddr, serverPackets := startInnerServer(t, signer, config.DefaultMTU)
	sshdAddr := startFakeSSHD(t, signer)

	clientPackets := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = clientPackets.Close() })

	cfg := unitClientConfig()
	cfg.ServerAddr = sshdAddr
	cfg.ForwardAddr = innerAddr

	cli, err := New(cfg, Deps{
		Packets:         clientPackets,
		Signer:          signer,
		HostKeyCallback: gossh.FixedHostKey(signer.PublicKey()),
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// onReady 在这里只用来把「首条会话已建立」这件事通知测试代码，
	// 真实调用方会在此处配置地址与路由。
	ready := make(chan proto.Response, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- cli.Run(ctx, func(resp proto.Response) error {
			ready <- resp
			return nil
		})
	}()

	// Assert 一：隧道建立，且服务端确认的参数与请求一致
	var resp proto.Response
	select {
	case resp = <-ready:
	case err := <-runErr:
		t.Fatalf("Run 在隧道建立前就返回了: %v", err)
	case <-time.After(setupTimeout):
		t.Fatal("等待隧道建立超时")
	}

	if resp.ClientIP != cfg.ClientTunnelIP.String() {
		t.Fatalf("分配的隧道地址 = %s，期望 %s", resp.ClientIP, cfg.ClientTunnelIP)
	}
	if resp.MTU != cfg.MTU {
		t.Fatalf("确认的 MTU = %d，期望 %d", resp.MTU, cfg.MTU)
	}

	// Assert 二：客户端网卡 → 服务端网卡
	toServer := []byte{0x45, 0x00, 0x01, 0x02, 0x03}
	if err := clientPackets.Send(toServer); err != nil {
		t.Fatalf("向客户端网卡注入包失败: %v", err)
	}
	got, err := serverPackets.Recv(packetTimeout)
	if err != nil {
		t.Fatalf("服务端未收到客户端发出的包: %v", err)
	}
	if !bytes.Equal(got, toServer) {
		t.Fatalf("服务端收到的包 = %x，期望 %x", got, toServer)
	}

	// Assert 三：服务端网卡 → 客户端网卡
	toClient := []byte{0x45, 0x00, 0x09, 0x08, 0x07}
	if err := serverPackets.Send(toClient); err != nil {
		t.Fatalf("向服务端网卡注入包失败: %v", err)
	}
	got, err = clientPackets.Recv(packetTimeout)
	if err != nil {
		t.Fatalf("客户端未收到服务端发出的包: %v", err)
	}
	if !bytes.Equal(got, toClient) {
		t.Fatalf("客户端收到的包 = %x，期望 %x", got, toClient)
	}

	// Assert 四：取消 ctx 应当让 Run 正常退出（Ctrl-C 的路径）
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("ctx 取消后 Run 应当返回 nil，实际: %v", err)
		}
	case <-time.After(setupTimeout):
		t.Fatal("ctx 取消后 Run 应当退出")
	}
}

// TestRunRejectsMismatchedMTU 守住「两端参数必须一致」：
// 客户端网卡 MTU 在连接之前就已按配置设好，服务端给出不同值时若继续跑下去，
// 会形成大包被无声丢弃这类极难定位的故障。
func TestRunRejectsMismatchedMTU(t *testing.T) {
	// Arrange：服务端 MTU 与客户端配置不同
	signer := testutil.MustSigner()
	innerAddr, _ := startInnerServer(t, signer, 1400)
	sshdAddr := startFakeSSHD(t, signer)

	clientPackets := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = clientPackets.Close() })

	cfg := unitClientConfig()
	cfg.ServerAddr = sshdAddr
	cfg.ForwardAddr = innerAddr
	cfg.MTU = 1280

	cli, err := New(cfg, Deps{
		Packets:         clientPackets,
		Signer:          signer,
		HostKeyCallback: gossh.FixedHostKey(signer.PublicKey()),
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}

	// Act
	_, err = cli.connect(context.Background())

	// Assert
	if err == nil {
		t.Fatal("两端 MTU 不一致时应当拒绝建立隧道")
	}
}
