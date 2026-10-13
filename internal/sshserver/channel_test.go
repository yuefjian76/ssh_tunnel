package sshserver

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
	gossh "golang.org/x/crypto/ssh"
)

// frameTimeout 是所有跨连接读取的等待上限。
//
// 用超时而非无限等待：这样失败会表现为「没收到帧」这一明确结论，
// 而不是挂到 go test 的整体超时、看不出究竟卡在哪一步。
const frameTimeout = 3 * time.Second

// testServer 是一台起在回环上的真实 SSH 隧道服务端。
type testServer struct {
	cfg       config.Server
	packets   *testutil.MemPacketConn
	addr      string
	clientKey gossh.Signer
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// startTestServer 起一台服务端并登记清理。被授权的客户端密钥固定为 clientKey，
// 便于各用例另行构造未被授权的连接来验证拒绝路径。
func startTestServer(t *testing.T) *testServer {
	t.Helper()

	clientKey := testutil.MustSigner()
	cfg := config.DefaultServer()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.AuthorizedKeysPaths = []string{"/dev/null"} // Validate 只校验非空，不读文件

	packets := testutil.NewMemPacketConn()
	srv, err := New(cfg, Deps{
		Packets:     packets,
		HostKey:     testutil.MustSigner(),
		AllowedKeys: KeyWhitelist{clientKey.PublicKey()},
		Logger:      testLogger(),
	})
	if err != nil {
		t.Fatalf("构造服务端失败: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听回环失败: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// 清理按注册顺序逆序执行，所以客户端会先于服务端关闭。
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("关闭服务端失败: %v", err)
		}
		if err := <-serveErr; err != nil {
			t.Errorf("Serve 返回错误: %v", err)
		}
	})

	return &testServer{
		cfg:       cfg,
		packets:   packets,
		addr:      ln.Addr().String(),
		clientKey: clientKey,
	}
}

// dialClient 尝试用给定私钥连接服务端。
func dialClient(addr string, signer gossh.Signer) (*gossh.Client, error) {
	return gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User: "tester",
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
		// 测试里跳过主机密钥校验：服务端主机密钥每次测试都是新生成的。
		// 生产代码必须走 known_hosts，见 internal/sshclient。
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         frameTimeout,
	})
}

// mustDial 连接服务端，失败即终止用例。
func mustDial(t *testing.T, ts *testServer, signer gossh.Signer) *gossh.Client {
	t.Helper()

	client, err := dialClient(ts.addr, signer)
	if err != nil {
		t.Fatalf("连接测试服务端失败: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// openL3 打开隧道通道。返回错误而非直接失败，便于断言「应当被拒绝」的用例。
func openL3(t *testing.T, client *gossh.Client, clientIP string, mtu int) (gossh.Channel, error) {
	t.Helper()

	request, err := proto.EncodeRequest(proto.Request{
		Version:  proto.Version,
		ClientIP: clientIP,
		MTU:      mtu,
	})
	if err != nil {
		t.Fatalf("构造请求载荷失败: %v", err)
	}

	ch, reqs, err := client.OpenChannel(proto.ChannelType, request)
	if err != nil {
		return nil, err
	}
	go gossh.DiscardRequests(reqs)
	return ch, nil
}

// readFrameWithin 在超时内从通道读一帧。
func readFrameWithin(ch gossh.Channel, timeout time.Duration) ([]byte, error) {
	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		payload, err := proto.ReadFrame(ch, nil)
		done <- result{payload, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-done:
		return r.payload, r.err
	case <-timer.C:
		return nil, fmt.Errorf("在 %s 内没有读到帧", timeout)
	}
}

// fakeIPv4Packet 造一个形似 IPv4 的包。内容不必真实可路由——这条链路上
// 没有内核参与解析，本测试只验证字节被原样搬运。
func fakeIPv4Packet(marker byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45   // IPv4 且首部长度为 5 个 32 位字
	pkt[1] = marker // 用作区分不同包的标记字节
	pkt[3] = 0x14   // 总长度 20
	return pkt
}

func TestServerCarriesPacketsBothWaysOverL3Channel(t *testing.T) {
	// Arrange
	ts := startTestServer(t)
	client := mustDial(t, ts, ts.clientKey)

	ch, err := openL3(t, client, ts.cfg.ClientTunnelIP.String(), ts.cfg.MTU)
	if err != nil {
		t.Fatalf("打开隧道通道失败: %v", err)
	}

	// 通道建立后的第一帧必须是协商应答
	payload, err := readFrameWithin(ch, frameTimeout)
	if err != nil {
		t.Fatalf("读取协商应答失败: %v", err)
	}
	resp, err := proto.DecodeResponse(payload)
	if err != nil {
		t.Fatalf("解析协商应答失败: %v", err)
	}
	if resp.ServerIP != ts.cfg.ServerTunnelIP.String() {
		t.Fatalf("应答中的服务端地址 = %s，期望 %s", resp.ServerIP, ts.cfg.ServerTunnelIP)
	}

	// 方向一：服务端网卡读到的包，应当出现在客户端
	upstream := fakeIPv4Packet(0x11)
	if err := ts.packets.Send(upstream); err != nil {
		t.Fatalf("向服务端网卡注入包失败: %v", err)
	}
	got, err := readFrameWithin(ch, frameTimeout)
	if err != nil {
		t.Fatalf("客户端未收到上行包: %v", err)
	}
	if !bytes.Equal(got, upstream) {
		t.Fatalf("客户端收到的包 = %x，期望 %x", got, upstream)
	}

	// 方向二：客户端写入的包，应当出现在服务端网卡
	downstream := fakeIPv4Packet(0x22)
	if err := proto.WriteFrame(ch, downstream); err != nil {
		t.Fatalf("客户端发送包失败: %v", err)
	}
	got, err = ts.packets.Recv(frameTimeout)
	if err != nil {
		t.Fatalf("服务端网卡未收到下行包: %v", err)
	}
	if !bytes.Equal(got, downstream) {
		t.Fatalf("服务端收到的包 = %x，期望 %x", got, downstream)
	}
}

func TestServerRejectsUnauthorizedKey(t *testing.T) {
	// Arrange
	ts := startTestServer(t)
	outsider := testutil.MustSigner()

	// Act
	client, err := dialClient(ts.addr, outsider)

	// Assert
	if err == nil {
		_ = client.Close()
		t.Fatal("未被授权的公钥不应能建立连接")
	}
}

func TestServerRejectsForeignClientIP(t *testing.T) {
	// Arrange
	ts := startTestServer(t)
	client := mustDial(t, ts, ts.clientKey)

	// Act：申请一个不属于本服务端的隧道地址
	ch, err := openL3(t, client, "10.9.0.99", ts.cfg.MTU)
	if ch != nil {
		_ = ch.Close()
	}

	// Assert
	if err == nil {
		t.Fatal("申请非本服务端的隧道地址应当被拒绝")
	}
}

func TestServerRejectsSecondConcurrentSession(t *testing.T) {
	// Arrange：先建立一个保持打开的会话
	ts := startTestServer(t)
	first := mustDial(t, ts, ts.clientKey)

	firstCh, err := openL3(t, first, ts.cfg.ClientTunnelIP.String(), ts.cfg.MTU)
	if err != nil {
		t.Fatalf("首个会话应当建立成功: %v", err)
	}
	if _, err := readFrameWithin(firstCh, frameTimeout); err != nil {
		t.Fatalf("首个会话未收到协商应答: %v", err)
	}

	// Act：第二个连接再尝试开会话
	second := mustDial(t, ts, ts.clientKey)
	secondCh, err := openL3(t, second, ts.cfg.ClientTunnelIP.String(), ts.cfg.MTU)
	if secondCh != nil {
		_ = secondCh.Close()
	}

	// Assert
	if err == nil {
		t.Fatal("同一时刻只应允许一个隧道会话")
	}
}

// TestServerRejectsSessionChannel 验证暴露面确实最小：
// 服务端只注册了 l3，普通 SSH 客户端无法在它上面开 shell。
func TestServerRejectsSessionChannel(t *testing.T) {
	// Arrange
	ts := startTestServer(t)
	client := mustDial(t, ts, ts.clientKey)

	// Act
	ch, _, err := client.OpenChannel("session", nil)
	if ch != nil {
		_ = ch.Close()
	}

	// Assert
	if err == nil {
		t.Fatal("session 通道应当被拒绝：本服务端只提供 l3 隧道")
	}
}
