package bridge

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
	gossh "golang.org/x/crypto/ssh"
)

// stepTimeout 是测试里等待异步结果的统一上限。
const stepTimeout = 2 * time.Second

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func mustBridge(t *testing.T, packets proto.PacketConn) *Bridge {
	t.Helper()

	b, err := New(packets, DefaultQueueSize, testLogger())
	if err != nil {
		t.Fatalf("构造 Bridge 失败: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestNewRejectsBadInput(t *testing.T) {
	tests := []struct {
		name      string
		packets   proto.PacketConn
		queueSize int
	}{
		{"缺少隧道网卡", nil, DefaultQueueSize},
		{"队列深度为零", testutil.NewMemPacketConn(), 0},
		{"队列深度为负", testutil.NewMemPacketConn(), -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			b, err := New(tc.packets, tc.queueSize, testLogger())

			// Assert
			if err == nil {
				t.Fatal("非法参数应当被拒绝")
			}
			if b != nil {
				t.Fatal("出错时不应返回 Bridge")
			}
		})
	}
}

func TestBridgeCarriesPacketsBothWays(t *testing.T) {
	// Arrange
	packets := testutil.NewMemPacketConn()
	b := mustBridge(t, packets)
	b.Start()

	remote := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = remote.Close() })

	attached := make(chan struct{})
	go func() {
		b.Attach(remote)
		close(attached)
	}()

	// Act & Assert 一：remote → packets
	fromRemote := []byte{0xA1, 0x01}
	if err := remote.Send(fromRemote); err != nil {
		t.Fatalf("向远端注入包失败: %v", err)
	}
	got, err := packets.Recv(stepTimeout)
	if err != nil {
		t.Fatalf("隧道网卡未收到远端发来的包: %v", err)
	}
	if !bytes.Equal(got, fromRemote) {
		t.Fatalf("网卡收到的包 = %x，期望 %x", got, fromRemote)
	}

	// Act & Assert 二：packets → remote
	fromPackets := []byte{0xB2, 0x02}
	if err := packets.Send(fromPackets); err != nil {
		t.Fatalf("向网卡注入包失败: %v", err)
	}
	got, err = remote.Recv(stepTimeout)
	if err != nil {
		t.Fatalf("远端未收到网卡发来的包: %v", err)
	}
	if !bytes.Equal(got, fromPackets) {
		t.Fatalf("远端收到的包 = %x，期望 %x", got, fromPackets)
	}

	// 收尾：关闭远端应当让 Attach 返回
	if err := remote.Close(); err != nil {
		t.Fatalf("关闭远端失败: %v", err)
	}
	select {
	case <-attached:
	case <-time.After(stepTimeout):
		t.Fatal("远端关闭后 Attach 应当返回")
	}
}

// TestBridgeDeliversPacketsQueuedBeforeAttach 守住一条被依赖的性质：
// 连接接入之前网卡上读到的包会排队，并在接入后送达，而不是被丢弃。
//
// 这条性质是客户端启动顺序的前提——调用方装好路由之后内核会立刻开始往网卡
// 投包，而那时搬运往往还没接上；若这些包被丢弃，隧道建立后的最初若干秒会
// 出现无谓的丢包与重传。测试不需要任何时序假设：队列有容量，注入一定成功，
// 接入后队列必然被消费。
func TestBridgeDeliversPacketsQueuedBeforeAttach(t *testing.T) {
	// Arrange
	packets := testutil.NewMemPacketConn()
	b := mustBridge(t, packets)
	b.Start()

	remote := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = remote.Close() })

	early := []byte{0xC3, 0x03}
	if err := packets.Send(early); err != nil {
		t.Fatalf("向网卡注入包失败: %v", err)
	}

	// Act：此时才接入连接
	go b.Attach(remote)

	// Assert
	got, err := remote.Recv(stepTimeout)
	if err != nil {
		t.Fatalf("接入前写入网卡的包应当被送达新连接: %v", err)
	}
	if !bytes.Equal(got, early) {
		t.Fatalf("收到的包 = %x，期望 %x", got, early)
	}
}

// TestBridgeEndsSessionWhenPacketsDeviceFails 守住「网卡不可用时会话必须结束」。
//
// 网卡可能因为拆除流程（Teardown）而消失。此时若搬运继续挂在那里，调用方会
// 以为隧道还活着，而实际上已经没有通路——这种「看起来正常但发不出包」的
// 状态比直接断开更难排查。
func TestBridgeEndsSessionWhenPacketsDeviceFails(t *testing.T) {
	// Arrange
	packets := testutil.NewMemPacketConn()
	b := mustBridge(t, packets)
	b.Start()

	remote := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = remote.Close() })

	attached := make(chan struct{})
	go func() {
		b.Attach(remote)
		close(attached)
	}()

	// 先用一条回程包确认会话确实接上了，避免下面的断言依赖时序假设。
	if err := remote.Send([]byte{0x01}); err != nil {
		t.Fatalf("向远端注入包失败: %v", err)
	}
	if _, err := packets.Recv(stepTimeout); err != nil {
		t.Fatalf("会话未接上: %v", err)
	}

	// Act：销毁网卡
	if err := packets.Close(); err != nil {
		t.Fatalf("关闭网卡失败: %v", err)
	}

	// Assert：连接上再来一个包时写入网卡会失败，会话应当随之结束
	if err := remote.Send([]byte{0x02}); err != nil {
		t.Fatalf("向远端注入包失败: %v", err)
	}
	select {
	case <-attached:
	case <-time.After(stepTimeout):
		t.Fatal("网卡不可用后会话应当结束，否则调用方会误以为隧道仍然可用")
	}
}

func TestBridgeAttachReturnsWhenRemoteCloses(t *testing.T) {
	// Arrange
	packets := testutil.NewMemPacketConn()
	b := mustBridge(t, packets)
	b.Start()

	remote := testutil.NewMemPacketConn()
	attached := make(chan struct{})
	go func() {
		b.Attach(remote)
		close(attached)
	}()

	// Act
	if err := remote.Close(); err != nil {
		t.Fatalf("关闭远端失败: %v", err)
	}

	// Assert
	select {
	case <-attached:
	case <-time.After(stepTimeout):
		t.Fatal("远端关闭后 Attach 应当返回，否则会话信号量会被永久占住")
	}
}

func TestBridgeCloseUnblocksAttach(t *testing.T) {
	// Arrange
	packets := testutil.NewMemPacketConn()
	b := mustBridge(t, packets)
	b.Start()

	remote := testutil.NewMemPacketConn()
	t.Cleanup(func() { _ = remote.Close() })

	attached := make(chan struct{})
	go func() {
		b.Attach(remote)
		close(attached)
	}()

	// Act
	if err := b.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}

	// Assert
	select {
	case <-attached:
	case <-time.After(stepTimeout):
		t.Fatal("Bridge 关闭后 Attach 应当返回")
	}
}

func TestBridgeCloseIsIdempotent(t *testing.T) {
	// Arrange
	b := mustBridge(t, testutil.NewMemPacketConn())

	// Act & Assert
	for i := 0; i < 3; i++ {
		if err := b.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 返回错误: %v", i+1, err)
		}
	}
}

func TestBridgeAttachIgnoresNilRemote(t *testing.T) {
	// Arrange
	b := mustBridge(t, testutil.NewMemPacketConn())

	// Act：传入 nil 必须立即返回，而不是阻塞
	done := make(chan struct{})
	go func() {
		b.Attach(nil)
		close(done)
	}()

	// Assert
	select {
	case <-done:
	case <-time.After(stepTimeout):
		t.Fatal("传入 nil 时 Attach 应当立即返回")
	}
}

// fakeChannel 是实现 gossh.Channel 的最小替身，让 ChannelConn 的分帧与关闭语义
// 可以离线测试，无需真的建立 SSH 连接。
type fakeChannel struct {
	reader io.Reader
	writer io.Writer

	mu         sync.Mutex
	closeCount int
}

func (c *fakeChannel) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *fakeChannel) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *fakeChannel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCount++
	return nil
}

func (c *fakeChannel) CloseWrite() error { return nil }
func (c *fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *fakeChannel) Stderr() io.ReadWriter { return nil }

func (c *fakeChannel) closes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCount
}

var _ gossh.Channel = (*fakeChannel)(nil)

func TestChannelConnFramingRoundTrip(t *testing.T) {
	// Arrange
	var stream bytes.Buffer
	ch := &fakeChannel{reader: &stream, writer: &stream}
	conn := NewChannelConn(ch, nil)

	// Act：写入两个包再按顺序读回
	if err := conn.WritePacket([]byte("first")); err != nil {
		t.Fatalf("WritePacket 返回错误: %v", err)
	}
	if err := conn.WritePacket([]byte("second")); err != nil {
		t.Fatalf("WritePacket 返回错误: %v", err)
	}

	// Assert
	for _, want := range []string{"first", "second"} {
		got, err := conn.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket 返回错误: %v", err)
		}
		if string(got) != want {
			t.Fatalf("ReadPacket = %q，期望 %q", got, want)
		}
	}
}

// TestChannelConnCloseIsIdempotent 守住「channel.Close 不幂等」这条约束：
// Bridge 与调用方都可能触发关闭，重复关闭会多发一条 channelCloseMsg。
func TestChannelConnCloseIsIdempotent(t *testing.T) {
	// Arrange
	ch := &fakeChannel{reader: bytes.NewReader(nil), writer: io.Discard}
	onCloseCalls := 0
	conn := NewChannelConn(ch, func() error {
		onCloseCalls++
		return nil
	})

	// Act
	for i := 0; i < 3; i++ {
		if err := conn.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 返回错误: %v", i+1, err)
		}
	}

	// Assert
	if ch.closes() != 1 {
		t.Fatalf("底层 channel 被关闭 %d 次，期望恰好 1 次", ch.closes())
	}
	if onCloseCalls != 1 {
		t.Fatalf("onClose 被调用 %d 次，期望恰好 1 次", onCloseCalls)
	}
}

func TestChannelConnClosePropagatesOnCloseError(t *testing.T) {
	// Arrange：让 onClose 返回一个可识别的错误
	wantErr := errors.New("下层连接关闭失败")
	conn := NewChannelConn(
		&fakeChannel{reader: bytes.NewReader(nil), writer: io.Discard},
		func() error { return wantErr },
	)

	// Act
	err := conn.Close()

	// Assert
	if !errors.Is(err, wantErr) {
		t.Fatalf("错误 = %v，期望包含 %v", err, wantErr)
	}
}

func TestIsStreamClosedRecognizesNormalTermination(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"io.ErrClosedPipe", io.ErrClosedPipe, true},
		{"普通错误", errors.New("连接被重置"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := IsStreamClosed(tc.err)

			// Assert
			if got != tc.want {
				t.Fatalf("IsStreamClosed(%v) = %v，期望 %v", tc.err, got, tc.want)
			}
		})
	}
}
