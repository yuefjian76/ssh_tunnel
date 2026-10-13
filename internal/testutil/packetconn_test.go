package testutil

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// 本文件测试的是测试辅助本身。它不是可选的洁癖：MemPacketConn 若语义写错，
// 所有依赖它的隧道测试都会「通过」，但通过得毫无意义。

func TestMemPacketConnDeliversInjectedPackets(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	t.Cleanup(func() { _ = conn.Close() })
	want := []byte{1, 2, 3}

	// Act
	if err := conn.Send(want); err != nil {
		t.Fatalf("Send 返回错误: %v", err)
	}
	got, err := conn.ReadPacket()

	// Assert
	if err != nil {
		t.Fatalf("ReadPacket 返回错误: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadPacket = %v，期望 %v", got, want)
	}
}

// TestMemPacketConnCopiesOnWrite 守住契约要求的「不保留入参」：
// 调用方写完就复用自己的缓冲，辅助实现若不拷贝，断言会读到被改写后的内容。
func TestMemPacketConnCopiesOnWrite(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	t.Cleanup(func() { _ = conn.Close() })
	src := []byte{9, 9, 9}

	// Act
	if err := conn.WritePacket(src); err != nil {
		t.Fatalf("WritePacket 返回错误: %v", err)
	}
	src[0] = 0 // 模拟调用方复用写缓冲

	got, err := conn.Recv(time.Second)

	// Assert
	if err != nil {
		t.Fatalf("Recv 返回错误: %v", err)
	}
	if got[0] != 9 {
		t.Fatalf("WritePacket 应当拷贝入参，实际被后续改写污染为 %v", got)
	}
}

func TestMemPacketConnCopiesOnSend(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	t.Cleanup(func() { _ = conn.Close() })
	src := []byte{7, 7, 7}

	// Act
	if err := conn.Send(src); err != nil {
		t.Fatalf("Send 返回错误: %v", err)
	}
	src[0] = 0 // 测试自己复用缓冲

	got, err := conn.ReadPacket()

	// Assert
	if err != nil {
		t.Fatalf("ReadPacket 返回错误: %v", err)
	}
	if got[0] != 7 {
		t.Fatalf("Send 应当拷贝入参，实际被后续改写污染为 %v", got)
	}
}

func TestMemPacketConnCloseUnblocksRead(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	done := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacket()
		done <- err
	}()
	// 给读协程一点时间先进入阻塞，让本用例真正覆盖「Close 唤醒阻塞读」这条路径。
	time.Sleep(20 * time.Millisecond)

	// Act
	if err := conn.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}

	// Assert
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("错误 = %v，期望 net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close 之后 ReadPacket 应当立即返回")
	}
}

func TestMemPacketConnCloseIsIdempotent(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()

	// Act & Assert
	for i := 0; i < 3; i++ {
		if err := conn.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 返回错误: %v", i+1, err)
		}
	}
}

func TestMemPacketConnOperationsFailAfterClose(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	if err := conn.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"ReadPacket", func() error { _, err := conn.ReadPacket(); return err }},
		{"WritePacket", func() error { return conn.WritePacket([]byte{1}) }},
		{"Send", func() error { return conn.Send([]byte{1}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.call()

			// Assert
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("错误 = %v，期望 net.ErrClosed", err)
			}
		})
	}
}

func TestMemPacketConnRecvTimesOutWhenNothingWritten(t *testing.T) {
	// Arrange
	conn := NewMemPacketConn()
	t.Cleanup(func() { _ = conn.Close() })

	// Act
	_, err := conn.Recv(20 * time.Millisecond)

	// Assert
	if err == nil {
		t.Fatal("没有写入任何包时 Recv 应当超时报错")
	}
}
