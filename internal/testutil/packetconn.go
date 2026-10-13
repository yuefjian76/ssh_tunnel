// Package testutil 提供仅用于测试的辅助实现。
//
// 这里刻意不导入 testing 包：那会给任何链接到本包的二进制注册测试用的命令行
// 标志。因此辅助函数返回 error，由调用方决定是否 panic。
package testutil

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// memQueueSize 是内存端点两侧队列的深度，够测试用即可。
const memQueueSize = 64

// MemPacketConn 是内存版 proto.PacketConn，一次读写一个 IP 包。
//
// 它的存在是为了让整条隧道链路可以在不创建真实 tun 网卡（因而不需要 root）
// 的前提下端到端测试。两侧语义与真实设备一致：
//   - ReadPacket 取出测试通过 Send 注入的包（模拟「网卡上收到了包」）
//   - WritePacket 把包交给测试通过 Recv 取出（模拟「代码往网卡写包」）
type MemPacketConn struct {
	in        chan []byte
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

// NewMemPacketConn 创建一个内存端点。
func NewMemPacketConn() *MemPacketConn {
	return &MemPacketConn{
		in:     make(chan []byte, memQueueSize),
		out:    make(chan []byte, memQueueSize),
		closed: make(chan struct{}),
	}
}

// ReadPacket 取出一个由 Send 注入的包。端点关闭后返回 net.ErrClosed。
func (m *MemPacketConn) ReadPacket() ([]byte, error) {
	if err := m.closedErr(); err != nil {
		return nil, err
	}
	select {
	case <-m.closed:
		return nil, net.ErrClosed
	case pkt := <-m.in:
		return pkt, nil
	}
}

// WritePacket 交出一个包。按契约拷贝，因此调用方可以立即复用 pkt。
func (m *MemPacketConn) WritePacket(pkt []byte) error {
	return m.deliver(m.out, pkt)
}

// Close 关闭端点。重复调用是安全的。
func (m *MemPacketConn) Close() error {
	m.closeOnce.Do(func() { close(m.closed) })
	return nil
}

// Send 由测试调用，模拟「隧道网卡上收到了这个包」。
func (m *MemPacketConn) Send(pkt []byte) error {
	return m.deliver(m.in, pkt)
}

// deliver 把包投入队列，若端点已关闭则返回 net.ErrClosed。
//
// 关闭检查必须**先**单独做一次、且不带 default 之外的其它就绪分支：
// 若把 `<-m.closed` 和队列发送放进同一个 select，两者在队列有剩余容量时
// 会同时就绪，Go 随机挑一个分支，于是「关闭后写入」会时灵时不灵——
// 这种不确定性会传导到所有使用本辅助的测试，表现为偶发失败。
func (m *MemPacketConn) deliver(queue chan []byte, pkt []byte) error {
	if err := m.closedErr(); err != nil {
		return err
	}

	clone := make([]byte, len(pkt))
	copy(clone, pkt)

	select {
	case <-m.closed:
		return net.ErrClosed
	case queue <- clone:
		return nil
	}
}

// closedErr 在端点已关闭时返回 net.ErrClosed，否则返回 nil。
func (m *MemPacketConn) closedErr() error {
	select {
	case <-m.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

// Recv 由测试调用，取出被测代码写出的一个包；超过 timeout 未等到则报错。
//
// 用超时而非无限等待：这样断言失败时测试会给出「没等到包」这一明确结论，
// 而不是挂到 go test 的整体超时、看不出失败原因。
func (m *MemPacketConn) Recv(timeout time.Duration) ([]byte, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case pkt := <-m.out:
		return pkt, nil
	case <-timer.C:
		return nil, fmt.Errorf("testutil: 在 %s 内没有等到写出的包", timeout)
	}
}
