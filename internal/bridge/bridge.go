// Package bridge 在「长期存在的隧道网卡」与「短期的隧道连接」之间搬运 IP 包。
//
// 它解决的是一个具体的结构问题：隧道网卡必须跨越断线重连存活——重建网卡会拿到
// 新的 utun 编号、连带丢掉已配置的路由，因此在网卡上读包的循环也只能有唯一一个、
// 常驻不退出。连接侧则可以来去自由：每次连接接入时消费网卡读到的包，断开时停止消费。
//
// server 与 client 两端都需要这套结构，故抽到此处共用。
package bridge

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// DefaultQueueSize 是「网卡 → 当前连接」队列的默认深度。
// 连接缺席时队列填满即形成背压，让网卡读循环阻塞，而不是无限堆积包。
const DefaultQueueSize = 64

// Bridge 在隧道网卡与当前接入的连接之间搬运包。
//
// 生命周期约定：Bridge 不拥有 packets，Close 不会关闭它。调用方关闭网卡后，
// 读循环才会从阻塞中退出——这也是进程退出时的正常收尾顺序。
type Bridge struct {
	packets proto.PacketConn
	log     *slog.Logger

	in        chan []byte
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

// New 构造 Bridge。queueSize 必须为正数，见 DefaultQueueSize。
func New(packets proto.PacketConn, queueSize int, log *slog.Logger) (*Bridge, error) {
	if packets == nil {
		return nil, fmt.Errorf("bridge: 缺少隧道网卡")
	}
	if queueSize <= 0 {
		return nil, fmt.Errorf("bridge: 队列深度 %d 必须为正数", queueSize)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Bridge{
		packets: packets,
		log:     log,
		in:      make(chan []byte, queueSize),
		done:    make(chan struct{}),
	}, nil
}

// Start 启动常驻的网卡读循环。重复调用只生效一次。
func (b *Bridge) Start() {
	b.startOnce.Do(func() { go b.readFromPackets() })
}

// Attach 把一条隧道连接接入，双向往返搬运，直到它断开或 Bridge 被关闭。
// 该调用会阻塞，直到连接结束。
func (b *Bridge) Attach(remote proto.PacketConn) {
	if remote == nil {
		return
	}

	stop := make(chan struct{})
	var once sync.Once
	// 任一方向结束时关闭连接：另一方向正阻塞在 remote.ReadPacket 上，
	// 只有连接被关闭才能让它返回，否则 wg.Wait() 永不返回。
	finish := func() {
		once.Do(func() {
			close(stop)
			if err := remote.Close(); err != nil {
				b.log.Debug("关闭隧道连接时出错", "err", err)
			}
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer finish()
		b.remoteToPackets(remote)
	}()
	go func() {
		defer wg.Done()
		defer finish()
		b.packetsToRemote(remote, stop)
	}()
	wg.Wait()
}

// Close 停止 Bridge。可重复调用。不会关闭底层网卡。
func (b *Bridge) Close() error {
	b.closeOnce.Do(func() { close(b.done) })
	return nil
}

// readFromPackets 是常驻的网卡读循环，把包投递给当前连接。
//
// 没有连接接入时读到的包一律入队（队列满则阻塞，形成背压），不做任何
// 「无连接就丢弃」的过滤。这个选择是权衡后的结果，理由值得写下来，
// 免得日后有人凭直觉把它改回丢弃：
//
//   - 队列有界（DefaultQueueSize），因此连接缺席期间积压的包至多这么多，
//     不存在无限堆积；
//   - 残留包被投给新连接时的实际影响由内核兜住——匹配不上任何 socket 的包
//     会被丢弃，而依然存活的 TCP 连接收到的晚到报文仍是有效数据；
//   - 反过来，「无连接就丢弃」要求调用方严格遵守「先接入、再产生流量」的
//     时序：调用方在装好路由之后内核会立刻开始往网卡投包，那些包会撞上
//     这个窗口被静默丢弃。为了消掉至多几十个包而引入一条隐式的时序约束，
//     不划算。
func (b *Bridge) readFromPackets() {
	for {
		pkt, err := b.packets.ReadPacket()
		if err != nil {
			if b.isClosed() {
				return // 正常关闭：关闭网卡导致读失败是预期行为
			}
			b.log.Error("从隧道网卡读包失败，读循环已退出", "err", err)
			return
		}

		// 必须拷贝：proto.PacketConn 的契约允许 ReadPacket 复用内部缓冲，
		// 而包一旦入队就会跨越下一次 ReadPacket。
		payload := make([]byte, len(pkt))
		copy(payload, pkt)

		select {
		case b.in <- payload:
		case <-b.done:
			return
		}
	}
}

// remoteToPackets 把连接上收到的包写进隧道网卡。
func (b *Bridge) remoteToPackets(remote proto.PacketConn) {
	for {
		pkt, err := remote.ReadPacket()
		if err != nil {
			LogStreamEnd(b.log, "隧道连接读取结束", err)
			return
		}
		if err := b.packets.WritePacket(pkt); err != nil {
			b.log.Warn("写入隧道网卡失败", "err", err)
			return
		}
	}
}

// packetsToRemote 把网卡读到的包发给连接。
func (b *Bridge) packetsToRemote(remote proto.PacketConn, stop <-chan struct{}) {
	for {
		select {
		case <-b.done:
			return
		case <-stop:
			return
		case pkt := <-b.in:
			if err := remote.WritePacket(pkt); err != nil {
				LogStreamEnd(b.log, "隧道连接写入结束", err)
				return
			}
		}
	}
}

func (b *Bridge) isClosed() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// ChannelConn 把 SSH channel 适配为 proto.PacketConn，载荷走 proto 的长度前缀帧。
type ChannelConn struct {
	ch        gossh.Channel
	onClose   func() error
	closeOnce sync.Once
	// readBuf 是复用的读缓冲。隧道数据面每一跳都经过这里，逐包分配会在
	// 大流量下持续产生垃圾。复用满足 proto.PacketConn 的契约（返回的切片
	// 仅在下一次 ReadPacket 之前有效）；目前唯一的消费者 Bridge 在读到包后
	// 立刻消费掉（拷贝进队列或写进网卡），不会跨调用持有。
	readBuf []byte
}

// NewChannelConn 包装一个 SSH channel。onClose 可为 nil；非 nil 时会在 Close 里
// 被调用一次，用于一并释放 channel 背后的 SSH 连接。
func NewChannelConn(ch gossh.Channel, onClose func() error) *ChannelConn {
	return &ChannelConn{ch: ch, onClose: onClose}
}

// ReadPacket 从 channel 读一帧。
//
// 返回的切片可能指向内部缓冲区，仅在下一次调用 ReadPacket 之前有效——
// 这与 proto.PacketConn 的契约一致。
func (c *ChannelConn) ReadPacket() ([]byte, error) {
	pkt, err := proto.ReadFrame(c.ch, c.readBuf)
	if err != nil {
		return nil, err
	}
	// 收回长度、保留容量，供下一轮复用；ReadFrame 若因容量不足而重新分配，
	// 这里也会随之切换到新缓冲。
	c.readBuf = pkt[:0]
	return pkt, nil
}

// WritePacket 把包作为一帧写入 channel。
func (c *ChannelConn) WritePacket(pkt []byte) error {
	return proto.WriteFrame(c.ch, pkt)
}

// Close 关闭 channel 并调用 onClose。可重复调用。
//
// 必须保证只关一次：channel.Close 不幂等，每次调用都会再发一条
// channelCloseMsg。而 Bridge 与调用方都可能触发关闭，这里用 sync.Once 兜住。
func (c *ChannelConn) Close() error {
	var errs []error
	c.closeOnce.Do(func() {
		if err := c.ch.Close(); err != nil {
			errs = append(errs, fmt.Errorf("bridge: 关闭 SSH channel 失败: %w", err))
		}
		if c.onClose != nil {
			if err := c.onClose(); err != nil {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

// LogStreamEnd 区分「对端正常关闭」与「真的出错」。
// 每次断线都会走到这里，若一律记 Warn，日志会被正常断线刷满。
func LogStreamEnd(log *slog.Logger, what string, err error) {
	if IsStreamClosed(err) {
		log.Debug(what, "err", err)
		return
	}
	log.Warn(what, "err", err)
}

// IsStreamClosed 判断错误是否表示「流已正常终结」而非异常。
func IsStreamClosed(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}
