// Package devtun 封装 golang.zx2c4.com/wireguard/tun，向上提供「一次一个 IP 包」
// 的读写接口，把该库的批量语义与平台差异收拢在这里。
//
// 之所以要封装：底层库的 Read/Write 是批量接口（返回包个数而非字节数），
// 且 macOS 的 utun 在每个包前面有一个 4 字节地址族头、库把它藏在 offset 参数之前。
// 这些细节一旦泄漏到隧道逻辑里，就会出现难查的 offset 错误。
package devtun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// 编译期确认 Device 满足隧道端点契约，防止方法签名漂移后到运行期才发现。
var _ proto.PacketConn = (*Device)(nil)

// packetOffset 是平台头部需要预留的字节数。
//
// macOS 的 utun 在每个包的载荷前有一个 4 字节地址族头，库把它藏在 offset 之前：
// Read 会写 bufs[0][offset-4:]，Write 在 offset < 4 时直接返回 io.ErrShortBuffer。
// Linux 允许 offset 为 0。统一取 16（与 wireguard-go 自身一致）以保证跨平台可移植。
const packetOffset = 16

// Device 是一条已创建的隧道网卡。
//
// 它持有操作系统资源句柄，内部读写缓冲会被后续调用复用——因此它不是值对象，
// 不适用「不可变」原则。复用缓冲是为了避免在每包热路径上分配内存；
// 这些缓冲不会外泄给调用方以外的作用域（见 Read 的返回值约定）。
//
// Device 不是并发安全的：Read 与 Write 各自绑定单一 goroutine（分别对应
// 「隧道→网卡」与「网卡→隧道」两个方向）。Close 可由第三个 goroutine 调用。
type Device struct {
	dev  tun.Device
	name string
	mtu  int

	// 读方向的复用缓冲。readBufs 恒为单元素，因为本封装每次只交付一个包。
	readBuf   []byte
	readBufs  [][]byte
	readSizes []int

	// 写方向的复用缓冲。
	writeBuf  []byte
	writeBufs [][]byte
}

// Open 创建隧道网卡。需要 root 或 CAP_NET_ADMIN。
//
// name 为空时使用平台默认名：macOS 用 "utun" 让内核分配下一个可用编号，
// Linux 用 "ssh-tun0"。macOS 上 name 必须是 "utun" 或 "utun<数字>"，否则内核拒绝。
// 通过 name 请求的名字与实际名字可能不同（"utun" 会被内核解析成具体的 utunN），
// 因此调用方必须用 Name() 获取真实名字，不可自行推断。
func Open(name string, mtu int) (*Device, error) {
	if mtu <= 0 {
		return nil, fmt.Errorf("devtun: MTU %d 必须为正数", mtu)
	}
	if name == "" {
		name = defaultDeviceName()
	}

	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("devtun: 创建隧道网卡 %q 失败（需要 root 或 CAP_NET_ADMIN）: %w", name, err)
	}

	realName, err := dev.Name()
	if err != nil {
		// 已经创建的内核接口必须回收，否则会留下一个悬空的 utun。
		_ = dev.Close()
		return nil, fmt.Errorf("devtun: 读取隧道网卡真实名称失败: %w", err)
	}
	realMTU, err := dev.MTU()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("devtun: 读取隧道网卡 %s 的 MTU 失败: %w", realName, err)
	}

	// 缓冲要能容纳「平台头部 + 一个整包」。
	bufLen := packetOffset + realMTU
	d := &Device{
		dev:       dev,
		name:      realName,
		mtu:       realMTU,
		readBuf:   make([]byte, bufLen),
		readSizes: make([]int, 1),
		writeBuf:  make([]byte, bufLen),
	}
	d.readBufs = [][]byte{d.readBuf}
	d.writeBufs = [][]byte{d.writeBuf}
	return d, nil
}

// ReadPacket 读取一个 IP 包。
//
// 返回的切片复用内部缓冲，仅在下一次 ReadPacket 之前有效；调用方若需留存必须自行拷贝。
// 该调用会阻塞直到有包可读、设备被关闭或出错。
func (d *Device) ReadPacket() ([]byte, error) {
	n, err := d.dev.Read(d.readBufs, d.readSizes, packetOffset)
	if err != nil {
		return nil, err
	}
	return packetSlice(d.readBuf, n, d.readSizes[0])
}

// WritePacket 写入一个 IP 包。
//
// 包体会被拷入内部缓冲：库要求载荷前预留 packetOffset 字节供平台头部使用，
// 而调用方传进来的切片没有这段余量。因为做了拷贝，返回后调用方可以复用 pkt。
func (d *Device) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return fmt.Errorf("devtun: 拒绝写入空包")
	}
	if len(pkt) > d.mtu {
		return fmt.Errorf("devtun: 包长 %d 超过隧道 MTU %d", len(pkt), d.mtu)
	}

	copy(d.writeBuf[packetOffset:], pkt)
	// 切片必须从索引 0 开始：库内部以 buf[offset-4:] 定位，
	// 并要求 buf[offset] 正好是包的首字节。
	d.writeBufs[0] = d.writeBuf[:packetOffset+len(pkt)]

	n, err := d.dev.Write(d.writeBufs, packetOffset)
	if err != nil {
		return fmt.Errorf("devtun: 写入隧道网卡 %s 失败: %w", d.name, err)
	}
	if n != 1 {
		return fmt.Errorf("devtun: 期望写入 1 个包，库实际写入 %d 个", n)
	}
	return nil
}

// Name 返回内核分配的真实网卡名（如 macOS 上的 "utun4"）。
func (d *Device) Name() string { return d.name }

// MTU 返回网卡的实际 MTU。
func (d *Device) MTU() int { return d.mtu }

// Close 关闭网卡。重复调用是安全的。
func (d *Device) Close() error {
	if err := d.dev.Close(); err != nil {
		return fmt.Errorf("devtun: 关闭隧道网卡 %s 失败: %w", d.name, err)
	}
	return nil
}

// packetSlice 把底层库的读取结果映射为载荷在缓冲中的位置。
//
// 抽成纯函数是为了可离线单测：offset 与长度的算术是本包最容易出 off-by-one 的
// 地方，而 Open/Read 本身需要 root 才能跑起来。
//
// n 是库返回的包个数，size 是 sizes[0]。按 tun.Device 的约定，size 已剔除
// 平台头部，载荷正好位于 buf[packetOffset : packetOffset+size]。
func packetSlice(buf []byte, n, size int) ([]byte, error) {
	if n == 0 {
		// 库在「读到不足 4 字节的高位头部」时会返回 (0, nil)。
		// 直接把它当成错误而非返回空包，避免调用方空转成死循环。
		return nil, fmt.Errorf("devtun: 底层读取返回 0 个包且无错误，设备状态异常")
	}
	if size <= 0 {
		return nil, fmt.Errorf("devtun: 底层返回长度为 %d 的畸形包", size)
	}
	if packetOffset+size > len(buf) {
		// 库自身应当保证不会越界；这里是防御性检查，把潜在的 panic 变成明确错误。
		return nil, fmt.Errorf("devtun: 包长 %d 超出缓冲容量 %d（疑似库行为异常）",
			size, len(buf)-packetOffset)
	}
	return buf[packetOffset : packetOffset+size], nil
}
