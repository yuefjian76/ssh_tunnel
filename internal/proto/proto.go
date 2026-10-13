// Package proto 定义 L3 SSH channel 上承载的线协议：一次性的隧道参数协商
// （handshake），以及用于承载原始 IP 包的长度前缀帧（framing）。
//
// 这里只有纯逻辑，不触碰网络或系统调用，因此可以完全离线单测。
package proto

import (
	"fmt"
	"net/netip"
)

const (
	// ChannelType 是承载 L3 隧道的 SSH channel 类型名。
	ChannelType = "l3@ssh_tunnel"

	// Version 是协议版本号。任何不兼容的改动都必须递增它，
	// 双端据此拒绝握手，避免新旧版本静默地互说胡话。
	Version = 1

	// HeaderSize 是帧长度前缀的宽度（大端 uint32）。
	HeaderSize = 4

	// MaxFrameSize 限制单个解码帧的长度。隧道 MTU 远小于此值，
	// 这个上限唯一的作用是在分配内存之前就拒掉畸形或恶意的长度前缀。
	MaxFrameSize = 1 << 16
)

// Request 是客户端在打开 channel 时作为 payload 携带的协商请求。
//
// 用 JSON 而非紧凑二进制编码：每个连接只在建立时交换一次，
// 这点开销可以忽略，换来的是可读性与易调试性（KISS）。
type Request struct {
	// Version 是客户端支持的协议版本。
	Version int `json:"version"`
	// ClientIP 是客户端希望为本端隧道网卡申请的地址。
	ClientIP string `json:"client_ip"`
	// MTU 是客户端建议的隧道 MTU。
	MTU int `json:"mtu"`
}

// Response 是服务端在 channel 建立后回写的第一帧，表示协商结果。
type Response struct {
	// Version 是服务端最终采用的协议版本。
	Version int `json:"version"`
	// ServerIP 是服务端隧道网卡的地址。
	ServerIP string `json:"server_ip"`
	// ClientIP 是为客户端分配的隧道网卡地址。
	ClientIP string `json:"client_ip"`
	// PrefixLen 是隧道网段的掩码长度。
	PrefixLen int `json:"prefix_len"`
	// MTU 是服务端最终确定的隧道 MTU。
	MTU int `json:"mtu"`
}

// TunnelPrefix 返回隧道所在网段，用于生成路由与 MASQUERADE 规则。
//
// 必须调用 Masked()：netip.PrefixFrom 只把地址和掩码长度捆在一起、
// 不规范化主机位，故 PrefixFrom(10.9.0.1, 24) 会打印成 "10.9.0.1/24"。
// 而这个值的用途是「网段」——iptables 的 -s 与路由的目标网络都要求
// 主机位归零，即 "10.9.0.0/24"。
func (r Response) TunnelPrefix() (netip.Prefix, error) {
	addr, err := netip.ParseAddr(r.ServerIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("proto: 解析服务端隧道地址 %q 失败: %w", r.ServerIP, err)
	}
	if r.PrefixLen < 0 || r.PrefixLen > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("proto: 掩码长度 %d 对地址 %s 非法", r.PrefixLen, addr)
	}
	return netip.PrefixFrom(addr, r.PrefixLen).Masked(), nil
}
