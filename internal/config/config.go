// Package config 定义 client 与 server 两端的运行配置及其校验。
//
// Validate 一律不触碰文件系统或网络，只做纯逻辑校验，因此可以完全离线单测；
// 需要 I/O 的检查（密钥文件能否读、私钥能否解析）留到各自的加载函数里做，
// 以便把"配置写错了"和"环境有问题"这两类失败区分开。
package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// 默认值集中在此，避免常量散落成隐式约定（替代魔数）。
const (
	// DefaultListenAddr 只绑回环：入站通路走系统 sshd 的 direct-tcpip 转发，
	// 自研 server 无需也不可能暴露到公网。
	DefaultListenAddr = "127.0.0.1:8443"
	// DefaultServerAddr 是云端系统 sshd，该端口已在云安全组放行。
	DefaultServerAddr = "43.155.231.133:22"
	// DefaultServerUser 是外层 SSH 的登录用户名。
	//
	// 用户名在 SSH 协议里是公开的（会明文出现在握手中），不是机密，
	// 因此给出与实际主机一致且便于修改的默认值。
	DefaultServerUser = "ubuntu"
	// DefaultForwardAddr 是自研 server 在云主机上的监听地址，
	// 即外层 direct-tcpip 通道的目标。
	DefaultForwardAddr = "127.0.0.1:8443"
	// DefaultServerTunnelIP / DefaultClientTunnelIP 是隧道两端地址。
	DefaultServerTunnelIP = "10.9.0.1"
	DefaultClientTunnelIP = "10.9.0.2"
	// DefaultPrefixLen 是隧道网段掩码长度（10.9.0.0/24）。
	DefaultPrefixLen = 24
	// DefaultMTU 是隧道网卡 MTU，按双层 SSH 封装开销推算并留足余量。
	DefaultMTU = 1280
	// DefaultEgressIface 是服务端 MASQUERADE 的出接口。
	DefaultEgressIface = "eth0"
	// DefaultHostKeyPath 是服务端 SSH 主机密钥的存放位置。
	DefaultHostKeyPath = "~/.ssh-tunnel/hostkey"
	// DefaultKnownHostsPath 是校验外层主机密钥所用的 known_hosts。
	//
	// 复用系统 ssh 的同一个文件：用户平时就用 ssh 登录云主机，该文件里
	// 已经有其主机密钥，因此首次运行无需额外的信任引导步骤即可严格校验。
	DefaultKnownHostsPath = "~/.ssh/known_hosts"
)

// Server 是服务端运行所需的全部配置。
type Server struct {
	// ListenAddr 是自研 SSH server 的监听地址（host:port）。
	ListenAddr string
	// HostKeyPath 是 SSH 主机密钥路径；文件不存在时首次启动会自动生成。
	HostKeyPath string
	// AuthorizedKeysPaths 是允许登录的公钥文件列表（authorized_keys 格式）。
	AuthorizedKeysPaths []string
	// ServerTunnelIP 是服务端隧道网卡地址。
	ServerTunnelIP netip.Addr
	// ClientTunnelIP 是分配给客户端的隧道网卡地址。
	ClientTunnelIP netip.Addr
	// PrefixLen 是隧道网段掩码长度。
	PrefixLen int
	// MTU 是隧道网卡 MTU。
	MTU int
	// EgressIface 是 NAT 出接口，供 deploy 脚本生成 MASQUERADE 规则使用。
	EgressIface string
}

// Client 是客户端运行所需的全部配置。
type Client struct {
	// ServerAddr 是外层 SSH 的目标，即云端系统 sshd 的 host:port。
	ServerAddr string
	// User 是外层 SSH 的登录用户名。
	//
	// 只用于外层：系统 sshd 按此用户名查找 authorized_keys。内层连的是自研
	// server，它只认公钥白名单、不看用户名，但协议要求非空，故一并沿用。
	User string
	// ForwardAddr 是 direct-tcpip 通道的目标，即服务端上自研 server 的地址。
	ForwardAddr string
	// KeyPath 是用于两段 SSH 认证的私钥文件（.pem）。
	KeyPath string
	// KnownHostsPath 是校验外层主机密钥所用的 known_hosts 文件。
	KnownHostsPath string
	// ClientTunnelIP 是本端希望申请的隧道地址。
	ClientTunnelIP netip.Addr
	// PrefixLen 是隧道网段掩码长度，用于计算要加的路由。
	PrefixLen int
	// MTU 是本端建议的隧道 MTU。
	MTU int
	// TunName 是隧道网卡名。为空时由平台默认值决定
	// （macOS 用 "utun" 让内核分配编号，Linux 用 "ssh-tun0"）。
	TunName string
	// TakeDefaultRoute 为真时接管全部流量（0.0.0.0/1 + 128.0.0.0/1），
	// 为假时只建立到隧道对端的路由。
	TakeDefaultRoute bool
}

// DefaultServer 返回填充了默认值的服务端配置。
func DefaultServer() Server {
	return Server{
		ListenAddr:     DefaultListenAddr,
		HostKeyPath:    DefaultHostKeyPath,
		ServerTunnelIP: netip.MustParseAddr(DefaultServerTunnelIP),
		ClientTunnelIP: netip.MustParseAddr(DefaultClientTunnelIP),
		PrefixLen:      DefaultPrefixLen,
		MTU:            DefaultMTU,
		EgressIface:    DefaultEgressIface,
	}
}

// DefaultClient 返回填充了默认值的客户端配置。
//
// 注意 KeyPath 没有默认值：私钥位置因人而异，硬编码一个绝对路径只会在别人
// 机器上失败。它必须由命令行显式给出（见 cmd/client 的 -key）。
func DefaultClient() Client {
	return Client{
		ServerAddr:       DefaultServerAddr,
		User:             DefaultServerUser,
		ForwardAddr:      DefaultForwardAddr,
		KnownHostsPath:   DefaultKnownHostsPath,
		ClientTunnelIP:   netip.MustParseAddr(DefaultClientTunnelIP),
		PrefixLen:        DefaultPrefixLen,
		MTU:              DefaultMTU,
		TakeDefaultRoute: true,
	}
}

// TunnelPrefix 返回服务端配置对应的隧道网段。
func (c Server) TunnelPrefix() (netip.Prefix, error) {
	return prefixOf(c.ServerTunnelIP, c.PrefixLen)
}

// TunnelPrefix 返回客户端配置所请求的隧道网段。
func (c Client) TunnelPrefix() (netip.Prefix, error) {
	return prefixOf(c.ClientTunnelIP, c.PrefixLen)
}

func prefixOf(addr netip.Addr, bits int) (netip.Prefix, error) {
	if !addr.IsValid() {
		return netip.Prefix{}, fmt.Errorf("config: 隧道地址无效")
	}
	if bits < 0 || bits > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("config: 掩码长度 %d 对地址 %s 非法", bits, addr)
	}
	// Masked() 把主机位归零：netip.PrefixFrom 只负责把地址和掩码长度捆在一起，
	// 不做规范化，故 PrefixFrom(10.9.0.1, 24) 会打印成 "10.9.0.1/24"。
	// 本函数返回的是「网段」，调用方（路由、MASQUERADE -s 参数）都要求
	// 主机位为零的 "10.9.0.0/24"。
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// Validate 校验服务端配置。不做任何 I/O。
func (c Server) Validate() error {
	if err := validateHostPort("监听地址", c.ListenAddr); err != nil {
		return err
	}
	if strings.TrimSpace(c.HostKeyPath) == "" {
		return fmt.Errorf("config: 主机密钥路径不能为空")
	}
	if len(c.AuthorizedKeysPaths) == 0 {
		return fmt.Errorf("config: 至少需要一个 authorized_keys 文件，否则无人能登录")
	}
	for i, p := range c.AuthorizedKeysPaths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("config: 第 %d 个 authorized_keys 路径为空", i+1)
		}
	}

	prefix, err := c.TunnelPrefix()
	if err != nil {
		return err
	}
	if err := validateTunnelPair(prefix, c.ServerTunnelIP, c.ClientTunnelIP); err != nil {
		return err
	}
	if err := validateMTU(c.MTU); err != nil {
		return err
	}
	if strings.TrimSpace(c.EgressIface) == "" {
		return fmt.Errorf("config: NAT 出接口不能为空")
	}
	return nil
}

// Validate 校验客户端配置。不做任何 I/O。
func (c Client) Validate() error {
	if err := validateHostPort("服务端地址", c.ServerAddr); err != nil {
		return err
	}
	if err := validateHostPort("转发目标地址", c.ForwardAddr); err != nil {
		return err
	}
	if strings.TrimSpace(c.User) == "" {
		return fmt.Errorf("config: 登录用户名不能为空")
	}
	if strings.TrimSpace(c.KeyPath) == "" {
		return fmt.Errorf("config: 私钥路径不能为空")
	}
	if strings.TrimSpace(c.KnownHostsPath) == "" {
		return fmt.Errorf("config: known_hosts 路径不能为空")
	}
	if !c.ClientTunnelIP.IsValid() {
		return fmt.Errorf("config: 客户端隧道地址无效")
	}
	if _, err := c.TunnelPrefix(); err != nil {
		return err
	}
	return validateMTU(c.MTU)
}

// validateTunnelPair 确认两端隧道地址同族、互不相同，且都落在隧道网段内。
func validateTunnelPair(prefix netip.Prefix, serverIP, clientIP netip.Addr) error {
	if !serverIP.IsValid() {
		return fmt.Errorf("config: 服务端隧道地址无效")
	}
	if !clientIP.IsValid() {
		return fmt.Errorf("config: 客户端隧道地址无效")
	}
	if serverIP.Is4() != clientIP.Is4() {
		return fmt.Errorf("config: 隧道两端地址族不一致（%s 与 %s）", serverIP, clientIP)
	}
	if serverIP == clientIP {
		return fmt.Errorf("config: 隧道两端地址相同（%s）", serverIP)
	}
	if !prefix.Contains(serverIP) {
		return fmt.Errorf("config: 服务端地址 %s 不在隧道网段 %s 内", serverIP, prefix)
	}
	if !prefix.Contains(clientIP) {
		return fmt.Errorf("config: 客户端地址 %s 不在隧道网段 %s 内", clientIP, prefix)
	}
	return nil
}

func validateMTU(mtu int) error {
	if mtu < proto.MinMTU || mtu > proto.MaxMTU {
		return fmt.Errorf("config: MTU %d 超出允许范围 [%d, %d]",
			mtu, proto.MinMTU, proto.MaxMTU)
	}
	return nil
}

func validateHostPort(what, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("config: %s不能为空", what)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: %s %q 不是合法的 host:port: %w", what, addr, err)
	}
	if host == "" {
		return fmt.Errorf("config: %s %q 缺少主机部分", what, addr)
	}
	if port == "" {
		return fmt.Errorf("config: %s %q 缺少端口部分", what, addr)
	}
	return nil
}
