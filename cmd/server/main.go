// Command server 是隧道服务端：在云主机上创建隧道网卡、监听自研 SSH 端口，
// 把客户端送来的 IP 包写进网卡，并向客户端回送网卡上收到的包。
//
// 它**只**负责这些。NAT 与转发开关属于一次性系统配置，由 deploy/install.sh
// 完成——这样常驻进程不需要在运行时改 iptables/sysctl，权限面更小，
// 也不会与主机上既有的规则相互干扰。
//
// 用法示例：
//
//	sudo ssh_tunnel_server -listen 127.0.0.1:8443
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/devtun"
	"github.com/yuefjian76/ssh_tunnel/internal/logging"
	"github.com/yuefjian76/ssh_tunnel/internal/netcfg"
	"github.com/yuefjian76/ssh_tunnel/internal/sshserver"
)

// defaultAuthorizedKeys 是公钥白名单的默认来源。
//
// 直接用系统 sshd 的同一个文件：客户端用的私钥本就是登录云主机的那把，
// 其公钥已经在里面，因此首次部署无需额外的分发步骤。这也不会扩大权限面——
// 能写这个文件的人本来就能直接登录主机。
const defaultAuthorizedKeys = "~/.ssh/authorized_keys"

func main() {
	if err := run(os.Args[1:]); err != nil {
		// -h 的用法说明已经由 flag 打印过了，那不是失败。
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "ssh_tunnel server: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, tunName, logLevel, err := parseFlags(args)
	if err != nil {
		return err
	}

	logger, err := logging.New(logLevel)
	if err != nil {
		return err
	}

	// 先加载密钥：这类失败（文件缺失、格式不对）应当在创建网卡之前就暴露，
	// 否则建完网卡又退出，留下一堆无意义的系统状态变更记录。
	hostKey, err := sshserver.LoadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		return err
	}
	allowed, err := sshserver.LoadAuthorizedKeys(cfg.AuthorizedKeysPaths)
	if err != nil {
		return err
	}

	device, err := devtun.Open(tunName, cfg.MTU)
	if err != nil {
		return err
	}

	// 给网卡配上隧道地址。没有地址的网卡收不下也发不出 IP 包——这条命令是
	// 服务端唯一需要改动的系统网络状态。
	//
	// 刻意不接管默认路由：出网靠的是 deploy/install.sh 装好的转发开关与
	// MASQUERADE 规则，本进程不碰路由表，因此也不存在回环风险。
	netSetup, err := netcfg.Apply(netcfg.Plan{
		DeviceName: device.Name(),
		LocalIP:    cfg.ServerTunnelIP,
		PrefixLen:  cfg.PrefixLen,
		// MTU 留 0：devtun 建网卡时已经设好，重复设置只会多一次命令。
	}, logger)
	if err != nil {
		_ = device.Close()
		return err
	}
	defer func() { _ = netSetup.Revert(logger) }()

	deps := sshserver.Deps{
		Packets:     device,
		HostKey:     hostKey,
		AllowedKeys: allowed,
		Logger:      logger,
	}
	srv, err := sshserver.New(cfg, deps)
	if err != nil {
		// 此时网卡所有权尚未转移给 Server，由本处负责收拾
		// （netSetup 由上面的 defer 撤销，无需在这里重复处理）。
		_ = device.Close()
		return err
	}
	// 此后网卡由 Server 负责关闭，这里不再单独关一次。
	defer func() { _ = srv.Close() }()

	logger.Info("隧道服务端已启动",
		"tun", device.Name(),
		"tun_ip", cfg.ServerTunnelIP,
		"mtu", cfg.MTU,
		"tunnel_ip", cfg.ServerTunnelIP,
		"client_ip", cfg.ClientTunnelIP,
		"prefix_len", cfg.PrefixLen)
	logger.Info("提示：本进程只给隧道网卡配地址，不改动路由表；出网所需的 ip_forward "+
		"与 MASQUERADE 由 deploy/install.sh 负责。若尚未执行过该脚本，客户端能连上"+
		"但无法经本机出网",
		"egress_iface", cfg.EgressIface, "tunnel_prefix", cfg.ServerTunnelIP.String())

	// 收到 SIGINT/SIGTERM 时关闭服务端，让 ListenAndServe 正常返回。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Info("收到退出信号，正在关闭")
		_ = srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil {
		return err
	}
	logger.Info("隧道服务端已停止")
	return nil
}

// parseFlags 解析命令行参数并做校验。独立的纯函数，便于单测。
func parseFlags(args []string) (config.Server, string, string, error) {
	cfg := config.DefaultServer()
	fs := flag.NewFlagSet("ssh_tunnel_server", flag.ContinueOnError)

	listen := fs.String("listen", cfg.ListenAddr,
		"自研 SSH server 的监听地址。默认只绑回环：入站通路走系统 sshd 的 direct-tcpip 转发，无需暴露公网")
	tunName := fs.String("tun", "", "隧道网卡名；留空则由平台决定（Linux: ssh-tun0）")
	hostKey := fs.String("host-key", cfg.HostKeyPath, "SSH 主机密钥路径；不存在时首次启动自动生成")
	authorizedKeys := fs.String("authorized-keys", defaultAuthorizedKeys,
		"允许建立隧道的公钥白名单，authorized_keys 格式；多个文件用逗号分隔")
	serverIP := fs.String("server-ip", cfg.ServerTunnelIP.String(), "服务端隧道网卡地址")
	clientIP := fs.String("client-ip", cfg.ClientTunnelIP.String(), "分配给客户端的隧道网卡地址")
	prefixLen := fs.Int("prefix-len", cfg.PrefixLen, "隧道网段掩码长度")
	mtu := fs.Int("mtu", cfg.MTU, "隧道网卡 MTU；必须与客户端一致")
	egressIface := fs.String("egress-iface", cfg.EgressIface,
		"NAT 出接口；仅用于生成 deploy 脚本里的 MASQUERADE 规则，本进程不使用")
	logLevel := fs.String("log-level", "info", "日志级别：debug/info/warn/error")

	if err := fs.Parse(args); err != nil {
		return config.Server{}, "", "", err
	}

	cfg.ListenAddr = *listen
	cfg.HostKeyPath = *hostKey
	cfg.AuthorizedKeysPaths = splitCommaList(*authorizedKeys)
	cfg.PrefixLen = *prefixLen
	cfg.MTU = *mtu
	cfg.EgressIface = *egressIface

	var err error
	if cfg.ServerTunnelIP, err = parseAddr("server-ip", *serverIP); err != nil {
		return config.Server{}, "", "", err
	}
	if cfg.ClientTunnelIP, err = parseAddr("client-ip", *clientIP); err != nil {
		return config.Server{}, "", "", err
	}
	if err := cfg.Validate(); err != nil {
		return config.Server{}, "", "", err
	}
	return cfg, *tunName, *logLevel, nil
}

func parseAddr(flagName, value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ssh_tunnel server: -%s %q 不是合法地址: %w", flagName, value, err)
	}
	return addr, nil
}

// splitCommaList 拆分逗号分隔的列表，并去掉空白项。
func splitCommaList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
