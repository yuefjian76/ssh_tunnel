// Command client 是隧道客户端：通过双层 SSH 连到云主机，把本机流量以 IP 包的
// 形式送进隧道，并按需接管本机默认路由。
//
// 双层 SSH 的拓扑（详见 internal/sshclient）：
//
//	外层：本机 ──ssh(pem)──> 云主机系统 sshd :22（已放行）
//	        └── direct-tcpip ──> 127.0.0.1:8443
//	内层：在上一跳的裸字节流上再做一次 SSH 握手 ──> 自研 server
//	        └── channel "l3@ssh_tunnel" ──> 灌 IP 包
//
// 本进程会改动系统路由表（接管默认路由时）并创建隧道网卡，因此需要 root：
//
//	sudo ssh_tunnel_client -key ~/cloud/soer.pem
//
// 自查用最小命令：默认不做任何路由改动，只建立隧道并给网卡配上地址，
// 目的是先把「IP 包能否穿过双层 SSH」与「路由配置得对不对」分开验证。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/devtun"
	"github.com/yuefjian76/ssh_tunnel/internal/logging"
	"github.com/yuefjian76/ssh_tunnel/internal/netcfg"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
	"github.com/yuefjian76/ssh_tunnel/internal/sshclient"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		// -h 的用法说明已经由 flag 打印过了，那不是失败。
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "ssh_tunnel client: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, logLevel, err := parseFlags(args)
	if err != nil {
		return err
	}

	logger, err := logging.New(logLevel)
	if err != nil {
		return err
	}

	// 防回环路由必须针对一个确定的 IP，因此这里要求 -server 的主机部分是
	// IP 字面量。放在建网卡之前校验：配置错的就不该动系统状态。
	endpointIP, err := netcfg.ServerIPFromAddr(cfg.ServerAddr)
	if err != nil {
		return err
	}

	// 私钥与 known_hosts 都在建网卡之前加载：文件缺失、格式不对这类问题
	// 应当先暴露，而不是建完网卡再退出。
	signer, err := sshclient.LoadSigner(cfg.KeyPath)
	if err != nil {
		return err
	}
	hostKeyCallback, err := sshclient.KnownHostsCallback(cfg.KnownHostsPath)
	if err != nil {
		return err
	}

	device, err := devtun.Open(cfg.TunName, cfg.MTU)
	if err != nil {
		return fmt.Errorf("%w\n（创建隧道网卡需要 root：请用 sudo 运行）", err)
	}
	defer func() { _ = device.Close() }()

	client, err := sshclient.New(cfg, sshclient.Deps{
		Packets:         device,
		Signer:          signer,
		HostKeyCallback: hostKeyCallback,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// applied 在 onReady 里赋值，因此 Run 返回后一定要读它。
	// onReady 与 Run 在同一个 goroutine 上执行，无需加锁。
	//
	// 之所以要记住这个句柄：路由必须在**整个 Run 期间**保持不变——
	// 断线重连时增删路由会造成流量黑洞与路由震荡，所以 netcfg.Apply 只在
	// 首条会话建立时调用一次（见 Client.Run 的说明），撤销则统一放在这里。
	var applied *netcfg.Setup

	runErr := client.Run(ctx, func(resp proto.Response) error {
		logger.Info("隧道已建立，正在配置本机网络",
			"tun", device.Name(),
			"tunnel_ip", resp.ClientIP,
			"server_tunnel_ip", resp.ServerIP,
			"mtu", resp.MTU,
			"take_default_route", cfg.TakeDefaultRoute,
			"endpoint", endpointIP)

		setup, err := netcfg.Apply(clientPlan(cfg, device.Name(), endpointIP, resp), logger)
		if err != nil {
			return err
		}
		applied = setup
		return nil
	})

	// 先撤路由、再关网卡（defer）。反过来会让还指向这张网卡的流量在网卡消失后
	// 无处可去，表现为机器短暂失去网络。
	if applied != nil {
		if err := applied.Revert(logger); err != nil {
			// 已经把错误记进日志了，但退出码也必须体现——残留的路由会让用户
			// 处在「明明退出了却上不了网」的状态，不能悄悄返回成功。
			return err
		}
	}

	if runErr != nil {
		return runErr
	}
	logger.Info("隧道已关闭，本机网络配置已还原")
	return nil
}

// clientPlan 把一次成功的协商结果翻译成 netcfg 的执行计划。
//
// 地址与掩码长度取服务端应答里的值而不是本端配置里的值：应答才是权威，
// 且 sshclient 已校验过两者一致（见 checkResponse），这里用应答只是让
// 「以服务端为准」这件事在代码上更显眼。
func clientPlan(cfg config.Client, deviceName string, endpointIP netip.Addr, resp proto.Response) netcfg.Plan {
	plan := netcfg.Plan{
		DeviceName:       deviceName,
		PrefixLen:        resp.PrefixLen,
		TakeDefaultRoute: cfg.TakeDefaultRoute,
		EndpointIP:       endpointIP,
		// MTU 留 0：devtun 建网卡时已按服务端确认过的值设好，无需重复设置。
	}

	// 地址解析失败不该发生（握手时已校验过），但即便发生也不能让本端
	// 拿一个零值地址去配置网卡——那样会在网卡上装出一条 ::/0 之类的怪路由。
	// 此处退回本端配置值，Plan.Validate 会给出明确报错。
	if addr, err := netip.ParseAddr(resp.ClientIP); err == nil {
		plan.LocalIP = addr
	} else {
		plan.LocalIP = cfg.ClientTunnelIP
	}
	return plan
}

// parseFlags 解析命令行参数并做校验。独立的纯函数，便于单测。
func parseFlags(args []string) (config.Client, string, error) {
	cfg := config.DefaultClient()
	fs := flag.NewFlagSet("ssh_tunnel_client", flag.ContinueOnError)

	key := fs.String("key", "", "用于两段 SSH 认证的私钥文件（.pem）；必填")
	server := fs.String("server", cfg.ServerAddr, "外层 SSH 目标，即云端 sshd 的 host:port；主机部分必须是 IP 字面量")
	user := fs.String("user", cfg.User, "外层 SSH 登录用户名")
	forward := fs.String("forward", cfg.ForwardAddr, "direct-tcpip 的目标，即服务端上自研 server 的地址")
	knownHosts := fs.String("known-hosts", cfg.KnownHostsPath, "校验外层主机密钥用的 known_hosts 文件")
	tunName := fs.String("tun", "", "隧道网卡名；留空由平台决定（macOS 为 utun，由内核分配编号）")
	clientIP := fs.String("client-ip", cfg.ClientTunnelIP.String(), "本端隧道地址")
	prefixLen := fs.Int("prefix-len", cfg.PrefixLen, "隧道网段掩码长度")
	mtu := fs.Int("mtu", cfg.MTU, "隧道网卡 MTU；必须与服务端一致")
	takeDefault := fs.Bool("take-default-route", cfg.TakeDefaultRoute,
		"是否接管全部 IPv4 流量；设为 false 只建立隧道、不改动路由表，便于分步排查")
	logLevel := fs.String("log-level", "info", "日志级别：debug/info/warn/error")

	if err := fs.Parse(args); err != nil {
		return config.Client{}, "", err
	}

	cfg.KeyPath = *key
	cfg.ServerAddr = *server
	cfg.User = *user
	cfg.ForwardAddr = *forward
	cfg.KnownHostsPath = *knownHosts
	cfg.TunName = *tunName
	cfg.PrefixLen = *prefixLen
	cfg.MTU = *mtu
	cfg.TakeDefaultRoute = *takeDefault

	addr, err := netip.ParseAddr(*clientIP)
	if err != nil {
		return config.Client{}, "", fmt.Errorf("ssh_tunnel client: -client-ip %q 不是合法地址: %w", *clientIP, err)
	}
	cfg.ClientTunnelIP = addr

	if err := cfg.Validate(); err != nil {
		return config.Client{}, "", err
	}
	return cfg, *logLevel, nil
}
