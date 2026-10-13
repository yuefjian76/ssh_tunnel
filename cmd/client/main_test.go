package main

import (
	"net/netip"
	"testing"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
	"github.com/yuefjian76/ssh_tunnel/internal/proto"
)

// TestParseFlagsMapsEveryFlag 逐个 flag 核对「参数确实落到了配置字段上」。
//
// 这类漏赋值编译器不会发现——flag 解析出来却忘了拷进 cfg，症状是参数静默失效
// （比如 -mtu 改了没用），排查起来很费时间。
func TestParseFlagsMapsEveryFlag(t *testing.T) {
	// Arrange
	args := []string{
		"-key", "/tmp/key.pem",
		"-server", "203.0.113.9:2222",
		"-user", "someone",
		"-forward", "127.0.0.1:9443",
		"-known-hosts", "/tmp/known_hosts",
		"-tun", "utun9",
		"-client-ip", "10.9.0.3",
		"-prefix-len", "16",
		"-mtu", "1400",
		"-take-default-route=false",
		"-log-level", "debug",
	}

	// Act
	cfg, logLevel, err := parseFlags(args)

	// Assert
	if err != nil {
		t.Fatalf("parseFlags 返回错误: %v", err)
	}
	if cfg.KeyPath != "/tmp/key.pem" {
		t.Fatalf("KeyPath = %q", cfg.KeyPath)
	}
	if cfg.ServerAddr != "203.0.113.9:2222" {
		t.Fatalf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.User != "someone" {
		t.Fatalf("User = %q", cfg.User)
	}
	if cfg.ForwardAddr != "127.0.0.1:9443" {
		t.Fatalf("ForwardAddr = %q", cfg.ForwardAddr)
	}
	if cfg.KnownHostsPath != "/tmp/known_hosts" {
		t.Fatalf("KnownHostsPath = %q", cfg.KnownHostsPath)
	}
	if cfg.TunName != "utun9" {
		t.Fatalf("TunName = %q", cfg.TunName)
	}
	if cfg.ClientTunnelIP != netip.MustParseAddr("10.9.0.3") {
		t.Fatalf("ClientTunnelIP = %s", cfg.ClientTunnelIP)
	}
	if cfg.PrefixLen != 16 {
		t.Fatalf("PrefixLen = %d", cfg.PrefixLen)
	}
	if cfg.MTU != 1400 {
		t.Fatalf("MTU = %d", cfg.MTU)
	}
	if cfg.TakeDefaultRoute {
		t.Fatal("TakeDefaultRoute 应为 false")
	}
	if logLevel != "debug" {
		t.Fatalf("logLevel = %q", logLevel)
	}
}

// TestParseFlagsDefaults 守住默认值：默认接管全部流量，且只有私钥是必填的。
func TestParseFlagsDefaults(t *testing.T) {
	// Act
	cfg, logLevel, err := parseFlags([]string{"-key", "/tmp/key.pem"})

	// Assert
	if err != nil {
		t.Fatalf("parseFlags 返回错误: %v", err)
	}
	if !cfg.TakeDefaultRoute {
		t.Fatal("默认应当接管全部流量")
	}
	if cfg.ServerAddr != config.DefaultServerAddr {
		t.Fatalf("ServerAddr = %q，期望默认值 %q", cfg.ServerAddr, config.DefaultServerAddr)
	}
	if logLevel != "info" {
		t.Fatalf("logLevel = %q，期望 info", logLevel)
	}
	// 私钥路径没有默认值：硬编码一个绝对路径只会在别人机器上失败。
	if cfg.KeyPath == "" {
		t.Fatal("私钥路径应当被记录")
	}
}

func TestParseFlagsRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"缺少私钥路径", nil},
		{"私钥路径为空串", []string{"-key", "  "}},
		{"服务端地址缺少端口", []string{"-key", "/tmp/key.pem", "-server", "203.0.113.9"}},
		{"隧道地址非法", []string{"-key", "/tmp/key.pem", "-client-ip", "不是地址"}},
		{"MTU 超出范围", []string{"-key", "/tmp/key.pem", "-mtu", "1"}},
		{"掩码长度非法", []string{"-key", "/tmp/key.pem", "-prefix-len", "64"}},
		{"未知参数", []string{"-key", "/tmp/key.pem", "-nope"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, _, err := parseFlags(tc.args)

			// Assert
			if err == nil {
				t.Fatal("非法参数应当被拒绝")
			}
		})
	}
}

func TestClientPlanUsesNegotiatedValues(t *testing.T) {
	// Arrange
	cfg := config.DefaultClient()
	cfg.KeyPath = "/tmp/key.pem"
	resp := proto.Response{
		Version:   proto.Version,
		ServerIP:  "10.9.0.1",
		ClientIP:  "10.9.0.2",
		PrefixLen: 24,
		MTU:       1280,
	}
	endpoint := netip.MustParseAddr("43.155.231.133")

	// Act
	plan := clientPlan(cfg, "utun7", endpoint, resp)

	// Assert
	if err := plan.Validate(); err != nil {
		t.Fatalf("生成的计划应当合法: %v", err)
	}
	if plan.DeviceName != "utun7" {
		t.Fatalf("DeviceName = %q", plan.DeviceName)
	}
	if plan.LocalIP.String() != "10.9.0.2" || plan.PrefixLen != 24 {
		t.Fatalf("隧道地址 = %s/%d", plan.LocalIP, plan.PrefixLen)
	}
	if plan.EndpointIP != endpoint {
		t.Fatalf("EndpointIP = %s", plan.EndpointIP)
	}
	if !plan.TakeDefaultRoute {
		t.Fatal("默认应当接管全部流量")
	}
	// MTU 留 0 表示「不改动」：网卡创建时已按协商结果设好。
	if plan.MTU != 0 {
		t.Fatalf("MTU = %d，期望 0（不改动网卡 MTU）", plan.MTU)
	}
}

// TestClientPlanFallsBackWhenClientIPUnparseable 守住「宁可报错也不要拿零值
// 地址去配置网卡」：零值地址会让 netcfg 装出一条毫无意义的 ::/0 规则。
func TestClientPlanFallsBackWhenClientIPUnparseable(t *testing.T) {
	// Arrange
	cfg := config.DefaultClient()
	cfg.KeyPath = "/tmp/key.pem"
	cfg.ClientTunnelIP = netip.MustParseAddr("10.9.0.7")
	resp := proto.Response{ClientIP: "不是地址", PrefixLen: 24}

	// Act
	plan := clientPlan(cfg, "utun7", netip.MustParseAddr("43.155.231.133"), resp)

	// Assert
	if plan.LocalIP != netip.MustParseAddr("10.9.0.7") {
		t.Fatalf("解析失败时应退回本端配置值，实际 %s", plan.LocalIP)
	}
}

// TestClientPlanWithoutDefaultRouteNeedsNoEndpoint 守住最小自查模式：
// 不接管默认路由时不需要防回环主机路由，因此也就不需要穿透目标地址。
func TestClientPlanWithoutDefaultRouteNeedsNoEndpoint(t *testing.T) {
	// Arrange
	cfg := config.DefaultClient()
	cfg.KeyPath = "/tmp/key.pem"
	cfg.TakeDefaultRoute = false
	resp := proto.Response{ClientIP: "10.9.0.2", PrefixLen: 24}

	// Act
	plan := clientPlan(cfg, "utun7", netip.Addr{}, resp)

	// Assert
	if err := plan.Validate(); err != nil {
		t.Fatalf("不接管默认路由时计划应当合法: %v", err)
	}
	if plan.TakeDefaultRoute {
		t.Fatal("TakeDefaultRoute 应随配置为 false")
	}
}
