package main

import (
	"net/netip"
	"testing"

	"github.com/yuefjian76/ssh_tunnel/internal/config"
)

func TestParseFlagsMapsEveryFlag(t *testing.T) {
	// Arrange
	args := []string{
		"-listen", "127.0.0.1:9443",
		"-tun", "ssh-tun9",
		"-host-key", "/tmp/hostkey",
		"-authorized-keys", "/tmp/a_keys, /tmp/b_keys",
		"-server-ip", "10.9.0.1",
		"-client-ip", "10.9.0.2",
		"-prefix-len", "24",
		"-mtu", "1400",
		"-egress-iface", "ens5",
		"-log-level", "warn",
	}

	// Act
	cfg, tunName, logLevel, err := parseFlags(args)

	// Assert
	if err != nil {
		t.Fatalf("parseFlags 返回错误: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9443" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if tunName != "ssh-tun9" {
		t.Fatalf("tunName = %q", tunName)
	}
	if cfg.HostKeyPath != "/tmp/hostkey" {
		t.Fatalf("HostKeyPath = %q", cfg.HostKeyPath)
	}
	// 逗号分隔的列表要拆分并去掉空白，否则路径会带上空格而找不到文件。
	if len(cfg.AuthorizedKeysPaths) != 2 ||
		cfg.AuthorizedKeysPaths[0] != "/tmp/a_keys" ||
		cfg.AuthorizedKeysPaths[1] != "/tmp/b_keys" {
		t.Fatalf("AuthorizedKeysPaths = %q", cfg.AuthorizedKeysPaths)
	}
	if cfg.ServerTunnelIP != netip.MustParseAddr("10.9.0.1") {
		t.Fatalf("ServerTunnelIP = %s", cfg.ServerTunnelIP)
	}
	if cfg.ClientTunnelIP != netip.MustParseAddr("10.9.0.2") {
		t.Fatalf("ClientTunnelIP = %s", cfg.ClientTunnelIP)
	}
	if cfg.PrefixLen != 24 || cfg.MTU != 1400 {
		t.Fatalf("PrefixLen = %d, MTU = %d", cfg.PrefixLen, cfg.MTU)
	}
	if cfg.EgressIface != "ens5" {
		t.Fatalf("EgressIface = %q", cfg.EgressIface)
	}
	if logLevel != "warn" {
		t.Fatalf("logLevel = %q", logLevel)
	}
}

// TestParseFlagsDefaults 守住默认值：默认只绑回环，且默认复用系统 sshd 的
// authorized_keys（客户端用的私钥本就是登录主机那把，首次部署无需分发步骤）。
func TestParseFlagsDefaults(t *testing.T) {
	// Act
	cfg, tunName, logLevel, err := parseFlags(nil)

	// Assert
	if err != nil {
		t.Fatalf("parseFlags 返回错误: %v", err)
	}
	if cfg.ListenAddr != config.DefaultListenAddr {
		t.Fatalf("ListenAddr = %q，期望默认值 %q", cfg.ListenAddr, config.DefaultListenAddr)
	}
	if tunName != "" {
		t.Fatalf("tunName = %q，留空表示由平台决定", tunName)
	}
	if len(cfg.AuthorizedKeysPaths) != 1 || cfg.AuthorizedKeysPaths[0] != defaultAuthorizedKeys {
		t.Fatalf("AuthorizedKeysPaths = %q", cfg.AuthorizedKeysPaths)
	}
	if logLevel != "info" {
		t.Fatalf("logLevel = %q，期望 info", logLevel)
	}
}

func TestParseFlagsRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"监听地址缺少端口", []string{"-listen", "127.0.0.1"}},
		{"监听地址为空", []string{"-listen", ""}},
		{"没有 authorized_keys", []string{"-authorized-keys", ""}},
		{"隧道地址非法", []string{"-server-ip", "不是地址"}},
		{"两端地址相同", []string{"-server-ip", "10.9.0.1", "-client-ip", "10.9.0.1"}},
		{"客户端地址不在网段内", []string{"-client-ip", "10.10.0.2"}},
		{"MTU 超出范围", []string{"-mtu", "1"}},
		{"主机密钥路径为空", []string{"-host-key", "  "}},
		{"未知参数", []string{"-nope"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, _, _, err := parseFlags(tc.args)

			// Assert
			if err == nil {
				t.Fatal("非法参数应当被拒绝")
			}
		})
	}
}

func TestSplitCommaList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"单个", "/tmp/a", 1},
		{"带空格的多个", "/tmp/a, /tmp/b ,/tmp/c", 3},
		{"忽略空项", "/tmp/a,,/tmp/b", 2},
		{"全为空白", " , ", 0},
		{"空串", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := splitCommaList(tc.input)

			// Assert
			if len(got) != tc.want {
				t.Fatalf("splitCommaList(%q) = %q，期望 %d 项", tc.input, got, tc.want)
			}
		})
	}
}
