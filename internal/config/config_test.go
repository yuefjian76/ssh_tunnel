package config

import (
	"net/netip"
	"testing"
)

func TestDefaultServerValidatesWithAuthorizedKeys(t *testing.T) {
	// Arrange：默认值本身不含 authorized_keys（那是环境相关的东西）
	srv := DefaultServer()
	srv.AuthorizedKeysPaths = []string{"/tmp/authorized_keys"}

	// Act
	err := srv.Validate()

	// Assert
	if err != nil {
		t.Fatalf("默认服务端配置应当合法，实际: %v", err)
	}
}

func TestDefaultClientValidates(t *testing.T) {
	// Arrange
	cli := DefaultClient()
	cli.KeyPath = "/tmp/key.pem"
	cli.KnownHostsPath = "/tmp/known_hosts"

	// Act
	err := cli.Validate()

	// Assert
	if err != nil {
		t.Fatalf("默认客户端配置应当合法，实际: %v", err)
	}
}

func TestServerValidateRejectsBadInput(t *testing.T) {
	base := DefaultServer()
	base.AuthorizedKeysPaths = []string{"/tmp/authorized_keys"}

	tests := []struct {
		name   string
		mutate func(Server) Server
	}{
		{"监听地址缺少端口", func(c Server) Server { c.ListenAddr = "127.0.0.1"; return c }},
		{"监听地址为空", func(c Server) Server { c.ListenAddr = ""; return c }},
		{"主机密钥路径为空", func(c Server) Server { c.HostKeyPath = "  "; return c }},
		{"没有 authorized_keys", func(c Server) Server { c.AuthorizedKeysPaths = nil; return c }},
		{"authorized_keys 路径为空串", func(c Server) Server {
			c.AuthorizedKeysPaths = []string{""}
			return c
		}},
		{"两端隧道地址相同", func(c Server) Server { c.ClientTunnelIP = c.ServerTunnelIP; return c }},
		{"客户端地址不在网段内", func(c Server) Server {
			c.ClientTunnelIP = netip.MustParseAddr("10.10.0.2")
			return c
		}},
		{"服务端地址不在网段内", func(c Server) Server {
			c.ServerTunnelIP = netip.MustParseAddr("10.10.0.1")
			return c
		}},
		{"两端地址族不一致", func(c Server) Server {
			c.ClientTunnelIP = netip.MustParseAddr("fd00::2")
			return c
		}},
		{"掩码长度越界", func(c Server) Server { c.PrefixLen = 33; return c }},
		{"掩码长度为负", func(c Server) Server { c.PrefixLen = -1; return c }},
		{"掩码过窄导致对端不在网段内", func(c Server) Server { c.PrefixLen = 32; return c }},
		{"MTU 过小", func(c Server) Server { c.MTU = 100; return c }},
		{"MTU 过大", func(c Server) Server { c.MTU = 100000; return c }},
		{"出接口为空", func(c Server) Server { c.EgressIface = " "; return c }},
		{"隧道地址零值", func(c Server) Server { c.ServerTunnelIP = netip.Addr{}; return c }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.mutate(base).Validate()

			// Assert
			if err == nil {
				t.Fatal("期望校验失败，却通过了")
			}
		})
	}
}

func TestClientValidateRejectsBadInput(t *testing.T) {
	base := DefaultClient()
	base.KeyPath = "/tmp/key.pem"
	base.KnownHostsPath = "/tmp/known_hosts"

	tests := []struct {
		name   string
		mutate func(Client) Client
	}{
		{"服务端地址非法", func(c Client) Client { c.ServerAddr = "no-port"; return c }},
		{"转发地址非法", func(c Client) Client { c.ForwardAddr = "127.0.0.1"; return c }},
		{"用户名称为空", func(c Client) Client { c.User = "  "; return c }},
		{"私钥路径为空", func(c Client) Client { c.KeyPath = ""; return c }},
		{"known_hosts 路径为空", func(c Client) Client { c.KnownHostsPath = "\t"; return c }},
		{"隧道地址无效", func(c Client) Client { c.ClientTunnelIP = netip.Addr{}; return c }},
		{"掩码长度越界", func(c Client) Client { c.PrefixLen = 99; return c }},
		{"MTU 越界", func(c Client) Client { c.MTU = 0; return c }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.mutate(base).Validate()

			// Assert
			if err == nil {
				t.Fatal("期望校验失败，却通过了")
			}
		})
	}
}

func TestServerTunnelPrefix(t *testing.T) {
	// Arrange
	srv := DefaultServer()

	// Act
	prefix, err := srv.TunnelPrefix()

	// Assert
	if err != nil {
		t.Fatalf("TunnelPrefix 返回错误: %v", err)
	}
	if got, want := prefix.String(), "10.9.0.0/24"; got != want {
		t.Fatalf("隧道网段 = %s，期望 %s", got, want)
	}
}

func TestClientTunnelPrefix(t *testing.T) {
	// Arrange
	cli := DefaultClient()

	// Act
	prefix, err := cli.TunnelPrefix()

	// Assert
	if err != nil {
		t.Fatalf("TunnelPrefix 返回错误: %v", err)
	}
	if got, want := prefix.String(), "10.9.0.0/24"; got != want {
		t.Fatalf("隧道网段 = %s，期望 %s", got, want)
	}
}

func TestValidateHostPortAcceptsIPv6AndHostnames(t *testing.T) {
	// 合法样例都必须通过，避免上面的"拒绝"用例变成恒真断言
	for _, addr := range []string{
		"127.0.0.1:8443",
		"[::1]:8443",
		"example.com:22",
		"0.0.0.0:0",
	} {
		// Act
		err := validateHostPort("测试", addr)

		// Assert
		if err != nil {
			t.Fatalf("%q 是合法的 host:port，却被拒绝: %v", addr, err)
		}
	}
}
