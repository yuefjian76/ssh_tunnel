package netcfg

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"testing"
)

// testLogger 丢弃输出：这些测试只关心「是否回滚、按什么顺序回滚」，
// 日志内容无关紧要，不必污染测试输出。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeRunner 替身：记录执行过的命令，并可按命令内容指定输出或故障。
//
// 之所以能按「命令行文本」做键，是因为被测的规划器是纯函数——命令是确定的，
// 用不着正则或子串匹配这类会掩盖行为变化的手段。
type fakeRunner struct {
	calls   []string
	outputs map[string][]byte
	failOn  map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		outputs: map[string][]byte{},
		failOn:  map[string]error{},
	}
}

func (r *fakeRunner) run(cmd command) ([]byte, error) {
	key := cmd.String()
	r.calls = append(r.calls, key)
	if err, ok := r.failOn[key]; ok {
		return nil, err
	}
	return r.outputs[key], nil
}

// callsAfter 返回第 n 次调用之后的所有命令，用于只看某个阶段执行了什么。
func (r *fakeRunner) callsAfter(n int) []string {
	if n >= len(r.calls) {
		return nil
	}
	return r.calls[n:]
}

// ---------------------------------------------------------------- fixtures

const (
	darwinDefaultRouteOutput = `   route to: default
destination: default
       mask: default
    gateway: 192.168.71.1
  interface: en1
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec  rttvar  hopcount      mtu     expire
       0         0         0         0        0         0      1500         0 `

	linuxDefaultRouteOutput = "default via 10.8.0.1 dev eth0 proto dhcp src 10.8.0.5 metric 100\n"
)

// clientPlan 是客户端接管全流量时的计划（含防回环所需的穿透目标地址）。
func clientPlan(device string, mtu int) Plan {
	return Plan{
		DeviceName:       device,
		LocalIP:          netip.MustParseAddr("10.9.0.2"),
		PrefixLen:        24,
		MTU:              mtu,
		TakeDefaultRoute: true,
		EndpointIP:       netip.MustParseAddr("43.155.231.133"),
	}
}

// doStrings 取出各步骤的 do 命令文本。
func doStrings(steps []step) []string {
	out := make([]string, 0, len(steps))
	for _, st := range steps {
		out = append(out, st.do.String())
	}
	return out
}

func assertCommands(t *testing.T, what string, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s 命令数 = %d，期望 %d\n实际: %v\n期望: %v", what, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s 第 %d 条命令 = %q，期望 %q", what, i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------- Plan.Validate

func TestPlanValidate(t *testing.T) {
	valid := clientPlan("utun7", 1280)

	tests := []struct {
		name    string
		mutate  func(p Plan) Plan
		wantErr bool
	}{
		{"合法计划", func(p Plan) Plan { return p }, false},
		{"不接管默认路由时无需穿透目标", func(p Plan) Plan {
			p.TakeDefaultRoute, p.EndpointIP = false, netip.Addr{}
			return p
		}, false},
		{"MTU 为 0 表示不改动", func(p Plan) Plan { p.MTU = 0; return p }, false},
		{"网卡名为空", func(p Plan) Plan { p.DeviceName = "  "; return p }, true},
		{"隧道地址无效", func(p Plan) Plan { p.LocalIP = netip.Addr{}; return p }, true},
		{"掩码长度超出地址位宽", func(p Plan) Plan { p.PrefixLen = 33; return p }, true},
		{"掩码长度为负", func(p Plan) Plan { p.PrefixLen = -1; return p }, true},
		{"MTU 为负", func(p Plan) Plan { p.MTU = -1; return p }, true},
		{"接管默认路由但缺少穿透目标", func(p Plan) Plan {
			p.EndpointIP = netip.Addr{}
			return p
		}, true},
		// 穿透目标落在隧道网段内时，/32 主机路由与隧道网段路由会争抢同一个
		// 地址族，防回环不可能成立——必须在配置期就拦住。
		{"穿透目标落在隧道网段内", func(p Plan) Plan {
			p.EndpointIP = netip.MustParseAddr("10.9.0.9")
			return p
		}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.mutate(valid).Validate()

			// Assert
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v，期望出错 = %v", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------- ServerIPFromAddr

func TestServerIPFromAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"IPv4 加端口", "43.155.231.133:22", "43.155.231.133", false},
		{"仅 IPv4", "43.155.231.133", "", true},
		{"域名被拒绝", "cloud.example.com:22", "", true},
		{"端口不是数字", "43.155.231.133:ssh", "", true},
		{"端口越界", "43.155.231.133:70000", "", true},
		{"端口为空", "43.155.231.133:", "", true},
		{"空字符串", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := ServerIPFromAddr(tc.input)

			// Assert
			if (err != nil) != tc.wantErr {
				t.Fatalf("ServerIPFromAddr(%q) 错误 = %v，期望出错 = %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.String() != tc.want {
				t.Fatalf("ServerIPFromAddr(%q) = %s，期望 %s", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- 解析默认路由

func TestDarwinParseDefaultRoute(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantGW    string
		wantIface string
		wantErr   bool
	}{
		{"典型输出", darwinDefaultRouteOutput, "192.168.71.1", "en1", false},
		{"网关与网卡顺序颠倒也能解析", "  interface: en0\n    gateway: 10.0.0.1\n", "10.0.0.1", "en0", false},
		{"无默认路由时输出为空", "", "", "", true},
		{"缺少网段行", "  interface: en1\n", "", "", true},
		{"网关不是合法地址", "    gateway: 不是地址\n  interface: en1\n", "", "", true},
		{"网关是 IPv6 被拒绝", "    gateway: fe80::1\n  interface: en1\n", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := darwinPlatform{}.parseDefaultRoute([]byte(tc.output))

			// Assert
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseDefaultRoute() 错误 = %v，期望出错 = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Gateway.String() != tc.wantGW || got.Iface != tc.wantIface {
				t.Fatalf("解析结果 = %s/%s，期望 %s/%s", got.Gateway, got.Iface, tc.wantGW, tc.wantIface)
			}
		})
	}
}

func TestLinuxParseDefaultRoute(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantGW    string
		wantIface string
		wantErr   bool
	}{
		{"典型输出", linuxDefaultRouteOutput, "10.8.0.1", "eth0", false},
		// 字段顺序与数量随内核版本变化（proto/src/metric 都可能缺席），
		// 因此解析不能依赖位置。
		{"最简输出", "default via 192.168.1.1 dev enp0s3\n", "192.168.1.1", "enp0s3", false},
		{"dev 在 via 之前", "default dev eth1 via 10.0.0.254 metric 50\n", "10.0.0.254", "eth1", false},
		{"忽略其它路由行", "10.9.0.0/24 dev ssh-tun0 scope link\ndefault via 10.8.0.1 dev eth0\n", "10.8.0.1", "eth0", false},
		{"空输出", "", "", "", true},
		{"没有 via（如 PPP 默认路由）", "default dev ppp0 scope link\n", "", "", true},
		{"网关不是合法地址", "default via 不是地址 dev eth0\n", "", "", true},
		{"网关是 IPv6 被拒绝", "default via fe80::1 dev eth0\n", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := linuxPlatform{}.parseDefaultRoute([]byte(tc.output))

			// Assert
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseDefaultRoute() 错误 = %v，期望出错 = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Gateway.String() != tc.wantGW || got.Iface != tc.wantIface {
				t.Fatalf("解析结果 = %s/%s，期望 %s/%s", got.Gateway, got.Iface, tc.wantGW, tc.wantIface)
			}
		})
	}
}

// ---------------------------------------------------------------- 规划器

func TestDarwinSteps(t *testing.T) {
	original := defaultRoute{
		Gateway: netip.MustParseAddr("192.168.71.1"),
		Iface:   "en1",
	}

	t.Run("接管全流量", func(t *testing.T) {
		// Act
		got := doStrings(darwinPlatform{}.steps(clientPlan("utun7", 1280), original))

		// Assert：防回环主机路由必须排在两条 /1 之前
		assertCommands(t, "macOS", got, []string{
			"ifconfig utun7 inet 10.9.0.2/24 10.9.0.2",
			"ifconfig utun7 mtu 1280",
			"ifconfig utun7 up",
			"route -q -n add -inet 43.155.231.133 -gateway 192.168.71.1",
			"route -q -n add -inet 0.0.0.0/1 -interface utun7",
			"route -q -n add -inet 128.0.0.0/1 -interface utun7",
		})
	})

	t.Run("不接管默认路由时不产生任何路由命令", func(t *testing.T) {
		// Arrange
		plan := clientPlan("utun7", 1280)
		plan.TakeDefaultRoute = false
		plan.EndpointIP = netip.Addr{}

		// Act
		got := doStrings(darwinPlatform{}.steps(plan, defaultRoute{}))

		// Assert
		for _, cmd := range got {
			if strings.HasPrefix(cmd, "route ") {
				t.Fatalf("不接管默认路由时不应改动路由表，却出现命令 %q", cmd)
			}
		}
	})

	t.Run("MTU 为 0 时不设置 MTU", func(t *testing.T) {
		// Act
		got := doStrings(darwinPlatform{}.steps(clientPlan("utun7", 0), original))

		// Assert
		for _, cmd := range got {
			if strings.Contains(cmd, "mtu") {
				t.Fatalf("MTU 为 0 表示不改动，不应出现 %q", cmd)
			}
		}
	})
}

func TestLinuxSteps(t *testing.T) {
	original := defaultRoute{
		Gateway: netip.MustParseAddr("10.8.0.1"),
		Iface:   "eth0",
	}

	t.Run("接管全流量", func(t *testing.T) {
		// Act
		got := doStrings(linuxPlatform{}.steps(clientPlan("ssh-tun0", 1280), original))

		// Assert
		assertCommands(t, "Linux", got, []string{
			"ip addr add 10.9.0.2/24 dev ssh-tun0",
			"ip link set dev ssh-tun0 mtu 1280 up",
			"ip route add 43.155.231.133/32 via 10.8.0.1 dev eth0",
			"ip route add 0.0.0.0/1 dev ssh-tun0",
			"ip route add 128.0.0.0/1 dev ssh-tun0",
		})
	})

	t.Run("服务端形态：只配地址与链路", func(t *testing.T) {
		// Arrange：服务端不需要接管默认路由，MTU 由 devtun 建网卡时设好
		plan := Plan{
			DeviceName: "ssh-tun0",
			LocalIP:    netip.MustParseAddr("10.9.0.1"),
			PrefixLen:  24,
		}

		// Act
		got := doStrings(linuxPlatform{}.steps(plan, defaultRoute{}))

		// Assert
		assertCommands(t, "Linux 服务端", got, []string{
			"ip addr add 10.9.0.1/24 dev ssh-tun0",
			"ip link set dev ssh-tun0 up",
		})
	})

	t.Run("不知道出口网卡时只给网关", func(t *testing.T) {
		// Arrange：某些系统（容器、精简发行版）的输出里可能没有 dev 字段
		bare := defaultRoute{Gateway: netip.MustParseAddr("10.8.0.1")}

		// Act
		got := doStrings(linuxPlatform{}.steps(clientPlan("ssh-tun0", 1280), bare))

		// Assert：不带 dev 参数，否则会执行出一条引用空网卡名的命令
		if got[2] != "ip route add 43.155.231.133/32 via 10.8.0.1" {
			t.Fatalf("缺少出口网卡时应当只按网关装主机路由，实际 %q", got[2])
		}
	})
}

// TestEndpointRouteIsUndone 守住防回环那条主机路由的「可撤销」：
// 它必须在 /1 之前装上，且必须能单独删掉。
func TestEndpointRouteIsUndone(t *testing.T) {
	original := defaultRoute{
		Gateway: netip.MustParseAddr("192.168.71.1"),
		Iface:   "en1",
	}

	steps := darwinPlatform{}.steps(clientPlan("utun7", 1280), original)

	// 第 4 步（下标 3）是穿透目标的主机路由
	if got := steps[3].undo.String(); got != "route -q -n delete -inet 43.155.231.133" {
		t.Fatalf("主机路由的撤销命令 = %q", got)
	}
	// 地址/MTU/up 三步随网卡销毁而消失，不需要撤销
	for i := 0; i < 3; i++ {
		if !steps[i].undo.empty() {
			t.Fatalf("第 %d 步不应有撤销命令，实际 %q", i, steps[i].undo.String())
		}
	}
}

// TestCurrentPlatformMatchesRuntime 验证构建标签选出来的实现确实与当前系统一致。
// 这是全包里唯一「平台差异」的接线处，选错会静默地在 macOS 上执行 iproute2 命令。
func TestCurrentPlatformMatchesRuntime(t *testing.T) {
	want, ok := map[string]string{
		"darwin": "route -n get default",
		"linux":  "ip -4 route show default",
	}[runtime.GOOS]
	if !ok {
		t.Fatalf("未知平台 %s：netcfg 只实现了 darwin 与 linux", runtime.GOOS)
	}

	if got := currentPlatform.defaultRouteCommand().String(); got != want {
		t.Fatalf("currentPlatform 的读路由命令 = %q，期望 %q", got, want)
	}
}

// ---------------------------------------------------------------- Apply / Revert

// applyWithDarwin 用替身执行一次 macOS 上的完整 Apply。
func applyWithDarwin(t *testing.T, plan Plan, r *fakeRunner) (*Setup, error) {
	t.Helper()

	r.outputs[darwinPlatform{}.defaultRouteCommand().String()] = []byte(darwinDefaultRouteOutput)
	return apply(plan, darwinPlatform{}, r, testLogger())
}

func TestApplyRunsStepsInOrderAfterReadingOriginalRoute(t *testing.T) {
	// Arrange
	r := newFakeRunner()

	// Act
	setup, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)

	// Assert
	if err != nil {
		t.Fatalf("Apply 返回错误: %v", err)
	}
	if setup == nil {
		t.Fatal("Apply 成功时必须返回可撤销的句柄")
	}

	// 读取原默认路由必须是第一条命令：一旦 /1 装上，读到的就指向隧道自身了。
	assertCommands(t, "Apply 全流程", r.calls, []string{
		"route -n get default",
		"ifconfig utun7 inet 10.9.0.2/24 10.9.0.2",
		"ifconfig utun7 mtu 1280",
		"ifconfig utun7 up",
		"route -q -n add -inet 43.155.231.133 -gateway 192.168.71.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun7",
		"route -q -n add -inet 128.0.0.0/1 -interface utun7",
	})
}

func TestApplyRejectsInvalidPlanBeforeTouchingSystem(t *testing.T) {
	// Arrange
	r := newFakeRunner()
	plan := clientPlan("utun7", 1280)
	plan.EndpointIP = netip.Addr{} // 接管默认路由却没有穿透目标

	// Act
	_, err := applyWithDarwin(t, plan, r)

	// Assert
	if err == nil {
		t.Fatal("非法计划应当被拒绝")
	}
	if len(r.calls) != 0 {
		t.Fatalf("校验失败时不应执行任何命令，实际执行了 %v", r.calls)
	}
}

func TestApplyFailsWhenOriginalRouteUnreadable(t *testing.T) {
	// Arrange：读默认路由失败时还没改过任何东西，因此不应有回滚动作
	r := newFakeRunner()
	r.failOn[darwinPlatform{}.defaultRouteCommand().String()] = errors.New("route: 命令不存在")

	// Act
	_, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)

	// Assert
	if err == nil {
		t.Fatal("读不到原默认路由时必须失败：用它装出来的防回环路由会指向隧道自身")
	}
	if len(r.calls) != 1 {
		t.Fatalf("失败前不应执行其它命令，实际 %v", r.calls)
	}
}

// TestApplyRollsBackOnStepFailure 守住最关键的一条：中途失败必须回滚。
// 路由表被改到一半的机器会表现为「网络时通时不通」，比彻底断网更难排查。
func TestApplyRollsBackOnStepFailure(t *testing.T) {
	// Arrange：让第二条 /1 路由失败
	r := newFakeRunner()
	failing := "route -q -n add -inet 128.0.0.0/1 -interface utun7"
	r.failOn[failing] = errors.New("route: 无效参数")

	// Act
	setup, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)

	// Assert
	if err == nil {
		t.Fatal("步骤失败时 Apply 必须返回错误")
	}
	if setup != nil {
		t.Fatal("失败时不应返回句柄，否则调用方会以为可以正常撤销")
	}
	if !strings.Contains(err.Error(), failing) {
		t.Fatalf("错误信息应指明是哪条命令失败，实际: %v", err)
	}

	// 失败前已完成两步带撤销的改动：0.0.0.0/1 与穿透目标主机路由。
	// 回滚按逆序进行，因此先删 /1、再删主机路由——顺序与安装时相反，
	// 也就与「先装主机路由、再装 /1」严格对称。
	assertCommands(t, "回滚", r.callsAfter(7), []string{
		"route -q -n delete -inet 0.0.0.0/1",
		"route -q -n delete -inet 43.155.231.133",
	})
}

func TestRevertUndoesInReverseOrder(t *testing.T) {
	// Arrange
	r := newFakeRunner()
	setup, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)
	if err != nil {
		t.Fatalf("Apply 返回错误: %v", err)
	}
	applied := len(r.calls)

	// Act
	if err := setup.Revert(testLogger()); err != nil {
		t.Fatalf("Revert 返回错误: %v", err)
	}

	// Assert：两条 /1 先删、穿透目标主机路由最后删。
	// 顺序颠倒的话，删掉主机路由的那一瞬间 /1 仍在生效，正在运行的隧道
	// 会把自己的连接吞进去。
	assertCommands(t, "撤销", r.callsAfter(applied), []string{
		"route -q -n delete -inet 128.0.0.0/1",
		"route -q -n delete -inet 0.0.0.0/1",
		"route -q -n delete -inet 43.155.231.133",
	})
}

func TestRevertIsIdempotent(t *testing.T) {
	// Arrange
	r := newFakeRunner()
	setup, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)
	if err != nil {
		t.Fatalf("Apply 返回错误: %v", err)
	}
	if err := setup.Revert(testLogger()); err != nil {
		t.Fatalf("首次 Revert 返回错误: %v", err)
	}
	after := len(r.calls)

	// Act：再撤两次
	for i := 0; i < 2; i++ {
		if err := setup.Revert(testLogger()); err != nil {
			t.Fatalf("第 %d 次重复 Revert 返回错误: %v", i+2, err)
		}
	}

	// Assert
	if got := r.callsAfter(after); len(got) != 0 {
		t.Fatalf("重复撤销不应再执行命令，实际 %v", got)
	}
}

// TestRevertKeepsGoingWhenOneStepFails 守住「一条撤销失败不能拖住其余撤销」：
// 早退还意味着剩下的 /1 路由永远留在表里，机器再也上不了网。
func TestRevertKeepsGoingWhenOneStepFails(t *testing.T) {
	// Arrange
	r := newFakeRunner()
	setup, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)
	if err != nil {
		t.Fatalf("Apply 返回错误: %v", err)
	}
	applied := len(r.calls)
	broken := "route -q -n delete -inet 0.0.0.0/1"
	r.failOn[broken] = errors.New("route: 路由不存在")

	// Act
	err = setup.Revert(testLogger())

	// Assert
	if err == nil {
		t.Fatal("撤销失败必须报错：残留的路由会让用户处在难以察觉的半配置状态")
	}
	if !strings.Contains(err.Error(), broken) {
		t.Fatalf("错误信息应指出失败的撤销命令，实际: %v", err)
	}
	assertCommands(t, "容错撤销", r.callsAfter(applied), []string{
		"route -q -n delete -inet 128.0.0.0/1",
		broken,
		"route -q -n delete -inet 43.155.231.133",
	})
}

// TestApplyRevertsOnEarlyFailure 覆盖失败点靠前的分支：只配了地址就失败时，
// 回滚不应执行任何命令（地址没有独立的撤销动作），但也不能报错。
func TestApplyRevertsOnEarlyFailure(t *testing.T) {
	// Arrange
	r := newFakeRunner()
	failing := "ifconfig utun7 up"
	r.failOn[failing] = errors.New("ifconfig: 设备忙")

	// Act
	_, err := applyWithDarwin(t, clientPlan("utun7", 1280), r)

	// Assert
	if err == nil {
		t.Fatal("步骤失败时 Apply 必须返回错误")
	}
	assertCommands(t, "早期失败后的回滚", r.callsAfter(4), nil)
}

// ---------------------------------------------------------------- execRunner

// TestExecRunnerReturnsOutputAndWrapError 覆盖真实执行层：它本身是薄薄一层，
// 但「报错时带上命令输出」这一点决定了用户能不能自己复现问题。
func TestExecRunnerReturnsOutputAndWrapError(t *testing.T) {
	t.Run("成功时返回输出", func(t *testing.T) {
		// Act
		out, err := execRunner{}.run(command{name: "/bin/echo", args: []string{"hello"}})

		// Assert
		if err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		if strings.TrimSpace(string(out)) != "hello" {
			t.Fatalf("输出 = %q", out)
		}
	})

	t.Run("失败时错误里带上命令行", func(t *testing.T) {
		// Act
		_, err := execRunner{}.run(command{name: "/nonexistent/ssh-tunnel-test-binary"})

		// Assert
		if err == nil {
			t.Fatal("执行不存在的程序应当报错")
		}
		if !strings.Contains(err.Error(), "/nonexistent/ssh-tunnel-test-binary") {
			t.Fatalf("错误信息应包含命令行，实际: %v", err)
		}
	})
}
