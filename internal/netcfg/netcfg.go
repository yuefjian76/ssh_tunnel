// Package netcfg 应用隧道所需的系统网络配置：网卡地址、MTU、路由（含防回环）。
//
// 这是全项目唯一直接改动系统网络状态的地方，因此设计上刻意收窄：
//
//   - 平台差异只体现在「生成哪些命令」上，而命令的生成是纯函数
//     （见 darwin_plan.go / linux_plan.go），可以离线单测；真正执行命令的
//     只有薄薄一层。
//
// 文件名是有讲究的：darwin_plan.go / linux_plan.go **必须**把平台名放在前面。
// 若写成 plan_darwin.go / plan_linux.go，Go 会按 `_GOOS.go` 的文件名约定把它
// 限制到对应系统上编译，于是「两个平台都能在 macOS 上单测」这个前提就没了。
// 同理，platform_darwin.go / platform_linux.go 是真的带构建标签的选择器，
// 那里才是唯一应当按平台裁剪的地方。
//   - Apply 与 Revert 严格成对。Apply 中途失败时会自行回滚已完成的步骤，
//     绝不给用户留下一张改了一半的路由表——改坏路由表会让机器直接失去网络。
//   - 命令一律以「程序 + 参数数组」的形式执行，不经过 shell，因此不存在
//     命令注入问题。
package netcfg

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// 路由掩码长度：隧道网段。
//
// 接管全部流量时用 0.0.0.0/1 + 128.0.0.0/1 两条半边路由，而不是一条
// 0.0.0.0/0。原因是这样无需删除系统原有的默认路由：原默认路由仍然是
// 0.0.0.0/0，但在最长前缀匹配下永远输给 /1，于是流量走隧道；拆除时只要
// 删掉这两条 /1，原默认路由立刻恢复生效——不需要在拆除时重建它，
// 也就不会因为拆除失败而把系统留在没有默认路由的状态。
const (
	defaultRouteHalfLen = 1
	hostRouteLen        = 32
)

// Plan 是一次「配置隧道网卡」的完整需求。
type Plan struct {
	// DeviceName 是隧道网卡的真实名字。
	// 必须取自 devtun.Device.Name()：macOS 上传 "utun" 会由内核分配具体编号，
	// 请求的名字与实际名字可能不同，自行推断必错。
	DeviceName string
	// LocalIP 与 PrefixLen 是本端隧道地址及其网段掩码长度。
	LocalIP   netip.Addr
	PrefixLen int
	// MTU 大于 0 时设置网卡 MTU；为 0 表示不改动
	// （服务端在 devtun 创建网卡时已设好，无需重复设置）。
	MTU int
	// TakeDefaultRoute 为真时接管全部 IPv4 流量。
	TakeDefaultRoute bool
	// EndpointIP 是承载隧道自身的那个对端地址（客户端的外层 SSH 目标）。
	//
	// 非零且 TakeDefaultRoute 为真时，会为它安装一条走原默认网关的主机路由：
	// 隧道一旦接管默认路由，承载隧道的那条 TCP 连接自己也会被塞进隧道，
	// 形成「隧道运载隧道」的死循环。主机路由的前缀更长（/32 对 /1），
	// 最长前缀匹配保证这条连接始终走物理链路。
	EndpointIP netip.Addr
}

// Validate 校验计划。不做任何 I/O。
func (p Plan) Validate() error {
	if strings.TrimSpace(p.DeviceName) == "" {
		return fmt.Errorf("netcfg: 隧道网卡名不能为空")
	}
	if !p.LocalIP.IsValid() {
		return fmt.Errorf("netcfg: 隧道地址无效")
	}
	if p.PrefixLen < 0 || p.PrefixLen > p.LocalIP.BitLen() {
		return fmt.Errorf("netcfg: 掩码长度 %d 对地址 %s 非法", p.PrefixLen, p.LocalIP)
	}
	if p.MTU < 0 {
		return fmt.Errorf("netcfg: MTU %d 不能为负数", p.MTU)
	}

	if p.TakeDefaultRoute {
		// 接管默认路由却没有防回环主机路由，等于把承载隧道自身的连接也送进
		// 隧道，隧道会当场自断。这不是「配置不够优雅」，而是直接不可用，
		// 因此在这里就挡下来。
		if !p.EndpointIP.IsValid() {
			return fmt.Errorf("netcfg: 接管默认路由时必须给出穿透目标地址（EndpointIP），否则隧道会把自身连接也吞进隧道")
		}
		prefix := netip.PrefixFrom(p.LocalIP, p.PrefixLen).Masked()
		if prefix.Contains(p.EndpointIP) {
			return fmt.Errorf("netcfg: 穿透目标地址 %s 落在隧道网段 %s 内，无法为它保留物理链路",
				p.EndpointIP, prefix)
		}
	}
	return nil
}

// command 是一条待执行的系统命令。程序与参数分开保存，不经过 shell。
type command struct {
	name string
	args []string
}

// String 返回便于日志阅读的命令行文本。注意它只用于展示，不用于执行。
func (c command) String() string {
	return strings.Join(append([]string{c.name}, c.args...), " ")
}

// empty 判断是否为空命令（表示「这一步不需要撤销」）。
func (c command) empty() bool { return c.name == "" }

// step 是配置过程中的一步，do 与 undo 成对出现。
//
// 成对保存是刻意的：若把「撤销」写在别处，两边很容易各自演化而失去对称，
// 而撤销一旦与执行不对称，后果是路由表被改坏。
type step struct {
	do   command
	undo command
}

// runner 执行系统命令并返回输出。
type runner interface {
	run(cmd command) ([]byte, error)
}

// execRunner 是真正落到系统上执行的实现。
type execRunner struct{}

func (execRunner) run(cmd command) ([]byte, error) {
	out, err := exec.Command(cmd.name, cmd.args...).CombinedOutput()
	if err != nil {
		// 带上命令输出：系统命令的报错原因几乎都在输出里，只回 exit status
		// 等于让人再去手敲一遍命令复现。
		return out, fmt.Errorf("%s: %w（输出: %s）", cmd, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// defaultRoute 是隧道建立之前系统原有的默认路由。
//
// 必须在改动任何路由**之前**读取：一旦隧道接管了默认路由，读到的就变成了
// 指向隧道自身的路由，用它做防回环主机路由会直接把隧道引向死循环。
type defaultRoute struct {
	Gateway netip.Addr
	Iface   string
}

// Setup 记录实际执行过的步骤，用于精确撤销。
type Setup struct {
	plan   Plan
	done   []step
	runner runner
	log    *slog.Logger
}

// Apply 按计划配置系统网络，返回用于撤销的句柄。
func Apply(plan Plan, log *slog.Logger) (*Setup, error) {
	return apply(plan, currentPlatform, execRunner{}, log)
}

func apply(plan Plan, impl platformImpl, r runner, log *slog.Logger) (*Setup, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}

	// 原默认路由必须在任何改动之前读取。
	var original defaultRoute
	if plan.TakeDefaultRoute {
		out, err := r.run(impl.defaultRouteCommand())
		if err != nil {
			return nil, fmt.Errorf("netcfg: 读取系统当前默认路由失败: %w", err)
		}
		original, err = impl.parseDefaultRoute(out)
		if err != nil {
			return nil, err
		}
		log.Info("已读取系统原有默认路由，将用它为穿透目标保留物理链路",
			"gateway", original.Gateway, "iface", original.Iface)
	}

	setup := &Setup{plan: plan, runner: r, log: log}
	for _, st := range impl.steps(plan, original) {
		// 步骤的输出（成功时）没有用处，只关心成败。
		if _, err := r.run(st.do); err != nil {
			// 已经改动的部分必须原样撤回去，否则用户会留在
			// 「路由改了一半」的状态里，症状是网络时通时不通。
			rollbackErr := setup.Revert(log)
			return nil, errors.Join(
				fmt.Errorf("netcfg: 执行 %q 失败: %w", st.do.String(), err),
				rollbackErr)
		}
		setup.done = append(setup.done, st)
	}
	return setup, nil
}

// Revert 按与配置相反的顺序撤销改动。可重复调用：撤销过的步骤不会再来一遍。
func (s *Setup) Revert(log *slog.Logger) error {
	if log == nil {
		log = s.log
	}
	if log == nil {
		log = slog.Default()
	}

	var errs []error
	for i := len(s.done) - 1; i >= 0; i-- {
		st := s.done[i]
		if st.undo.empty() {
			continue
		}
		if _, err := s.runner.run(st.undo); err != nil {
			// 撤销失败会留下改乱的路由表，必须让用户知道，不能只记 debug。
			log.Warn("撤销网络配置失败，系统可能残留改动", "cmd", st.undo.String(), "err", err)
			errs = append(errs, fmt.Errorf("netcfg: 撤销 %q 失败: %w", st.undo.String(), err))
		}
	}
	s.done = nil
	return errors.Join(errs...)
}

// ServerIPFromAddr 从 host:port 中取出主机地址，要求它是 IP 字面量。
//
// 之所以要求字面量而不是接受域名：防回环主机路由必须针对一个确定的 IP。
// 若在这里解析域名，解析结果可能与真正建立连接时的解析结果不同
// （或在此期间变化），于是保下来的那条路由指向的就不是隧道实际连接的地址，
// 死循环照样会发生。要求字面量把这个问题从运行期挪到了配置期。
//
// 端口只做「是不是一个端口号」的检查（net.SplitHostPort 不管这个，它会把
// 任意字符串都当成合法端口），因为地址串同时也是 SSH 的连接目标，端口写错
// 是在这里就能一眼看出的配置错误，没必要留到连接时才报。
func ServerIPFromAddr(hostPort string) (netip.Addr, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("netcfg: %q 不是合法的 host:port: %w", hostPort, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return netip.Addr{}, fmt.Errorf("netcfg: %q 的端口 %q 不是 1-65535 之间的端口号", hostPort, port)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("netcfg: %q 的主机部分必须是 IP 字面量（防回环路由需要确定的地址），实际为 %q",
			hostPort, host)
	}
	return ip, nil
}

// halfRoutes 返回接管默认路由要安装的两条半边路由的目标。
func halfRoutes() []string {
	return []string{
		fmt.Sprintf("0.0.0.0/%d", defaultRouteHalfLen),
		fmt.Sprintf("128.0.0.0/%d", defaultRouteHalfLen),
	}
}
