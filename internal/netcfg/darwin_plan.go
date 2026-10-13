package netcfg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// darwinPlatform 是 macOS 的实现。
//
// 本文件不带构建标签，因此在任何平台上都会被编译、也都能被测到：
// 命令的生成与解析是纯逻辑，与运行在哪个系统无关。
type darwinPlatform struct{}

// 关于点对点地址的写法：这里采用 wg-quick 的做法（darwin.bash 的 add_addr()）——
//
//	ifconfig <utun> inet <地址>/<掩码长度> <同一个地址>
//
// 即第一个参数带上掩码长度、第二个参数（BSD 语义里的对端地址）填同一个地址，
// 于是内核为隧道网段建立一条直连路由，对端地址在该网段内即可直达。
//
// ⚠️ 另有一派写法是「本端与对端给不同地址」：ifconfig <utun> inet 10.9.0.2 10.9.0.1。
// 两者都能工作，但语义不同，且本机无法在无 root 的情况下验证。这里选 wg-quick
// 的做法是因为它有生产环境验证；若真机上 ping 不通对端，改用另一派写法即可。
// 这一点记在计划的「必须在真机验证后才能定稿」清单里。
func (darwinPlatform) steps(p Plan, original defaultRoute) []step {
	var steps []step

	// 顺序：地址 → MTU → up → 路由。与 wg-quick 的 add_addr/set_mtu/up_if/add_route 一致。
	steps = append(steps, step{
		do: command{"ifconfig", []string{
			p.DeviceName, "inet",
			fmt.Sprintf("%s/%d", p.LocalIP, p.PrefixLen),
			p.LocalIP.String(),
		}},
		// 地址、MTU、up 三步的效果都随网卡销毁而消失（网卡由 devtun 关闭时移除），
		// 不需要单独撤销；而且界面名在同一进程内不会被复用。
	})

	if p.MTU > 0 {
		steps = append(steps, step{
			do: command{"ifconfig", []string{p.DeviceName, "mtu", strconv.Itoa(p.MTU)}},
		})
	}

	steps = append(steps, step{
		do: command{"ifconfig", []string{p.DeviceName, "up"}},
	})

	if p.TakeDefaultRoute {
		steps = append(steps, darwinEndpointRoute(p, original))
		steps = append(steps, darwinDefaultRoutes(p)...)
	}
	return steps
}

// darwinEndpointRoute 为穿透目标保留一条走原网关的主机路由。
//
// 这一步必须在两条 /1 路由**之前**执行：/1 一旦装上，穿透目标就会落进隧道，
// 而承载隧道自身的连接随即被吞进隧道，形成死循环。先装 /32 则全程受最长
// 前缀匹配保护。
func darwinEndpointRoute(p Plan, original defaultRoute) step {
	target := p.EndpointIP.String()
	return step{
		do: command{"route", []string{
			"-q", "-n", "add", "-inet", target,
			"-gateway", original.Gateway.String(),
		}},
		// 撤销时刻意不带 -gateway：删除只需指定目标，带上网关反而会在
		// 网关已被其它程序改动时报错，导致这条路由删不掉——而它残留的后果是
		// 穿透目标永远走旧网关，比删错更麻烦。
		undo: command{"route", []string{"-q", "-n", "delete", "-inet", target}},
	}
}

// darwinDefaultRoutes 安装两条半边路由以接管全部 IPv4 流量。
func darwinDefaultRoutes(p Plan) []step {
	var steps []step
	for _, target := range halfRoutes() {
		steps = append(steps, step{
			do: command{"route", []string{
				"-q", "-n", "add", "-inet", target,
				"-interface", p.DeviceName,
			}},
			undo: command{"route", []string{"-q", "-n", "delete", "-inet", target}},
		})
	}
	return steps
}

// defaultRouteCommand 返回读取当前默认路由的命令。
func (darwinPlatform) defaultRouteCommand() command {
	return command{"route", []string{"-n", "get", "default"}}
}

// parseDefaultRoute 从 `route -n get default` 的输出里取出网关与出口网卡。
//
// 典型输出（缩进不定，字段顺序也可能变化，因此按行解析而非按位置）：
//
//	   route to: default
//	destination: default
//	       mask: default
//	    gateway: 192.168.71.1
//	  interface: en1
func (darwinPlatform) parseDefaultRoute(out []byte) (defaultRoute, error) {
	var parsed defaultRoute
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "gateway":
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return defaultRoute{}, fmt.Errorf("netcfg: 默认路由的网关 %q 不是合法地址: %w", value, err)
			}
			// 隧道只承载 IPv4：IPv6 网关无法用来安装 /32 主机路由。
			if !addr.Is4() {
				return defaultRoute{}, fmt.Errorf("netcfg: 默认网关 %s 不是 IPv4 地址，隧道只承载 IPv4", addr)
			}
			parsed.Gateway = addr
		case "interface":
			parsed.Iface = value
		}
	}

	if !parsed.Gateway.IsValid() {
		return defaultRoute{}, fmt.Errorf("netcfg: 未能从系统输出中解析出默认网关，无法为穿透目标保留物理链路")
	}
	return parsed, nil
}
