package netcfg

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// linuxPlatform 是 Linux 的实现。
//
// 本文件不带构建标签，因此在任何平台上都会被编译、也都能被测到：
// 命令的生成与解析是纯逻辑，与运行在哪个系统无关。
type linuxPlatform struct{}

// steps 生成 Linux 上的配置步骤。顺序：地址 → 链路（MTU + up）→ 路由。
func (linuxPlatform) steps(p Plan, original defaultRoute) []step {
	var steps []step

	steps = append(steps, step{
		do: command{"ip", []string{
			"addr", "add",
			fmt.Sprintf("%s/%d", p.LocalIP, p.PrefixLen),
			"dev", p.DeviceName,
		}},
		// 地址与链路状态随网卡销毁而消失（网卡由 devtun 关闭时移除），
		// 不需要单独撤销。
	})

	// MTU 与 up 合成一条命令：两者都是对链路属性的设置，分开执行只会多一次
	// 系统调用，不带来任何好处。
	link := []string{"link", "set", "dev", p.DeviceName}
	if p.MTU > 0 {
		link = append(link, "mtu", strconv.Itoa(p.MTU))
	}
	link = append(link, "up")
	steps = append(steps, step{do: command{"ip", link}})

	if p.TakeDefaultRoute {
		steps = append(steps, linuxEndpointRoute(p, original))
		steps = append(steps, linuxDefaultRoutes(p)...)
	}
	return steps
}

// linuxEndpointRoute 为穿透目标保留一条走原网关的主机路由。
//
// 与 macOS 同理，必须在两条 /1 之前执行，否则承载隧道自身的连接会被吞进隧道。
func linuxEndpointRoute(p Plan, original defaultRoute) step {
	target := fmt.Sprintf("%s/%d", p.EndpointIP, hostRouteLen)

	args := []string{"route", "add", target, "via", original.Gateway.String()}
	if original.Iface != "" {
		// 显式给出出口网卡：多网卡机器上若只有网关，内核可能选错出口。
		args = append(args, "dev", original.Iface)
	}

	return step{
		do:   command{"ip", args},
		undo: command{"ip", []string{"route", "del", target}},
	}
}

// linuxDefaultRoutes 安装两条半边路由以接管全部 IPv4 流量。
func linuxDefaultRoutes(p Plan) []step {
	var steps []step
	for _, target := range halfRoutes() {
		steps = append(steps, step{
			do:   command{"ip", []string{"route", "add", target, "dev", p.DeviceName}},
			undo: command{"ip", []string{"route", "del", target}},
		})
	}
	return steps
}

// defaultRouteCommand 返回读取当前默认路由的命令。
//
// -4 是必需的：不带它时输出里会混入 IPv6 的默认路由，而隧道只承载 IPv4。
func (linuxPlatform) defaultRouteCommand() command {
	return command{"ip", []string{"-4", "route", "show", "default"}}
}

// parseDefaultRoute 从 `ip -4 route show default` 的输出里取出网关与出口网卡。
//
// 典型输出：
//
//	default via 10.8.0.1 dev eth0 proto dhcp src 10.8.0.5 metric 100
//
// 按 token 解析而非按位置：字段的出现顺序与数量随内核版本、以及是否由 DHCP
// 写入而变化（proto/src/metric 都是可选的）。网关取 "via" 之后的那个 token，
// 出口网卡取 "dev" 之后的那个。
func (linuxPlatform) parseDefaultRoute(out []byte) (defaultRoute, error) {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}

		var parsed defaultRoute
		for i, field := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch field {
			case "via":
				addr, err := netip.ParseAddr(fields[i+1])
				if err != nil {
					return defaultRoute{}, fmt.Errorf("netcfg: 默认路由的网关 %q 不是合法地址: %w", fields[i+1], err)
				}
				// 隧道只承载 IPv4。若这里拿到 IPv6 网关，说明 -4 没有生效或
				// 系统状态与预期不符；拿着它去装 /32 主机路由会装出一条
				// 与隧道无关的规则，不如直接报错。
				if !addr.Is4() {
					return defaultRoute{}, fmt.Errorf("netcfg: 默认网关 %s 不是 IPv4 地址，隧道只承载 IPv4", addr)
				}
				parsed.Gateway = addr
			case "dev":
				parsed.Iface = fields[i+1]
			}
		}
		if !parsed.Gateway.IsValid() {
			return defaultRoute{}, fmt.Errorf("netcfg: 默认路由 %q 中没有 via 网关，无法为穿透目标保留物理链路", line)
		}
		return parsed, nil
	}

	return defaultRoute{}, fmt.Errorf("netcfg: 系统中没有 IPv4 默认路由，无法为穿透目标保留物理链路")
}
