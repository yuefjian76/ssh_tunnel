//go:build linux

package netcfg

// platformImpl 是「某个操作系统上如何配置隧道网卡」的全部差异面。
//
// 刻意只有三个方法，且都是纯逻辑（构造命令、解析输出），不含任何执行动作：
// 执行统一由 runner 负责。这样两个平台的实现都能在任意操作系统上编译并单测，
// 平台差异被压缩到「谁来当 currentPlatform」这一行。
type platformImpl interface {
	// steps 按顺序返回配置步骤。original 是改动前的默认路由，
	// 仅在 TakeDefaultRoute 为真时有意义。
	steps(p Plan, original defaultRoute) []step
	// defaultRouteCommand 返回读取当前默认路由的命令。
	defaultRouteCommand() command
	// parseDefaultRoute 解析 defaultRouteCommand 的输出。
	parseDefaultRoute(out []byte) (defaultRoute, error)
}

// currentPlatform 是构建时选定的平台实现。
var currentPlatform platformImpl = linuxPlatform{}

var _ platformImpl = linuxPlatform{}
