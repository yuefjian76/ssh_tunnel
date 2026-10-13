//go:build darwin

package devtun

// defaultDeviceName 返回 macOS 上让内核分配编号所需的通配名。
//
// 传入 "utun"（不带数字）时内核会挑选下一个可用的 utunN；传 "utunN" 才是指定编号。
// 不能用固定编号：开发机上 utun0–utun13 已被其他程序占用。
func defaultDeviceName() string { return "utun" }
