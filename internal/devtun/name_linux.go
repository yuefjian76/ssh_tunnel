//go:build linux

package devtun

// defaultDeviceName 返回 Linux 上的默认隧道网卡名。
//
// 与 macOS 不同，Linux 不会自动分配编号，名字必须由调用方给定；
// 内核在名字已存在时返回 EEXIST，因此这里用一个语义清晰且不会撞名的前缀。
func defaultDeviceName() string { return "ssh-tun0" }
