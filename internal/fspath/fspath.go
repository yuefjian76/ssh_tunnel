// Package fspath 提供路径处理上的小工具，供 client 与 server 共用。
package fspath

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ExpandHome 把路径开头的 "~" 展开为用户主目录。
//
// 只支持 "~" 与 "~/..."（配置里最常见的写法），不支持 "~user"：
// 后者需要查 /etc/passwd、行为依赖平台，收益极小却引入一类难以排查的失败。
func ExpandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := homeDir()
	if err != nil {
		return "", fmt.Errorf("fspath: 无法确定用户主目录以展开 %q: %w", path, err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[len("~/"):]), nil
}

// homeDir 返回当前用户的主目录。
//
// 先试 $HOME，取不到时退回 os/user（读 /etc/passwd）。
// 这个退路在守护进程里是必需的：systemd 的系统级服务默认不设置 $HOME，
// 只看 $HOME 的实现在交互式 shell 下跑得好好的，一旦被 systemd 拉起就会
// 报「$HOME is not defined」并以退出码 1 反复重启。
func homeDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home, nil
	}

	current, err := user.Current()
	if err != nil {
		return "", err
	}
	if current.HomeDir == "" {
		return "", fmt.Errorf("用户在 /etc/passwd 中没有主目录")
	}
	return current.HomeDir, nil
}
