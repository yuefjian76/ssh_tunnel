package fspath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHomeLeavesOtherPathsUntouched(t *testing.T) {
	// "~user/x" 明确不在支持范围内（需要查 /etc/passwd），必须原样返回。
	for _, path := range []string{
		"/etc/ssh/authorized_keys",
		"relative/path",
		"",
		"./x",
		"~user/x",
		"/tmp/~not-at-start",
	} {
		t.Run(path, func(t *testing.T) {
			// Act
			got, err := ExpandHome(path)

			// Assert
			if err != nil {
				t.Fatalf("ExpandHome(%q) 返回错误: %v", path, err)
			}
			if got != path {
				t.Fatalf("ExpandHome(%q) = %q，期望原样返回", path, got)
			}
		})
	}
}

func TestExpandHomeExpandsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("无法取得用户主目录，跳过: %v", err)
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"单独的 ~", "~", home},
		{"~/ 前缀", "~/.ssh-tunnel/hostkey", filepath.Join(home, ".ssh-tunnel", "hostkey")},
		{"~ 后跟单层", "~/key", filepath.Join(home, "key")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := ExpandHome(tc.in)

			// Assert
			if err != nil {
				t.Fatalf("ExpandHome(%q) 返回错误: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ExpandHome(%q) = %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestExpandHomeWorksWithoutHomeEnv 守住守护进程场景：
// systemd 的系统级服务默认不设置 $HOME，只看 $HOME 的展开会在服务里失败，
// 而同一份二进制在交互式 shell 下却完全正常——这个差异极难从现象上猜到。
func TestExpandHomeWorksWithoutHomeEnv(t *testing.T) {
	// Arrange：模拟 systemd 拉起服务时的环境
	t.Setenv("HOME", "")

	// Act
	got, err := ExpandHome("~/.ssh-tunnel/hostkey")

	// Assert
	if err != nil {
		t.Fatalf("$HOME 为空时应当退回 /etc/passwd，实际报错: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("展开结果 = %q，期望绝对路径", got)
	}
	if filepath.Base(filepath.Dir(got)) != ".ssh-tunnel" {
		t.Fatalf("展开结果 = %q，期望落在 <home>/.ssh-tunnel/ 下", got)
	}
}
