package sshserver

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile 在测试里准备一个文件，必要时创建父目录。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("创建目录 %s 失败: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入文件 %s 失败: %v", path, err)
	}
}
