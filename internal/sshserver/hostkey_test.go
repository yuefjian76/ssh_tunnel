package sshserver

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateHostKeyUsesRestrictivePermissions(t *testing.T) {
	// Arrange：父目录也不存在，验证会一并创建
	path := filepath.Join(t.TempDir(), "sub", "hostkey")

	// Act
	signer, err := LoadOrCreateHostKey(path)

	// Assert
	if err != nil {
		t.Fatalf("LoadOrCreateHostKey 返回错误: %v", err)
	}
	if signer == nil {
		t.Fatal("应当返回可用的签名器")
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("主机密钥文件应当已创建: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != hostKeyFileMode {
		t.Fatalf("主机密钥文件权限 = %o，期望 %o", got, hostKeyFileMode)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("主机密钥目录应当已创建: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != hostKeyDirMode {
		t.Fatalf("主机密钥目录权限 = %o，期望 %o", got, hostKeyDirMode)
	}
}

// TestLoadOrCreateHostKeyIsIdempotent 很重要：若每次启动都换一枚主机密钥，
// 客户端会看到「主机密钥已变更」而拒绝连接。
func TestLoadOrCreateHostKeyIsIdempotent(t *testing.T) {
	// Arrange
	path := filepath.Join(t.TempDir(), "hostkey")

	// Act
	first, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("首次调用返回错误: %v", err)
	}
	second, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("第二次调用返回错误: %v", err)
	}

	// Assert
	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Fatal("两次加载应当得到同一枚主机密钥")
	}
}

func TestLoadOrCreateHostKeyRejectsMalformedFile(t *testing.T) {
	// Arrange：文件存在但不是合法私钥
	path := filepath.Join(t.TempDir(), "hostkey")
	writeFile(t, path, "这不是一个私钥\n")

	// Act
	_, err := LoadOrCreateHostKey(path)

	// Assert
	if err == nil {
		t.Fatal("内容非法的主机密钥文件应当报错，而不是被当成不存在再生成一枚")
	}
}

func TestLoadOrCreateHostKeyRejectsUnreadablePath(t *testing.T) {
	// Arrange：路径本身是个目录，读取必然失败
	dir := t.TempDir()

	// Act
	_, err := LoadOrCreateHostKey(dir)

	// Assert
	if err == nil {
		t.Fatal("路径是目录时应当报错")
	}
}
