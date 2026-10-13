package sshserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/fspath"
)

// 主机密钥文件的权限。主机密钥泄露意味着攻击者可以冒充服务端（中间人），
// 因此目录 0700、文件 0600。
const (
	hostKeyDirMode  = 0o700
	hostKeyFileMode = 0o600
	hostKeyComment  = "ssh_tunnel host key"
)

// LoadOrCreateHostKey 读取主机密钥；文件不存在时生成一枚 ed25519 密钥并落盘。
//
// 自动生成是为了让首次部署不必手工跑 ssh-keygen。选 ed25519 而非 RSA：
// 密钥更短、握手更快，且 x/crypto 原生支持，无需生成参数的额外步骤。
func LoadOrCreateHostKey(path string) (gossh.Signer, error) {
	resolved, err := fspath.ExpandHome(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(resolved)
	switch {
	case err == nil:
		signer, parseErr := gossh.ParsePrivateKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("sshserver: 解析主机密钥 %s 失败: %w", resolved, parseErr)
		}
		return signer, nil
	case errors.Is(err, fs.ErrNotExist):
		return generateHostKey(resolved)
	default:
		return nil, fmt.Errorf("sshserver: 读取主机密钥 %s 失败: %w", resolved, err)
	}
}

func generateHostKey(path string) (gossh.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(path), hostKeyDirMode); err != nil {
		return nil, fmt.Errorf("sshserver: 创建主机密钥目录失败: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshserver: 生成 ed25519 主机密钥失败: %w", err)
	}

	block, err := gossh.MarshalPrivateKey(priv, hostKeyComment)
	if err != nil {
		return nil, fmt.Errorf("sshserver: 序列化主机密钥失败: %w", err)
	}
	// 这里必然是新建文件（调用方已确认文件不存在），所以 0600 会真正生效。
	if err := os.WriteFile(path, pem.EncodeToMemory(block), hostKeyFileMode); err != nil {
		return nil, fmt.Errorf("sshserver: 写入主机密钥 %s 失败: %w", path, err)
	}

	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshserver: 由主机密钥构造签名器失败: %w", err)
	}
	return signer, nil
}
