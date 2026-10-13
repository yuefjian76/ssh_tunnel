package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	gossh "golang.org/x/crypto/ssh"
)

// NewSigner 生成一枚用于测试的 ed25519 签名器（同时可当作主机密钥或客户端密钥）。
func NewSigner() (gossh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testutil: 生成 ed25519 密钥失败: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("testutil: 构造签名器失败: %w", err)
	}
	return signer, nil
}

// MustSigner 是 NewSigner 的 panic 版本，供测试代码简化写法。
// 生成密钥失败在测试环境里只可能是系统级故障，没有可恢复的处置方式。
func MustSigner() gossh.Signer {
	signer, err := NewSigner()
	if err != nil {
		panic(err)
	}
	return signer
}

// AuthorizedKeyLine 返回 signer 对应公钥的 authorized_keys 行（含结尾换行）。
func AuthorizedKeyLine(signer gossh.Signer) []byte {
	return gossh.MarshalAuthorizedKey(signer.PublicKey())
}
