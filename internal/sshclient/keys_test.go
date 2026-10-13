package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
)

// writePrivateKey 生成一枚 ed25519 私钥并以 PEM 落盘，返回路径。
func writePrivateKey(t *testing.T, comment string) (string, gossh.Signer) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 ed25519 私钥失败: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("写入私钥失败: %v", err)
	}
	return path, signer
}

func TestLoadSignerReadsPEMFile(t *testing.T) {
	// Arrange
	path, want := writePrivateKey(t, "unit test")

	// Act
	got, err := LoadSigner(path)

	// Assert
	if err != nil {
		t.Fatalf("LoadSigner 返回错误: %v", err)
	}
	// 用指纹比较而非 gliderlabs 的 KeysEqual：后者在另一处包中，
	// 为单个断言引入依赖不划算；指纹比较对公钥而言是等价的。
	if gossh.FingerprintSHA256(got.PublicKey()) != gossh.FingerprintSHA256(want.PublicKey()) {
		t.Fatal("加载出的签名器与写入的私钥不是同一枚")
	}
}

func TestLoadSignerRejectsMissingFile(t *testing.T) {
	// Act
	_, err := LoadSigner(filepath.Join(t.TempDir(), "不存在"))

	// Assert
	if err == nil {
		t.Fatal("文件不存在时应当报错")
	}
}

// TestLoadSignerErrorDoesNotLeakKeyMaterial 守住「错误信息不得泄露敏感数据」：
// 错误信息常被贴进 issue 或日志聚合系统，私钥内容绝不能出现在里面。
func TestLoadSignerErrorDoesNotLeakKeyMaterial(t *testing.T) {
	// Arrange：写入一个内容可识别、且不是合法私钥的文件
	const marker = "SECRET-KEY-MATERIAL-MARKER"
	path := filepath.Join(t.TempDir(), "bad_key")
	if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
		t.Fatalf("写入文件失败: %v", err)
	}

	// Act
	_, err := LoadSigner(path)

	// Assert
	if err == nil {
		t.Fatal("非法私钥应当报错")
	}
	if msg := err.Error(); strings.Contains(msg, marker) {
		t.Fatalf("错误信息泄露了文件内容: %s", msg)
	}
}

func TestKnownHostsCallbackRejectsMissingFile(t *testing.T) {
	// Act
	_, err := KnownHostsCallback(filepath.Join(t.TempDir(), "不存在"))

	// Assert
	if err == nil {
		t.Fatal("known_hosts 不存在时应当报错（fail closed），而不是放行任何主机")
	}
}

func TestKnownHostsCallbackAcceptsKnownHostAndRejectsOthers(t *testing.T) {
	// Arrange
	signer := testutil.MustSigner()
	const host = "tunnel.example.com"

	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{host}, signer.PublicKey())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("写入 known_hosts 失败: %v", err)
	}

	callback, err := KnownHostsCallback(path)
	if err != nil {
		t.Fatalf("KnownHostsCallback 返回错误: %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	// Act & Assert 一：已知主机、密钥一致 → 通过
	if err := callback(host+":22", remote, signer.PublicKey()); err != nil {
		t.Fatalf("已知主机应当被接受，实际: %v", err)
	}

	// Act & Assert 二：同一主机但密钥不同 → 拒绝，且被判定为致命错误
	other := testutil.MustSigner()
	err = callback(host+":22", remote, other.PublicKey())
	if err == nil {
		t.Fatal("主机密钥不符时应当拒绝连接")
	}
	if !isFatal(err) {
		t.Fatalf("主机密钥不符应判定为致命错误（不再重试），实际错误: %v", err)
	}
}
