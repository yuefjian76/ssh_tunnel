package sshserver

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuefjian76/ssh_tunnel/internal/testutil"
	gossh "golang.org/x/crypto/ssh"
)

func TestKeyWhitelistAllowsOnlyListedKeys(t *testing.T) {
	// Arrange
	listed := testutil.MustSigner()
	outsider := testutil.MustSigner()
	list := KeyWhitelist{listed.PublicKey()}

	tests := []struct {
		name string
		key  gossh.PublicKey
		want bool
	}{
		{"白名单内的公钥", listed.PublicKey(), true},
		{"白名单外的公钥", outsider.PublicKey(), false},
		{"nil 公钥", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := list.Allows(tc.key)

			// Assert
			if got != tc.want {
				t.Fatalf("Allows() = %v，期望 %v", got, tc.want)
			}
		})
	}
}

// TestKeyWhitelistEmptyDeniesEverything 守住 fail-closed：
// 空白名单绝不能被当成「不做校验」。
func TestKeyWhitelistEmptyDeniesEverything(t *testing.T) {
	// Arrange
	var empty KeyWhitelist

	// Act
	got := empty.Allows(testutil.MustSigner().PublicKey())

	// Assert
	if got {
		t.Fatal("空白名单必须拒绝一切公钥")
	}
}

func TestKeyWhitelistSkipsNilEntries(t *testing.T) {
	// Arrange：混入 nil 项不应 panic
	listed := testutil.MustSigner()
	list := KeyWhitelist{nil, listed.PublicKey()}

	// Act & Assert
	if !list.Allows(listed.PublicKey()) {
		t.Fatal("应当跳过 nil 项并匹配到后面的有效公钥")
	}
}

func TestLoadAuthorizedKeysIgnoresCommentsAndBlankLines(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	first := testutil.MustSigner()
	second := testutil.MustSigner()

	pathA := filepath.Join(dir, "a")
	writeFile(t, pathA, "# 这是注释\n\n   \n"+string(testutil.AuthorizedKeyLine(first)))

	pathB := filepath.Join(dir, "b")
	writeFile(t, pathB, string(testutil.AuthorizedKeyLine(second)))

	// Act
	list, err := LoadAuthorizedKeys([]string{pathA, pathB})

	// Assert
	if err != nil {
		t.Fatalf("LoadAuthorizedKeys 返回错误: %v", err)
	}
	if !list.Allows(first.PublicKey()) {
		t.Fatal("第一个文件的公钥应当被载入")
	}
	if !list.Allows(second.PublicKey()) {
		t.Fatal("第二个文件的公钥应当被载入")
	}
	if list.Allows(testutil.MustSigner().PublicKey()) {
		t.Fatal("未列出的公钥不应被接受")
	}
}

// TestLoadAuthorizedKeysRejectsInvalidLine 断言错误里带行号——
// 配置解析出错时，行号是最有用的定位信息。
func TestLoadAuthorizedKeysRejectsInvalidLine(t *testing.T) {
	// Arrange：第 2 行是坏的
	dir := t.TempDir()
	path := filepath.Join(dir, "bad")
	key := testutil.MustSigner()
	writeFile(t, path, string(testutil.AuthorizedKeyLine(key))+"这不是公钥\n")

	// Act
	_, err := LoadAuthorizedKeys([]string{path})

	// Assert
	if err == nil {
		t.Fatal("非法公钥行应当导致报错")
	}
	if !strings.Contains(err.Error(), "第 2 行") {
		t.Fatalf("错误信息里应当包含行号，实际: %v", err)
	}
}

func TestLoadAuthorizedKeysRejectsMissingFile(t *testing.T) {
	// Act
	_, err := LoadAuthorizedKeys([]string{filepath.Join(t.TempDir(), "不存在")})

	// Assert
	if err == nil {
		t.Fatal("文件不存在应当报错，而不是静默忽略")
	}
}

func TestLoadAuthorizedKeysRejectsFileWithoutKeys(t *testing.T) {
	// Arrange：只有注释，一个公钥都没有
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	writeFile(t, path, "# 只有注释\n\n")

	// Act
	_, err := LoadAuthorizedKeys([]string{path})

	// Assert
	if err == nil {
		t.Fatal("没有任何公钥时应当报错，避免服务端起来却无人能登录")
	}
}
