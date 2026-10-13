package sshserver

import (
	"fmt"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/yuefjian76/ssh_tunnel/internal/fspath"
)

// KeyWhitelist 是按公钥内容比对的白名单。
//
// 空白名单拒绝一切（fail closed）——"没配白名单就放行"是最危险的失败模式，
// 因此这里绝不允许出现该行为。New 也会拒绝空白名单。
type KeyWhitelist []gossh.PublicKey

// Allows 判断候选公钥是否在白名单中。
func (w KeyWhitelist) Allows(candidate gossh.PublicKey) bool {
	if candidate == nil {
		return false
	}
	for _, allowed := range w {
		if allowed == nil {
			continue
		}
		if ssh.KeysEqual(allowed, candidate) {
			return true
		}
	}
	return false
}

// LoadAuthorizedKeys 读取并解析若干 authorized_keys 文件，合并成一个白名单。
//
// 任一文件不可读、或任一行不是合法公钥，都立即报错——配置错误应当启动即暴露，
// 而不是等到客户端连不上时才回头排查。
func LoadAuthorizedKeys(paths []string) (KeyWhitelist, error) {
	var all KeyWhitelist
	for _, p := range paths {
		keys, err := loadAuthorizedKeyFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("sshserver: %d 个 authorized_keys 文件里没有任何公钥", len(paths))
	}
	return all, nil
}

// loadAuthorizedKeyFile 逐行解析一个 authorized_keys 文件。
//
// 之所以按行拆分而不直接把整个文件交给 ssh.ParseAuthorizedKey：后者在出错时
// 无法指出是哪一行坏的，而配置文件解析错误里最有用的信息就是行号。
func loadAuthorizedKeyFile(path string) (KeyWhitelist, error) {
	resolved, err := fspath.ExpandHome(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("sshserver: 读取 authorized_keys %s 失败: %w", resolved, err)
	}

	var keys KeyWhitelist
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
		if err != nil {
			return nil, fmt.Errorf("sshserver: %s 第 %d 行不是合法的公钥: %w", resolved, i+1, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}
