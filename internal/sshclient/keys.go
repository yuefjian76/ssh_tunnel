package sshclient

import (
	"fmt"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/yuefjian76/ssh_tunnel/internal/fspath"
)

// LoadSigner 读取 PEM 私钥并解析为 Signer。
//
// 私钥内容绝不进入日志或错误信息：出错时只回路径与失败原因，
// 因为错误信息常常会被贴进 issue、写进日志聚合系统。
func LoadSigner(path string) (gossh.Signer, error) {
	expanded, err := fspath.ExpandHome(path)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 读取私钥失败: %w", err)
	}

	signer, err := gossh.ParsePrivateKey(raw)
	if err != nil {
		// ParsePrivateKey 的错误里不含密钥内容，可以安全透出，
		// 它给出的是「格式不对」还是「缺少口令」这类可操作的信息。
		return nil, fmt.Errorf("sshclient: 解析私钥 %s 失败: %w", path, err)
	}
	return signer, nil
}

// KnownHostsCallback 基于 known_hosts 构造外层主机密钥校验回调。
//
// 刻意不提供「跳过校验」的开关：那是个一旦存在就会被用上的后门。
// 若主机密钥真的变了，正确做法是人工核对后更新 known_hosts，
// 而不是让工具默默放行。
func KnownHostsCallback(path string) (gossh.HostKeyCallback, error) {
	expanded, err := fspath.ExpandHome(path)
	if err != nil {
		return nil, err
	}

	callback, err := knownhosts.New(expanded)
	if err != nil {
		return nil, fmt.Errorf("sshclient: 加载 known_hosts %s 失败: %w", path, err)
	}
	return callback, nil
}
