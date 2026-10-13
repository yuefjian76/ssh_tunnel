// Package logging 提供统一的结构化日志入口。
package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// ParseLevel 把命令行传入的级别字符串转换为 slog.Level。
//
// 只接受明确列出的取值，拼错时直接报错而非静默回退到默认级别——
// 静默回退会让人以为已经开了 debug 日志，实际却没开。
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: 未知日志级别 %q（可选 debug/info/warn/error）", name)
	}
}

// New 创建输出到 stderr 的结构化日志器。
func New(level string) (*slog.Logger, error) {
	parsed, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parsed})
	return slog.New(handler), nil
}
