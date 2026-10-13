package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevelAcceptsKnownNames(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want slog.Level
	}{
		{"缺省即 info", "", slog.LevelInfo},
		{"info", "info", slog.LevelInfo},
		{"大小写不敏感", "INFO", slog.LevelInfo},
		{"忽略首尾空白", " debug ", slog.LevelDebug},
		{"warn 简写", "warn", slog.LevelWarn},
		{"warning 全称", "warning", slog.LevelWarn},
		{"error", "error", slog.LevelError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := ParseLevel(tc.in)

			// Assert
			if err != nil {
				t.Fatalf("ParseLevel(%q) 返回错误: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseLevel(%q) = %v，期望 %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseLevelRejectsUnknownName 守住「拼错必须报错」这条约定：
// 若静默回退到 info，用户会以为 debug 日志已开启，实际却没开。
func TestParseLevelRejectsUnknownName(t *testing.T) {
	for _, in := range []string{"verbose", "trace", "inf", "1", "deug"} {
		t.Run(in, func(t *testing.T) {
			// Act
			_, err := ParseLevel(in)

			// Assert
			if err == nil {
				t.Fatalf("ParseLevel(%q) 应当被拒绝，却通过了", in)
			}
		})
	}
}

func TestNewPropagatesLevelErrors(t *testing.T) {
	// Arrange & Act：合法级别应当拿到可用的 logger
	logger, err := New("debug")

	// Assert
	if err != nil {
		t.Fatalf("合法级别不应报错: %v", err)
	}
	if logger == nil {
		t.Fatal("logger 不应为 nil")
	}

	// Act & Assert：非法级别必须把错误透传出来
	if _, err := New("nope"); err == nil {
		t.Fatal("非法级别应当报错")
	}
}
