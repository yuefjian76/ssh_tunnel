package devtun

import (
	"os"
	"testing"
)

// TestOpenCreatesRealDevice 需要 root 与真实内核接口，默认跳过。
//
// 它把计划里「本机建 utun 并 ifconfig 可见」这一步固化成可复现的验证，
// 而不是每次手敲命令。macOS 创建 utun 必须 root，且 sudo 会重置 HOME/PATH，
// 故用 -E 保留环境、并显式给出 go 的绝对路径：
//
//	sudo -E SSHTUN_PROBE=1 \
//	  /Users/yuefengjiang/.local/bin/go test ./internal/devtun \
//	  -run TestOpenCreatesRealDevice -v
func TestOpenCreatesRealDevice(t *testing.T) {
	if os.Getenv("SSHTUN_PROBE") == "" {
		t.Skip("需要 root 与真实内核接口；设置 SSHTUN_PROBE=1 启用")
	}

	// Arrange
	const mtu = 1280

	// Act
	dev, err := Open("", mtu)

	// Assert
	if err != nil {
		t.Fatalf("创建隧道网卡失败: %v", err)
	}
	defer func() {
		if err := dev.Close(); err != nil {
			t.Errorf("关闭隧道网卡失败: %v", err)
		}
	}()

	// 请求名是平台默认值（macOS 为 "utun"），内核会换成具体的 utunN，
	// 所以这里断言的是「拿到了一个真实名字」而非名字等于请求值。
	name := dev.Name()
	t.Logf("已创建隧道网卡: name=%s mtu=%d", name, dev.MTU())
	if name == "" {
		t.Fatal("内核应当分配一个真实的网卡名")
	}
	if got := dev.MTU(); got != mtu {
		t.Errorf("MTU = %d，期望 %d", got, mtu)
	}
}
