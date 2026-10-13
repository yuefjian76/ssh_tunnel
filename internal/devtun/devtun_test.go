package devtun

import (
	"bytes"
	"testing"
)

// TestOpenRejectsNonPositiveMTU 覆盖唯一无需 root 的路径：
// MTU 校验发生在创建内核接口之前，因此可以离线测试。
func TestOpenRejectsNonPositiveMTU(t *testing.T) {
	for _, mtu := range []int{0, -1, -1400} {
		t.Run("mtu", func(t *testing.T) {
			// Act
			dev, err := Open("utun", mtu)

			// Assert
			if err == nil {
				t.Fatalf("MTU=%d 应当被拒绝，却创建成功了", mtu)
			}
			if dev != nil {
				t.Fatalf("出错时不应返回设备，实际返回 %v", dev)
			}
		})
	}
}

func TestDefaultDeviceNameIsUsable(t *testing.T) {
	// Act
	name := defaultDeviceName()

	// Assert
	if name == "" {
		t.Fatal("平台默认网卡名不能为空")
	}
}

func TestPacketSliceReturnsPayloadAtOffset(t *testing.T) {
	// Arrange：缓冲足够大，载荷应当落在 [packetOffset, packetOffset+size)
	buf := make([]byte, packetOffset+1500)
	want := []byte{0x45, 0x00, 0x00, 0x54} // 一个 IPv4 头的开头
	copy(buf[packetOffset:], want)

	// Act
	got, err := packetSlice(buf, 1, len(want))

	// Assert
	if err != nil {
		t.Fatalf("packetSlice 返回错误: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("载荷 = %x，期望 %x", got, want)
	}
	if &got[0] != &buf[packetOffset] {
		t.Fatal("载荷应当直接指向缓冲内的位置，而不是拷贝")
	}
}

func TestPacketSliceRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		n    int
		size int
	}{
		{"零个包且无错误", 0, 100},
		{"包长为零", 1, 0},
		{"包长为负", 1, -1},
		{"包长超出缓冲容量", 1, 1500},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange：缓冲容量恰好为一个 MTU，装不下 1500 字节载荷
			buf := make([]byte, packetOffset+1280)

			// Act
			got, err := packetSlice(buf, tc.n, tc.size)

			// Assert
			if err == nil {
				t.Fatalf("n=%d size=%d 应当被拒绝，却返回了 %d 字节", tc.n, tc.size, len(got))
			}
			if got != nil {
				t.Fatalf("出错时返回值应为 nil，实际为 %d 字节", len(got))
			}
		})
	}
}

// TestPacketSliceAcceptsFullMTUPacket 是上面拒绝用例的正向对照，
// 避免那组断言因为条件恒不成立而变成假阳性。
func TestPacketSliceAcceptsFullMTUPacket(t *testing.T) {
	// Arrange
	const mtu = 1280
	buf := make([]byte, packetOffset+mtu)

	// Act
	got, err := packetSlice(buf, 1, mtu)

	// Assert
	if err != nil {
		t.Fatalf("恰好一个 MTU 的包应当被接受，实际: %v", err)
	}
	if len(got) != mtu {
		t.Fatalf("载荷长度 = %d，期望 %d", len(got), mtu)
	}
}
