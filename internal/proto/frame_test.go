package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestFrameRoundTripPreservesPayload(t *testing.T) {
	sizes := []int{0, 1, 2, 4, 63, 1280, 1500, HeaderSize, MaxFrameSize}

	for _, size := range sizes {
		t.Run(itoa(size), func(t *testing.T) {
			// Arrange
			payload := bytes.Repeat([]byte{0xAB}, size)
			var stream bytes.Buffer

			// Act
			if err := WriteFrame(&stream, payload); err != nil {
				t.Fatalf("WriteFrame(%d) 返回错误: %v", size, err)
			}
			got, err := ReadFrame(&stream, nil)

			// Assert
			if err != nil {
				t.Fatalf("ReadFrame 返回错误: %v", err)
			}
			if len(got) != size {
				t.Fatalf("包体长度 = %d，期望 %d", len(got), size)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("包体内容与写入的不一致")
			}
			if stream.Len() != 0 {
				t.Fatalf("读取后流中残留 %d 字节", stream.Len())
			}
		})
	}
}

func TestReadFrameReturnsEOFAtCleanBoundary(t *testing.T) {
	// Arrange：空流等价于"上一帧刚结束"
	stream := bytes.NewReader(nil)

	// Act
	_, err := ReadFrame(stream, nil)

	// Assert
	if !errors.Is(err, io.EOF) {
		t.Fatalf("错误 = %v，期望 io.EOF", err)
	}
}

func TestReadFrameReturnsUnexpectedEOFOnPartialHeader(t *testing.T) {
	// Arrange：只给了 2 字节，不足 4 字节的长度前缀
	stream := bytes.NewReader([]byte{0x00, 0x00})

	// Act
	_, err := ReadFrame(stream, nil)

	// Assert
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("错误 = %v，期望 io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameReturnsUnexpectedEOFOnTruncatedBody(t *testing.T) {
	// Arrange：声明 16 字节包体，实际只给 4 字节
	stream := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x10, 1, 2, 3, 4})

	// Act
	_, err := ReadFrame(stream, nil)

	// Assert
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("错误 = %v，期望 io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameRejectsOversizedLengthBeforeReadingBody(t *testing.T) {
	// Arrange：长度前缀声明 MaxFrameSize+1，但后面一个字节都没有。
	// 若实现先按声明长度分配/读取，这里会阻塞或浪费 64KiB；正确行为是立刻报错。
	var header [HeaderSize]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
	stream := bytes.NewReader(header[:])

	// Act
	got, err := ReadFrame(stream, nil)

	// Assert
	if err == nil {
		t.Fatal("期望报错，却成功返回了")
	}
	if got != nil {
		t.Fatalf("出错时返回值应为 nil，实际为 %d 字节", len(got))
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	// Arrange
	var stream bytes.Buffer
	payload := make([]byte, MaxFrameSize+1)

	// Act
	err := WriteFrame(&stream, payload)

	// Assert
	if err == nil {
		t.Fatal("期望拒绝超长包体，却成功了")
	}
	if stream.Len() != 0 {
		t.Fatalf("被拒绝的帧不应写入任何字节，实际写入 %d 字节", stream.Len())
	}
}

func TestReadFrameReusesProvidedBuffer(t *testing.T) {
	// Arrange
	var stream bytes.Buffer
	payload := []byte("reuse-me")
	if err := WriteFrame(&stream, payload); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}
	buf := make([]byte, 0, 1024)
	bufPtr := &buf[:1][0]

	// Act
	got, err := ReadFrame(&stream, buf)

	// Assert
	if err != nil {
		t.Fatalf("ReadFrame 返回错误: %v", err)
	}
	if &got[0] != bufPtr {
		t.Fatal("容量足够时应当复用调用方提供的缓冲区，实际发生了重新分配")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("包体 = %q，期望 %q", got, payload)
	}
}

func TestReadFrameHandlesShortReads(t *testing.T) {
	// Arrange：OneByteReader 每次只吐 1 字节，模拟 TCP 分片
	var stream bytes.Buffer
	want := bytes.Repeat([]byte{0x5A}, 300)
	if err := WriteFrame(&stream, want); err != nil {
		t.Fatalf("准备数据失败: %v", err)
	}

	// Act
	got, err := ReadFrame(iotest.OneByteReader(&stream), nil)

	// Assert
	if err != nil {
		t.Fatalf("ReadFrame 返回错误: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("逐字节读取后内容与写入的不一致")
	}
}

func TestFramesAreSequentialInOneStream(t *testing.T) {
	// Arrange：连续 3 帧写进同一条流
	want := [][]byte{[]byte("first"), {}, []byte("third")}
	var stream bytes.Buffer
	for _, p := range want {
		if err := WriteFrame(&stream, p); err != nil {
			t.Fatalf("WriteFrame 返回错误: %v", err)
		}
	}

	// Act & Assert：按顺序逐帧读出，内容必须一一对应
	for i, expected := range want {
		got, err := ReadFrame(&stream, nil)
		if err != nil {
			t.Fatalf("第 %d 帧读取失败: %v", i, err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("第 %d 帧 = %q，期望 %q", i, got, expected)
		}
	}
	// 读完之后应当正好落在干净的边界上
	if _, err := ReadFrame(&stream, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("全部读完后错误 = %v，期望 io.EOF", err)
	}
}

// itoa 避免为测试引入 strconv 依赖，让子测试名保持简短。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
