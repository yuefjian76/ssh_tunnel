package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteFrame 写出一个长度前缀帧：4 字节大端长度 + 包体。
//
// 整帧通过单次 Write 提交，因此长度前缀与包体之间不可能被同一 writer 上
// 的其他帧插入。即便如此，调用方仍须保证同一时刻只有一个 goroutine 在写
// 同一个 writer（每个方向一个写协程即可），否则帧仍会互相穿插。
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("proto: 帧长 %d 超过上限 %d", len(payload), MaxFrameSize)
	}

	frame := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[:HeaderSize], uint32(len(payload)))
	copy(frame[HeaderSize:], payload)

	written, err := w.Write(frame)
	if err != nil {
		return fmt.Errorf("proto: 写帧失败: %w", err)
	}
	if written != len(frame) {
		return fmt.Errorf("proto: 写帧不完整，期望 %d 字节、实际 %d 字节: %w",
			len(frame), written, io.ErrShortWrite)
	}
	return nil
}

// ReadFrame 读出一个长度前缀帧的包体。
//
// buf 用于复用内存：容量足够时直接复用，否则新分配。返回的切片**可能指向
// buf**，因此调用方必须在下一次调用 ReadFrame 之前用完它。
//
// 错误语义沿用 io.ReadFull：流在帧边界处正常结束返回 io.EOF；帧读到一半
// 断开返回 io.ErrUnexpectedEOF；长度前缀超过 MaxFrameSize 时返回错误且不读包体。
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	length := int(binary.BigEndian.Uint32(header[:]))
	if length > MaxFrameSize {
		return nil, fmt.Errorf("proto: 对端声明的帧长 %d 超过上限 %d", length, MaxFrameSize)
	}

	if cap(buf) < length {
		buf = make([]byte, length)
	}
	buf = buf[:length]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
