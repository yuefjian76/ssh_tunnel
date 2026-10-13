package proto

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// MinMTU 是协议允许的最小隧道 MTU。低于 IPv6 最小 MTU（1280）的隧道
// 会让上层协议无法可靠工作，因此直接在边界上拒绝。
const MinMTU = 1280

// MaxMTU 是协议允许的最大隧道 MTU。取值高于常见物理链路 MTU，留出余量，
// 真正的约束由双端实测决定。
const MaxMTU = 9000

// EncodeRequest 把协商请求序列化为 channel-open 的 payload。
func EncodeRequest(req Request) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("proto: 编码 Request 失败: %w", err)
	}
	return payload, nil
}

// DecodeRequest 解析对端在 channel-open 时携带的 payload。
// 会一并执行校验，因此调用方拿到的一定是合法请求。
func DecodeRequest(payload []byte) (Request, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return Request{}, fmt.Errorf("proto: 解码 Request 失败: %w", err)
	}
	if err := req.Validate(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// EncodeResponse 把协商结果序列化为一个帧的 payload。
func EncodeResponse(resp Response) ([]byte, error) {
	if err := resp.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("proto: 编码 Response 失败: %w", err)
	}
	return payload, nil
}

// DecodeResponse 解析服务端回写的协商结果。
func DecodeResponse(payload []byte) (Response, error) {
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		return Response{}, fmt.Errorf("proto: 解码 Response 失败: %w", err)
	}
	if err := resp.Validate(); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// Validate 校验协商请求。系统边界上的输入一律先校验再使用。
func (r Request) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("proto: 协议版本不匹配，客户端 %d，本端支持 %d", r.Version, Version)
	}
	if _, err := netip.ParseAddr(r.ClientIP); err != nil {
		return fmt.Errorf("proto: 客户端隧道地址 %q 非法: %w", r.ClientIP, err)
	}
	return validateMTU(r.MTU)
}

// Validate 校验协商结果。
func (r Response) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("proto: 协议版本不匹配，服务端 %d，本端支持 %d", r.Version, Version)
	}
	if _, err := netip.ParseAddr(r.ServerIP); err != nil {
		return fmt.Errorf("proto: 服务端隧道地址 %q 非法: %w", r.ServerIP, err)
	}
	clientAddr, err := netip.ParseAddr(r.ClientIP)
	if err != nil {
		return fmt.Errorf("proto: 客户端隧道地址 %q 非法: %w", r.ClientIP, err)
	}
	if r.PrefixLen < 0 || r.PrefixLen > clientAddr.BitLen() {
		return fmt.Errorf("proto: 掩码长度 %d 对地址 %s 非法", r.PrefixLen, clientAddr)
	}
	return validateMTU(r.MTU)
}

func validateMTU(mtu int) error {
	if mtu < MinMTU || mtu > MaxMTU {
		return fmt.Errorf("proto: MTU %d 超出允许范围 [%d, %d]", mtu, MinMTU, MaxMTU)
	}
	return nil
}
