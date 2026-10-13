package proto

import (
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	// Arrange
	want := Request{Version: Version, ClientIP: "10.9.0.2", MTU: 1280}

	// Act
	payload, err := EncodeRequest(want)
	if err != nil {
		t.Fatalf("EncodeRequest 返回错误: %v", err)
	}
	got, err := DecodeRequest(payload)

	// Assert
	if err != nil {
		t.Fatalf("DecodeRequest 返回错误: %v", err)
	}
	if got != want {
		t.Fatalf("往返后 = %+v，期望 %+v", got, want)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	// Arrange
	want := Response{
		Version:   Version,
		ServerIP:  "10.9.0.1",
		ClientIP:  "10.9.0.2",
		PrefixLen: 24,
		MTU:       1280,
	}

	// Act
	payload, err := EncodeResponse(want)
	if err != nil {
		t.Fatalf("EncodeResponse 返回错误: %v", err)
	}
	got, err := DecodeResponse(payload)

	// Assert
	if err != nil {
		t.Fatalf("DecodeResponse 返回错误: %v", err)
	}
	if got != want {
		t.Fatalf("往返后 = %+v，期望 %+v", got, want)
	}
}

func TestRequestValidateRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{"协议版本过旧", Request{Version: Version - 1, ClientIP: "10.9.0.2", MTU: 1280}},
		{"协议版本过新", Request{Version: Version + 1, ClientIP: "10.9.0.2", MTU: 1280}},
		{"版本号缺失", Request{ClientIP: "10.9.0.2", MTU: 1280}},
		{"地址为空", Request{Version: Version, ClientIP: "", MTU: 1280}},
		{"地址不是 IP", Request{Version: Version, ClientIP: "not-an-ip", MTU: 1280}},
		{"地址带掩码", Request{Version: Version, ClientIP: "10.9.0.2/24", MTU: 1280}},
		{"MTU 低于下限", Request{Version: Version, ClientIP: "10.9.0.2", MTU: MinMTU - 1}},
		{"MTU 高于上限", Request{Version: Version, ClientIP: "10.9.0.2", MTU: MaxMTU + 1}},
		{"MTU 为零", Request{Version: Version, ClientIP: "10.9.0.2", MTU: 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.req.Validate()

			// Assert
			if err == nil {
				t.Fatalf("期望拒绝 %+v，却通过了校验", tc.req)
			}
		})
	}
}

func TestRequestValidateAcceptsBoundaryMTU(t *testing.T) {
	for _, mtu := range []int{MinMTU, MaxMTU} {
		// Arrange
		req := Request{Version: Version, ClientIP: "10.9.0.2", MTU: mtu}

		// Act
		err := req.Validate()

		// Assert
		if err != nil {
			t.Fatalf("MTU=%d 位于允许范围边界，应当通过，实际: %v", mtu, err)
		}
	}
}

func TestEncodeRequestValidatesBeforeEmittingBytes(t *testing.T) {
	// Arrange
	bad := Request{Version: Version, ClientIP: "10.9.0.2", MTU: 0}

	// Act
	payload, err := EncodeRequest(bad)

	// Assert
	if err == nil {
		t.Fatal("期望编码前校验失败，却成功了")
	}
	if payload != nil {
		t.Fatalf("校验失败时不应产出字节，实际产出 %d 字节", len(payload))
	}
}

func TestDecodeRequestRejectsMalformedPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"不是 JSON", "}}}garbage"},
		{"JSON 但字段缺失", `{"version":1}`},
		{"JSON 但类型错误", `{"version":"1","client_ip":"10.9.0.2","mtu":1280}`},
		{"空 payload", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, err := DecodeRequest([]byte(tc.payload))

			// Assert
			if err == nil {
				t.Fatalf("期望拒绝 payload %q，却解析成功了", tc.payload)
			}
		})
	}
}

func TestResponseValidateRejectsBadInput(t *testing.T) {
	valid := Response{
		Version:   Version,
		ServerIP:  "10.9.0.1",
		ClientIP:  "10.9.0.2",
		PrefixLen: 24,
		MTU:       1280,
	}

	tests := []struct {
		name   string
		mutate func(Response) Response
	}{
		{"协议版本不匹配", func(r Response) Response { r.Version = Version + 1; return r }},
		{"服务端地址非法", func(r Response) Response { r.ServerIP = "10.9.0.999"; return r }},
		{"客户端地址非法", func(r Response) Response { r.ClientIP = "abc"; return r }},
		{"掩码长度为负", func(r Response) Response { r.PrefixLen = -1; return r }},
		{"掩码长度超过地址位宽", func(r Response) Response { r.PrefixLen = 33; return r }},
		{"MTU 越界", func(r Response) Response { r.MTU = 1; return r }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := tc.mutate(valid).Validate()

			// Assert
			if err == nil {
				t.Fatal("期望校验失败，却通过了")
			}
		})
	}

	// 反例：未改动的合法响应必须通过，否则上面的用例可能是"恒为真"的假阳性
	if err := valid.Validate(); err != nil {
		t.Fatalf("合法响应不应被拒绝: %v", err)
	}
}

func TestResponseTunnelPrefix(t *testing.T) {
	// Arrange
	resp := Response{
		Version:   Version,
		ServerIP:  "10.9.0.1",
		ClientIP:  "10.9.0.2",
		PrefixLen: 24,
		MTU:       1280,
	}

	// Act
	prefix, err := resp.TunnelPrefix()

	// Assert
	if err != nil {
		t.Fatalf("TunnelPrefix 返回错误: %v", err)
	}
	if got, want := prefix.String(), "10.9.0.0/24"; got != want {
		t.Fatalf("隧道网段 = %s，期望 %s", got, want)
	}
}

func TestResponseTunnelPrefixRejectsUnparseableAddress(t *testing.T) {
	// Arrange：绕过 Validate 直接构造非法响应，确认 TunnelPrefix 自身也做防御
	resp := Response{ServerIP: "not-an-ip", PrefixLen: 24}

	// Act
	_, err := resp.TunnelPrefix()

	// Assert
	if err == nil {
		t.Fatal("期望拒绝非法服务端地址，却成功了")
	}
}
