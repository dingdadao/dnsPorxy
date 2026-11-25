package dns

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// 缓存命中走 wire 快路径时，DoH 响应必须带 Content-Type: application/dns-message。
// 旧实现只写字节不设头，Go 会嗅探成 application/octet-stream，
// 严格的 DoH 客户端（systemd-resolved 等）会直接拒绝该响应。
func TestDoHWireWriteSetsHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/dns-query", nil)
	dw := newDoHResponseWriter(rec, req, netip.MustParseAddr("203.0.113.9"), "socket", "DoH")

	wire, err := makeAResp("wire.example", 42).Pack()
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	if _, err := dw.Write(wire); err != nil {
		t.Fatalf("写出失败: %v", err)
	}

	if got := rec.Header().Get("Content-Type"); got != dohMediaType {
		t.Fatalf("Content-Type = %q，应为 %q", got, dohMediaType)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "max-age=42") {
		t.Fatalf("Cache-Control = %q，应包含 max-age=42", got)
	}
	if rec.Code != 200 {
		t.Fatalf("状态码 = %d", rec.Code)
	}
}

// WriteMsg 路径（首次未命中）保持原有行为。
func TestDoHWriteMsgSetsHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/dns-query", nil)
	dw := newDoHResponseWriter(rec, req, netip.MustParseAddr("203.0.113.9"), "socket", "DoH")

	if err := dw.WriteMsg(makeAResp("msg.example", 7)); err != nil {
		t.Fatalf("写出失败: %v", err)
	}
	if got := rec.Header().Get("Content-Type"); got != dohMediaType {
		t.Fatalf("Content-Type = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=7") {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}
