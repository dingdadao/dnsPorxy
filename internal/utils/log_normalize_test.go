package utils

import (
	"errors"
	"net"
	"testing"
)

// 日志字段里的 error 必须转成文本：直接 json.Marshal(error) 只会得到 {}，
// 排障时最关键的失败原因会全部丢失。
func TestNormalizeFieldsError(t *testing.T) {
	fields := map[string]interface{}{
		"error": errors.New("dial udp 127.0.0.1:53: i/o timeout"),
		"ok":    1,
	}
	got := normalizeFields(fields)
	s, ok := got["error"].(string)
	if !ok || s == "" {
		t.Fatalf("error 字段未转成字符串：%#v", got["error"])
	}
	if got["ok"] != 1 {
		t.Fatal("非 error 字段被改动")
	}
}

// typed nil 的 error（如 var e error = (*net.OpError)(nil)）不能 panic。
func TestNormalizeFieldsTypedNilError(t *testing.T) {
	var typedNil error = (*net.OpError)(nil)
	fields := map[string]interface{}{"error": typedNil}
	got := normalizeFields(fields)
	if got["error"] != nil {
		t.Fatalf("typed nil error 应归一化为 nil，实际 %#v", got["error"])
	}
}

// 没有 error 字段时不应重建 map（避免热路径上的额外分配）。
func TestNormalizeFieldsNoErrorKeepsMap(t *testing.T) {
	fields := map[string]interface{}{"domain": "a.example"}
	if got := normalizeFields(fields); len(got) != 1 || got["domain"] != "a.example" {
		t.Fatalf("普通字段被改动：%#v", got)
	}
}
