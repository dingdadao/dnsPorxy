package dns

import (
	"net/netip"
	"testing"

	"dnsPorxy/internal/config"

	"github.com/miekg/dns"
)

// TestECSSummaryFor_AutoIPv4 自动模式下日志应记录实际注入的前缀
func TestECSSummaryFor_AutoIPv4(t *testing.T) {
	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	got := ecsSummaryFor(nil, d, netip.MustParseAddr("223.104.134.252"))
	if got != "注入 223.104.134.0/24" {
		t.Fatalf("期望 注入 223.104.134.0/24，实际 %q", got)
	}
}

// TestECSSummaryFor_AutoPrivate 内网客户端：Auto 模式不注入，日志应为空
func TestECSSummaryFor_AutoPrivate(t *testing.T) {
	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	got := ecsSummaryFor(nil, d, netip.MustParseAddr("10.0.0.4"))
	if got != "" {
		t.Fatalf("内网客户端不应记录注入，实际 %q", got)
	}
}

// TestECSSummaryFor_ManualUnchanged 手动模式回归保护
func TestECSSummaryFor_ManualUnchanged(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeUnicom, Subnet: "58.20.127.238/24"},
	}
	got := ecsSummaryFor(nil, d, netip.MustParseAddr("223.104.134.252"))
	if got != "注入 58.20.127.0/24" {
		t.Fatalf("手动模式应记录配置值，实际 %q", got)
	}
}

// TestECSSummaryFor_StripsClientECS 未注入但客户端自带 ECS 时应记录“剥离”
func TestECSSummaryFor_StripsClientECS(t *testing.T) {
	req := newECSReq()
	req.SetEdns0(1232, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: netip.MustParseAddr("1.2.3.4").AsSlice(),
	})

	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	got := ecsSummaryFor(req, d, netip.MustParseAddr("10.0.0.4"))
	if got != "剥离客户端 ECS" {
		t.Fatalf("期望 剥离客户端 ECS，实际 %q", got)
	}
}
