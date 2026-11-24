package dns

import (
	"net/netip"
	"testing"

	"dnsPorxy/internal/config"

	"github.com/miekg/dns"
)

// ecsOf 从请求里取出注入的 ECS 前缀描述，无 ECS 返回空串
func ecsOf(t *testing.T, m *dns.Msg) string {
	t.Helper()
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if sn, ok := o.(*dns.EDNS0_SUBNET); ok {
			addr, ok := netip.AddrFromSlice(sn.Address)
			if !ok {
				return "?"
			}
			p := netip.PrefixFrom(addr, int(sn.SourceNetmask))
			return p.Masked().String()
		}
	}
	return ""
}

func newECSReq() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	return m
}

// TestECSAuto_IPv4 自动模式：IPv4 客户端取 /24
func TestECSAuto_IPv4(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, Auto: true},
	}
	ip := netip.MustParseAddr("223.104.134.252")

	got := applySplitECS(newECSReq(), d, ip)
	if s := ecsOf(t, got); s != "223.104.134.0/24" {
		t.Fatalf("期望 223.104.134.0/24，实际 %q", s)
	}
}

// TestECSAuto_IPv6 自动模式：IPv6 客户端取 /56
func TestECSAuto_IPv6(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, Auto: true},
	}
	ip := netip.MustParseAddr("2408:8352:e40:548a:70c5:3825:5e9f:31cf")

	got := applySplitECS(newECSReq(), d, ip)
	// /56 的定界点在第 56 位：5400::（不是 548a::）
	want := "2408:8352:e40:5400::/56"
	if s := ecsOf(t, got); s != want {
		t.Fatalf("期望 %s，实际 %q", want, s)
	}
}

// TestECSAuto_PrivateNotInjected 内网客户端不注入（避免把私网段发给上游）
func TestECSAuto_PrivateNotInjected(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, Auto: true},
	}
	for _, ipStr := range []string{"10.0.0.4", "192.168.1.10", "172.16.5.5", "127.0.0.1", "::1", "fe80::1"} {
		ip := netip.MustParseAddr(ipStr)
		got := applySplitECS(newECSReq(), d, ip)
		if s := ecsOf(t, got); s != "" {
			t.Fatalf("%s 是内网/回环地址，不该注入 ECS，实际注入 %q", ipStr, s)
		}
	}
}

// TestECSAuto_InvalidAddr 无效地址不注入也不崩
func TestECSAuto_InvalidAddr(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, Auto: true},
	}
	got := applySplitECS(newECSReq(), d, netip.Addr{})
	if s := ecsOf(t, got); s != "" {
		t.Fatalf("无效客户端地址不该注入，实际 %q", s)
	}
}

// TestECSManual_Unchanged 手动模式行为不变（回归保护）
func TestECSManual_Unchanged(t *testing.T) {
	d := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeUnicom, Subnet: "58.20.127.238/24"},
	}
	// 客户端是移动 IP，但手动模式必须仍是配置里的联通段
	ip := netip.MustParseAddr("223.104.134.252")

	got := applySplitECS(newECSReq(), d, ip)
	if s := ecsOf(t, got); s != "58.20.127.0/24" {
		t.Fatalf("手动模式应保持配置值 58.20.127.0/24，实际 %q", s)
	}
}

// TestECSAuto_StripsClientECS 客户端自带的 ECS 必须先剥离再注入自己的
func TestECSAuto_StripsClientECS(t *testing.T) {
	req := newECSReq()
	req.SetEdns0(1232, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: netip.MustParseAddr("1.2.3.4").AsSlice(),
	})

	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	got := applySplitECS(req, d, netip.MustParseAddr("223.104.134.252"))

	if s := ecsOf(t, got); s != "223.104.134.0/24" {
		t.Fatalf("应注入客户端推导值，实际 %q", s)
	}
	// 原请求不能被污染（single-flight 复用）
	if s := ecsOf(t, req); s != "1.2.3.0/24" {
		t.Fatalf("原请求被就地修改了，实际 %q", s)
	}
}

// TestECSAuto_Disabled 关闭时不注入也不崩溃
func TestECSAuto_Disabled(t *testing.T) {
	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: false, Auto: true}}
	got := applySplitECS(newECSReq(), d, netip.MustParseAddr("223.104.134.252"))
	if s := ecsOf(t, got); s != "" {
		t.Fatalf("未启用时不该注入，实际 %q", s)
	}
}
