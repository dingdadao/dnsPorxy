package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestApplyTTLBounds_MinRewrite 下限应真实改写 RR 的 TTL（不只是过期时间）
func TestApplyTTLBounds_MinRewrite(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(300*time.Second, 0)

	m := makeAResp("short.example", 30)
	c.applyTTLBounds(m)

	if got := m.Answer[0].Header().Ttl; got != 300 {
		t.Fatalf("RR TTL 应被抬到 300，实际 %d", got)
	}
}

// TestApplyTTLBounds_MaxRewrite 上限应真实压小 RR 的 TTL
func TestApplyTTLBounds_MaxRewrite(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(0, 600*time.Second)

	m := makeAResp("long.example", 86400)
	c.applyTTLBounds(m)

	if got := m.Answer[0].Header().Ttl; got != 600 {
		t.Fatalf("RR TTL 应被压到 600，实际 %d", got)
	}
}

// TestApplyTTLBounds_OptUntouched OPT 记录承载 EDNS 标志，绝不能改
func TestApplyTTLBounds_OptUntouched(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(300*time.Second, 0)

	m := makeAResp("x.example", 30)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.SetDo()
	opt.Hdr.Ttl = 0x8000 // DO 位
	m.Extra = append(m.Extra, opt)

	c.applyTTLBounds(m)

	if opt.Hdr.Ttl != 0x8000 {
		t.Fatalf("OPT 的 TTL 字段被篡改：0x%x（DO 位会丢失）", opt.Hdr.Ttl)
	}
}

// TestApplyTTLBounds_NegativeNoMin NXDOMAIN 不得被抬高
func TestApplyTTLBounds_NegativeNoMin(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(600*time.Second, 0)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("nx.example."), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	// NXDOMAIN 通常带 SOA 在 Ns 段，SOA 的 TTL 就是负缓存时长
	soa, _ := dns.NewRR("example. 30 IN SOA ns.example. admin.example. 1 2 3 4 30")
	m.Ns = append(m.Ns, soa)

	c.applyTTLBounds(m)

	if got := m.Ns[0].Header().Ttl; got > 35 {
		t.Fatalf("负缓存的 SOA TTL 被 min_ttl 抬高了：%d（应保持 ~30）", got)
	}
}

// TestApplyTTLBounds_Disabled 未配置时不改动
func TestApplyTTLBounds_Disabled(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(0, 0)

	m := makeAResp("raw.example", 7)
	if changed := c.applyTTLBounds(m); changed {
		t.Fatal("未配置钳制时不该报告改写")
	}
	if got := m.Answer[0].Header().Ttl; got != 7 {
		t.Fatalf("TTL 不该被改，实际 %d", got)
	}
}

// TestSet_ClampReachesWire 端到端：Set 之后取出的响应，TTL 应是钳制后的值
func TestSet_ClampReachesWire(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(120*time.Second, 0)

	c.Set("-", "e2e.example", dns.TypeA, makeAResp("e2e.example", 5), false)

	s, ok := c.GetServe("-", "e2e.example", dns.TypeA)
	if !ok {
		t.Fatal("缓存应命中")
	}
	// 校验写入 wire 的 TTL 元信息已是钳制后的值
	for _, f := range s.Meta.ttls {
		if f.ttl < 119 {
			t.Fatalf("wire 里的 TTL 仍是原值 %d，钳制没落到 wire 上", f.ttl)
		}
	}
}
