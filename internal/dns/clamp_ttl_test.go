package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// makeAResp 构造一个带指定 TTL 的 A 记录响应
func makeAResp(domain string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	rr, _ := dns.NewRR(m.Question[0].Name + " " + itoa(ttl) + " IN A 1.2.3.4")
	m.Answer = append(m.Answer, rr)
	return m
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

// TestClampTTL_Min 上游 TTL 过短时应被抬高到 min_ttl
func TestClampTTL_Min(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(60*time.Second, 0) // min=60s，不设上限

	c.Set("-", "short.example", dns.TypeA, makeAResp("short.example", 5), false)

	exp := c.GetExpireTime("-", "short.example", dns.TypeA)
	remaining := time.Until(exp)
	if remaining < 55*time.Second || remaining > 65*time.Second {
		t.Fatalf("TTL 未被抬高到 60s，实际剩余 %s", remaining)
	}
}

// TestClampTTL_Max 上游 TTL 过长时应被压到 max_ttl
func TestClampTTL_Max(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(0, 300*time.Second) // 不设下限，max=300s

	c.Set("-", "long.example", dns.TypeA, makeAResp("long.example", 86400), false)

	remaining := time.Until(c.GetExpireTime("-", "long.example", dns.TypeA))
	if remaining < 295*time.Second || remaining > 305*time.Second {
		t.Fatalf("TTL 未被压到 300s，实际剩余 %s", remaining)
	}
}

// TestClampTTL_InRange 区间内的 TTL 不应被改动
func TestClampTTL_InRange(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(10*time.Second, 3600*time.Second)

	c.Set("-", "mid.example", dns.TypeA, makeAResp("mid.example", 120), false)

	remaining := time.Until(c.GetExpireTime("-", "mid.example", dns.TypeA))
	if remaining < 115*time.Second || remaining > 125*time.Second {
		t.Fatalf("区间内 TTL 被意外改动，实际剩余 %s", remaining)
	}
}

// TestClampTTL_Disabled 两个都没配时不钳制
func TestClampTTL_Disabled(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(0, 0)

	c.Set("-", "raw.example", dns.TypeA, makeAResp("raw.example", 3), false)

	remaining := time.Until(c.GetExpireTime("-", "raw.example", dns.TypeA))
	if remaining < 2*time.Second || remaining > 4*time.Second {
		t.Fatalf("未启用钳制时 TTL 不该被改，实际剩余 %s", remaining)
	}
}

// TestClampTTL_NegativeNotRaised 负缓存（NXDOMAIN）不得被 min_ttl 抬高（RFC 2308）
func TestClampTTL_NegativeNotRaised(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(600*time.Second, 0) // min=10min

	neg := new(dns.Msg)
	neg.SetQuestion(dns.Fqdn("nx.example."), dns.TypeA)
	neg.Response = true
	neg.Rcode = dns.RcodeNameError // NXDOMAIN，无 Answer

	c.SetWithTTL("-", "nx.example", dns.TypeA, neg, false, 30*time.Second)

	remaining := time.Until(c.GetExpireTime("-", "nx.example", dns.TypeA))
	if remaining > 35*time.Second {
		t.Fatalf("负缓存被 min_ttl 抬高了，实际剩余 %s（应为 ~30s）", remaining)
	}
}

// TestClampTTL_HotUpdate 热更新后新的钳制立即生效
func TestClampTTL_HotUpdate(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(0, 1000*time.Second)

	c.Set("-", "before.example", dns.TypeA, makeAResp("before.example", 500), false)
	if r := time.Until(c.GetExpireTime("-", "before.example", dns.TypeA)); r < 495*time.Second {
		t.Fatalf("500s 在 max=1000 区间内不该被压，实际 %s", r)
	}

	// 热更新把上限压到 100s
	c.SetTTLBounds(0, 100*time.Second)
	c.Set("-", "after.example", dns.TypeA, makeAResp("after.example", 500), false)
	if r := time.Until(c.GetExpireTime("-", "after.example", dns.TypeA)); r > 105*time.Second {
		t.Fatalf("热更新未生效，实际剩余 %s（应为 ~100s）", r)
	}
}
