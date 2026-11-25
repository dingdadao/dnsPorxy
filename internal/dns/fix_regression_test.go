package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// ECS 自动模式必须按推导前缀分区：不同网段的客户端不能互相命中对方的结果。
func TestCacheScopeForECSAuto(t *testing.T) {
	auto := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	a := netip.MustParseAddr("203.0.113.9")
	b := netip.MustParseAddr("198.51.100.7")

	sa, sb := cacheScopeFor("-", auto, a), cacheScopeFor("-", auto, b)
	if sa == sb {
		t.Fatalf("不同 /24 应得到不同缓存作用域，实际都是 %q", sa)
	}
	if sa != "-|ecs:203.0.113.0/24" {
		t.Fatalf("作用域格式不符：%q", sa)
	}
	// 同一 /24 内必须一致，否则缓存命中率会被打散
	if got := cacheScopeFor("-", auto, netip.MustParseAddr("203.0.113.200")); got != sa {
		t.Fatalf("同网段应共享作用域：%q != %q", got, sa)
	}
	// 内网客户端不注入 ECS，也不分区
	if got := cacheScopeFor("-", auto, netip.MustParseAddr("192.168.1.5")); got != "-" {
		t.Fatalf("内网地址不应分区：%q", got)
	}
	// 手动 ECS（固定 subnet）所有客户端同一份结果，不分区
	manual := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, ISPType: "telecom", Subnet: "8.8.8.0/24"}}
	if got := cacheScopeFor("-", manual, a); got != "-" {
		t.Fatalf("手动模式不应分区：%q", got)
	}
	// 未命中分流列表不干预 ECS，不分区
	if got := cacheScopeFor("-", SplitDecision{Matched: false, ECS: auto.ECS}, a); got != "-" {
		t.Fatalf("未命中列表不应分区：%q", got)
	}
}

// 不同 ECS 前缀的缓存必须真正隔离（同域名各存一份）。
func TestCacheScopeIsolatesCacheEntries(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	d := SplitDecision{Matched: true, ECS: config.ECSPolicy{Enabled: true, Auto: true}}
	s1 := cacheScopeFor("-", d, netip.MustParseAddr("203.0.113.9"))
	s2 := cacheScopeFor("-", d, netip.MustParseAddr("198.51.100.7"))

	c.Set(s1, "x.example", dns.TypeA, makeAResp("x.example", 60), false)
	if _, hit, _, _ := c.GetWithFlight(s2, "x.example", dns.TypeA); hit {
		t.Fatal("另一个 ECS 网段命中了不属于它的缓存")
	}
	if _, hit, _, _ := c.GetWithFlight(s1, "x.example", dns.TypeA); !hit {
		t.Fatal("同网段缓存应命中")
	}
}

// 缓存命中的 TTL 只能被 max_ttl 压小，不能被 min_ttl 抬回。
func TestCachedHitTTLNotRaisedByMin(t *testing.T) {
	c := NewOptimizedDNSCache(1000, 5*time.Minute)
	c.SetTTLBounds(300*time.Second, 0)

	// 上游给 2s，写入缓存时被下限抬到 300s
	c.Set("-", "hit.example", dns.TypeA, makeAResp("hit.example", 2), false)
	time.Sleep(1200 * time.Millisecond)

	resp, hit, _, _ := c.GetWithFlight("-", "hit.example", dns.TypeA)
	if !hit {
		t.Fatal("缓存应命中")
	}
	before := resp.Answer[0].Header().Ttl
	if before >= 300 {
		t.Fatalf("命中响应 TTL 应已按缓存时长递减，实际 %d", before)
	}
	c.applyTTLUpperBound(resp)
	if after := resp.Answer[0].Header().Ttl; after != before {
		t.Fatalf("命中出口不该改动 TTL：%d → %d", before, after)
	}

	// 对照：完整钳制（上游新鲜响应走 writeResponse）仍然会抬到下限
	fresh := makeAResp("hit.example", 1)
	c.applyTTLBounds(fresh)
	if got := fresh.Answer[0].Header().Ttl; got != 300 {
		t.Fatalf("上游新鲜响应的下限钳制失效：%d", got)
	}
}

// 上游返回 >512B 的 UDP 响应（部分运营商/家用 DNS 不按 512 截断）时必须能读回，
// 旧实现用默认 512 读缓冲会解包失败并把查询误判成上游故障。
func TestUpstreamLargeUDPResponseAccepted(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 UDP 失败: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for i := 0; i < 40; i++ {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(10, 2, byte(i/256), byte(i%256)),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, 2*time.Second)

	req := new(dns.Msg)
	req.SetQuestion("big.test.", dns.TypeA)
	resp, err := qo.queryUDP(req, "udp://"+pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("大响应 UDP 查询失败（读缓冲不足？）: %v", err)
	}
	if resp == nil || len(resp.Answer) != 40 {
		t.Fatalf("应答记录数不符：%v", resp)
	}
}

// 满容量写入后总量不能突破容量（采样淘汰必须仍然守住上限）。
func TestEvictKeepsSizeUnderCapacity(t *testing.T) {
	c := NewOptimizedDNSCache(5000, 5*time.Minute)
	c.SetMemoryBudget(0)
	resp := makeAResp("f.example", 300)
	for i := 0; i < 5000; i++ {
		c.Set("-", "f"+itoa(uint32(i))+".example", dns.TypeA, resp, false)
	}
	filled := c.GetStats(false).Size
	if filled < 4800 || filled > 5000 {
		t.Fatalf("填充 5000 条后总量应接近 5000（分片余数已分配），实际 %d", filled)
	}
	for i := 0; i < 500; i++ {
		c.Set("-", "new"+itoa(uint32(i))+".example", dns.TypeA, resp, false)
	}
	if got := c.GetStats(false).Size; got > 5000 {
		t.Fatalf("容量被突破：%d > 5000", got)
	}
}

// max_items 小于分片数时，每片容量按 1 兜底，而不是 0（0 会让每次写入都淘汰）。
func TestShardCapacityAtLeastOne(t *testing.T) {
	c := NewOptimizedDNSCache(8, 5*time.Minute)
	if got := c.shardCapacity(0); got < 1 {
		t.Fatalf("max_items 小于分片数时每片容量至少为 1，实际 %d", got)
	}
	resp := makeAResp("s.example", 300)
	for i := 0; i < 200; i++ {
		c.Set("-", "s"+itoa(uint32(i))+".example", dns.TypeA, resp, false)
	}
	if got := c.GetStats(false).Size; got > c.shardCount {
		t.Fatalf("每片最多 1 条，总量应 ≤ %d，实际 %d", c.shardCount, got)
	}
}

// 总预算到点必须真正中止在途上游请求（ctx 取消），而不是只让调用方不等结果。
// 旧实现的 goroutine 会继续跑到单台超时，上游变慢时会把上游 QPS 按并发放大。
func TestQueryCtxCancelsSlowUpstream(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 UDP 失败: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(9, 9, 9, 9),
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("slow.example.", dns.TypeA)
	start := time.Now()
	res := qo.QueryCtx(ctx, req, []string{"udp://" + pc.LocalAddr().String()})
	elapsed := time.Since(start)

	if elapsed > 400*time.Millisecond {
		t.Fatalf("ctx 取消没有中止在途请求：耗时 %s（单台超时 5s，预算 80ms）", elapsed)
	}
	if res.HasSuccess {
		t.Fatal("取消的查询不该返回成功结果")
	}
}

// 串行模式在 ctx 取消后不得再发起下一台上游。
func TestFailoverCtxStopsAfterCancel(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 UDP 失败: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(9, 9, 9, 8),
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, 5*time.Second)
	addr := "udp://" + pc.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	req := new(dns.Msg)
	req.SetQuestion("slow2.example.", dns.TypeA)
	res := qo.QueryFailoverCtx(ctx, req, []string{addr, addr}, 0)

	if len(res.AllResults) != 1 {
		t.Fatalf("ctx 取消后应只尝试 1 台，实际 %d 台（%+v）", len(res.AllResults), res.AllResults)
	}
}
