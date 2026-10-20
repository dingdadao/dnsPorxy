package dns

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// 权重后缀剥离 + 默认权重：只有 "#<n>" 参与权重，地址部分一律剥净
func TestParseWeightedUpstreams(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, time.Second)
	t.Cleanup(qo.Close)

	got := qo.parseWeightedUpstreams([]string{
		"udp://1.1.1.1:53#70",
		"udp://8.8.8.8:53",     // 无后缀 → 默认权重 1
		"udp://9.9.9.9:53#0",   // 0 权重保留（禁用），仍会返回
		"ftp://bad.example#70", // 不支持协议 → 过滤
	})

	if len(got) != 3 {
		t.Fatalf("应保留 3 条有效上游，实际 %d: %+v", len(got), got)
	}
	want := []weightedUpstream{
		{server: "udp://1.1.1.1:53", weight: 70},
		{server: "udp://8.8.8.8:53", weight: defaultUpstreamWeight},
		{server: "udp://9.9.9.9:53", weight: 0},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条 = %+v，期望 %+v", i, got[i], want[i])
		}
	}
}

// 加权随机分布：70/20/10 的权重应落在合理区间；0 权重不参与；全 0 退化为等权
func TestPickWeightedIndexDistribution(t *testing.T) {
	const iters = 200000

	t.Run("按权重分布", func(t *testing.T) {
		ups := []weightedUpstream{
			{server: "a", weight: 70},
			{server: "b", weight: 20},
			{server: "c", weight: 10},
		}
		rnd := rand.New(rand.NewSource(42))
		counts := map[string]int{}
		for i := 0; i < iters; i++ {
			counts[ups[pickWeightedIndex(ups, rnd)].server]++
		}
		// 允许 ±3% 偏差
		checkRatio(t, counts["a"], iters, 0.70, 0.03)
		checkRatio(t, counts["b"], iters, 0.20, 0.03)
		checkRatio(t, counts["c"], iters, 0.10, 0.03)
	})

	t.Run("0 权重不参与随机", func(t *testing.T) {
		ups := []weightedUpstream{
			{server: "a", weight: 70},
			{server: "off", weight: 0},
			{server: "c", weight: 30},
		}
		rnd := rand.New(rand.NewSource(7))
		var offHits int
		for i := 0; i < iters; i++ {
			if ups[pickWeightedIndex(ups, rnd)].server == "off" {
				offHits++
			}
		}
		if offHits != 0 {
			t.Errorf("0 权重条目不应被选中，实际命中 %d 次", offHits)
		}
	})

	t.Run("全 0 权重退化为等权", func(t *testing.T) {
		ups := []weightedUpstream{{server: "a", weight: 0}, {server: "b", weight: 0}}
		rnd := rand.New(rand.NewSource(9))
		counts := map[string]int{}
		for i := 0; i < iters; i++ {
			counts[ups[pickWeightedIndex(ups, rnd)].server]++
		}
		if counts["a"] == 0 || counts["b"] == 0 {
			t.Errorf("全 0 权重应仍能选中各台，实际 %+v", counts)
		}
	})
}

// 权重随机每次 miss 只发 1 次：首选成功即不再联系其它上游
func TestQueryWeightedRandomSendsSingleUpstream(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)

	var calls int32
	qo := NewSimpleModernOptimizer(logger, 2*time.Second)
	t.Cleanup(qo.Close)
	qo.udpQueryFunc = func(_ *dns.Msg, _ string) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		return wrandomOKResp(req), nil
	}

	res := qo.QueryWeightedRandom(req, []string{
		"udp://10.0.0.1:53#70", "udp://10.0.0.2:53#20", "udp://10.0.0.3:53#10",
	})
	if !res.HasSuccess || res.SuccessResult == nil {
		t.Fatalf("应查询成功: %+v", res)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("首选成功时对外请求应为 1 次，实际 %d 次", n)
	}
}

// 首选失败后应从其余上游再试一次，且两次选中的上游不同（最多 2 次）
func TestQueryWeightedRandomRetriesOnceOnFailure(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)

	var calls int32
	var mu = make(chan struct{}, 1)
	servers := make(map[string]int)
	qo := NewSimpleModernOptimizer(logger, 2*time.Second)
	t.Cleanup(qo.Close)
	qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		mu <- struct{}{}
		servers[server]++
		<-mu
		return nil, errors.New("mock query failed")
	}

	res := qo.QueryWeightedRandom(req, []string{
		"udp://10.0.0.1:53", "udp://10.0.0.2:53", "udp://10.0.0.3:53",
	})
	if res.HasSuccess {
		t.Fatalf("全部失败时不应标记成功: %+v", res)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("失败回退应最多尝试 2 台，实际 %d 次", n)
	}
	if len(servers) != 2 {
		t.Errorf("两次尝试应为不同上游，实际命中 %+v", servers)
	}
}

// 无可用的加权上游时返回错误结果，不 panic
func TestQueryWeightedRandomNoValidUpstream(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)

	qo := NewSimpleModernOptimizer(logger, time.Second)
	t.Cleanup(qo.Close)

	res := qo.QueryWeightedRandom(req, []string{"ftp://bad.example#70"})
	if res.HasSuccess || res.FastestResult == nil || res.FastestResult.Error == nil {
		t.Errorf("无有效上游时应返回错误结果: %+v", res)
	}
}

// 端到端：带 "#权重" 的地址经真实 UDP dial 能正常解析（权重在后端被剥离）
func TestQueryWeightedRandomRealUpstream(t *testing.T) {
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	up := startFakeUpstream(t)
	logger := utils.NewEnhancedLogger("error", "test", false)

	qo := NewSimpleModernOptimizer(logger, 2*time.Second)
	t.Cleanup(qo.Close)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	res := qo.QueryWeightedRandom(req, []string{"udp://" + up.addr + "#100"})
	if !res.HasSuccess || res.SuccessResult == nil || len(res.SuccessResult.Response.Answer) == 0 {
		t.Fatalf("带权重的真实上游应查询成功: %+v", res)
	}
	if up.lastRequest(t) == nil {
		t.Error("上游应收到请求")
	}
}

// checkRatio 断言命中比例落在期望值 ±tol 区间内
func checkRatio(t *testing.T, got, total int, want, tol float64) {
	t.Helper()
	ratio := float64(got) / float64(total)
	if ratio < want-tol || ratio > want+tol {
		t.Errorf("命中比例 = %.4f，期望 %.2f ± %.2f", ratio, want, tol)
	}
}

// wrandomOKResp 构造一条带 A 记录的成功响应
func wrandomOKResp(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("10.0.0.1"),
	}}
	return m
}
