package dns

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// 串行模式配置了总预算后，不应再把「上游数 × 单台超时」全部耗完：
// 单台 60ms、预算 100ms、4 台上游，只允许发起 2 次尝试。
func TestQueryFailoverStopsAtBudget(t *testing.T) {
	const perUpstream = 60 * time.Millisecond
	const budget = 100 * time.Millisecond

	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, perUpstream)
	t.Cleanup(qo.Close)

	req := new(dns.Msg)
	req.SetQuestion("budget.example.com.", dns.TypeA)

	var calls int32
	qo.udpQueryFunc = func(_ *dns.Msg, _ string) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(perUpstream)
		return nil, errors.New("i/o timeout")
	}

	upstreams := []string{
		"udp://10.0.0.1:53", "udp://10.0.0.2:53",
		"udp://10.0.0.3:53", "udp://10.0.0.4:53",
	}

	start := time.Now()
	res := qo.queryFailover(req, upstreams, budget)
	elapsed := time.Since(start)

	if res.HasSuccess {
		t.Fatalf("全部上游都失败，不应标记成功: %+v", res)
	}
	// 无预算时是 4×60=240ms；有预算应在 100ms 后不再发起新尝试（最多再等一台）
	if got := atomic.LoadInt32(&calls); got > 2 {
		t.Errorf("预算 %v / 单台 %v：最多发起 2 次尝试，实际 %d 次", budget, perUpstream, got)
	}
	if elapsed > 3*perUpstream {
		t.Errorf("总耗时应被预算压住（< %v），实际 %v", 3*perUpstream, elapsed)
	}
}

// 无预算时保持历史行为：每台都试一遍
func TestQueryFailoverWithoutBudgetTriesAll(t *testing.T) {
	const perUpstream = 20 * time.Millisecond

	logger := utils.NewEnhancedLogger("error", "test", false)
	qo := NewSimpleModernOptimizer(logger, perUpstream)
	t.Cleanup(qo.Close)

	req := new(dns.Msg)
	req.SetQuestion("nobudget.example.com.", dns.TypeA)

	var calls int32
	qo.udpQueryFunc = func(_ *dns.Msg, _ string) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(perUpstream)
		return nil, errors.New("i/o timeout")
	}

	upstreams := []string{"udp://10.0.1.1:53", "udp://10.0.1.2:53", "udp://10.0.1.3:53"}
	qo.queryFailover(req, upstreams, 0)

	if got := atomic.LoadInt32(&calls); got != int32(len(upstreams)) {
		t.Errorf("不设预算时应逐台尝试 %d 次，实际 %d 次", len(upstreams), got)
	}
}

// 硬上限：解析慢于预算时必须按预算返回，而不是等解析自然结束
func TestRunWithBudgetHardCap(t *testing.T) {
	const budget = 40 * time.Millisecond

	start := time.Now()
	_, err := runWithBudget(budget, nil, func() (upstreamAnswer, error) {
		time.Sleep(400 * time.Millisecond)
		return upstreamAnswer{}, nil
	})
	elapsed := time.Since(start)

	if !errors.Is(err, errQueryBudgetExceeded) {
		t.Fatalf("应返回总预算超时错误，实际 %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("应在预算附近返回（≤200ms），实际 %v", elapsed)
	}
}

// budget<=0 时 runWithBudget 直接同步执行，不引入额外 goroutine 与超时
func TestRunWithBudgetDisabledRunsSync(t *testing.T) {
	want := upstreamAnswer{server: "udp://1.1.1.1:53"}
	got, err := runWithBudget(0, func() { t.Error("不应触发过期回调") }, func() (upstreamAnswer, error) {
		return want, nil
	})
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if got.server != want.server {
		t.Errorf("应原样返回结果，实际 %+v", got)
	}
}

// 作用域解析：自身配置优先，未配置回退全局；全局未配置则为 0（不限制）
func TestEffectiveQueryTimeout(t *testing.T) {
	h := &RefactoredHandler{config: &config.Config{QueryTimeout: 3 * time.Second}}

	if got := h.effectiveQueryTimeout(2 * time.Second); got != 2*time.Second {
		t.Errorf("作用域已配置时应优先自身，实际 %v", got)
	}
	if got := h.effectiveQueryTimeout(0); got != 3*time.Second {
		t.Errorf("作用域未配置时应回退全局 3s，实际 %v", got)
	}

	h.config = &config.Config{}
	if got := h.effectiveQueryTimeout(0); got != 0 {
		t.Errorf("全局也未配置时应为 0（不限制），实际 %v", got)
	}
}

// firstPositive 取第一个正数，0 视为"未配置"
func TestFirstPositive(t *testing.T) {
	cases := []struct {
		in   []time.Duration
		want time.Duration
	}{
		{[]time.Duration{0, 0}, 0},
		{[]time.Duration{0, 2 * time.Second}, 2 * time.Second},
		{[]time.Duration{5 * time.Second, 2 * time.Second}, 5 * time.Second},
	}
	for _, c := range cases {
		if got := firstPositive(c.in...); got != c.want {
			t.Errorf("firstPositive(%v) = %v，期望 %v", c.in, got, c.want)
		}
	}
}

// 端到端：总预算从决策层传到回源层，慢上游必须按预算提前返回
func TestProxyQueryWithCachingRespectsBudget(t *testing.T) {
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	logger := utils.NewEnhancedLogger("error", "test", false)
	cfg := config.DefaultConfig()
	cfg.Timeout = 2 * time.Second

	optimizer := NewSimpleModernOptimizer(logger, cfg.Timeout)
	t.Cleanup(optimizer.Close)
	optimizer.udpQueryFunc = func(_ *dns.Msg, _ string) (*dns.Msg, error) {
		time.Sleep(600 * time.Millisecond) // 远慢于预算
		return nil, errors.New("i/o timeout")
	}

	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	h := &RefactoredHandler{config: cfg, Logger: logger, cacheManager: cm, queryOptimizer: optimizer}

	req := new(dns.Msg)
	req.SetQuestion("budget-path.example.com.", dns.TypeA)

	start := time.Now()
	_, _, err := h.proxyQueryWithCaching(req, []string{"udp://10.0.0.1:53"},
		"budget-path.example.com", dns.TypeA, config.DNSModeRace, "-", 80*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, errQueryBudgetExceeded) {
		t.Fatalf("应返回总预算超时错误，实际 %v", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("应在预算附近返回（≤300ms），实际 %v", elapsed)
	}
}

// 云替换回源只用剩余预算：已过期的截止时间应立刻判定超时，而不是再放行一整份预算
func TestReplaceContextRemainingBudget(t *testing.T) {
	if got := (ReplaceContext{}).remainingBudget(); got != 0 {
		t.Errorf("未设截止时间应返回 0（不限制），实际 %v", got)
	}
	ctx := ReplaceContext{Deadline: time.Now().Add(time.Second)}
	if got := ctx.remainingBudget(); got <= 0 || got > time.Second {
		t.Errorf("剩余预算应在 (0,1s]，实际 %v", got)
	}
	ctx = ReplaceContext{Deadline: time.Now().Add(-time.Second)}
	if got := ctx.remainingBudget(); got <= 0 || got > time.Millisecond {
		t.Errorf("已过期应返回极小正值，实际 %v", got)
	}
}
