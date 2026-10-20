package dns

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// TestProxyQueryWithCachingCoalescesConcurrentMiss 并发冷启动同一域名时，
// 回源应被 single-flight 合并为一次，而不是每个请求各自回源。
func TestProxyQueryWithCachingCoalescesConcurrentMiss(t *testing.T) {
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	logger := utils.NewEnhancedLogger("error", "test", false)
	cfg := config.DefaultConfig()
	cfg.Timeout = 2 * time.Second
	upstreams := []string{"udp://10.0.0.1:53"}

	var calls int32
	optimizer := NewSimpleModernOptimizer(logger, cfg.Timeout)
	t.Cleanup(optimizer.Close)
	optimizer.udpQueryFunc = func(req *dns.Msg, _ string) (*dns.Msg, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(150 * time.Millisecond) // 让所有并发请求都汇入同一飞行
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{10, 0, 0, 1},
		}}
		return resp, nil
	}

	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	h := &RefactoredHandler{config: cfg, Logger: logger, cacheManager: cm, queryOptimizer: optimizer}

	const n = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	responses := make([]*dns.Msg, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion("coalesce.example.com.", dns.TypeA)
			<-start // 对齐启动，确保全部进入同一飞行
			resp, _, err := h.proxyQueryWithCaching(req, upstreams, "coalesce.example.com", dns.TypeA, config.DNSModeRace, "-")
			if err != nil {
				t.Errorf("goroutine %d 查询失败: %v", i, err)
				return
			}
			responses[i] = resp
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("并发 %d 个 miss 应合并为 1 次回源，实际回源 %d 次", n, got)
	}

	// 每个并发请求必须拿到各自独立的副本（共享同一 *dns.Msg 会被 writeResponse 并发改写）
	seen := make(map[*dns.Msg]bool, n)
	for i, resp := range responses {
		if resp == nil {
			t.Fatalf("goroutine %d 未拿到响应", i)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("goroutine %d 响应答案数 = %d，want 1", i, len(resp.Answer))
		}
		if seen[resp] {
			t.Fatalf("goroutine %d 拿到了被共享的同一个响应对象", i)
		}
		seen[resp] = true
	}
	t.Logf("%d 个并发 miss 合并为 1 次回源，且各请求持有独立响应副本", n)
}
