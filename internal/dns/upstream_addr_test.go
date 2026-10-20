package dns

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// 上游写成「带 scheme 但不带端口」时，所有真实的 dial 路径都必须补上默认端口。
// 修复前 handler.queryUDP/queryTCP（经 udpQueryFunc 注入给现代优化器）与 DoTConnPool
// 会把剥掉 scheme 的裸地址直接交给 dial，报 "missing port in address"：
// 生产分流列表里的 udp://1.1.1.1 因此完全失效（9-27~10-05 累计 2 万余次）。
func TestUpstreamWithoutPortDoesNotReportMissingPort(t *testing.T) {
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	logger := utils.NewEnhancedLogger("error", "test", false)
	cfg := config.DefaultConfig()
	cfg.Timeout = 500 * time.Millisecond
	cfg.ModernTimeout = 500 * time.Millisecond

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	t.Run("handler.queryUDP", func(t *testing.T) {
		h := &RefactoredHandler{config: cfg, Logger: logger, udpConnPool: NewUDPConnPool()}
		t.Cleanup(func() { h.udpConnPool.Close() })

		_, err := h.queryUDP(req, "udp://127.0.0.1")
		assertNoMissingPort(t, err)

		// 连接池键必须是归一化后的 host:port，证明补端口真的生效了
		h.udpConnPool.mu.RLock()
		_, ok := h.udpConnPool.clients["127.0.0.1:53"]
		h.udpConnPool.mu.RUnlock()
		if !ok {
			t.Errorf("UDP 连接池键应为 127.0.0.1:53，实际: %v", poolKeys(h.udpConnPool.clients))
		}
	})

	t.Run("handler.queryTCP", func(t *testing.T) {
		h := &RefactoredHandler{config: cfg, Logger: logger, tcpConnPool: NewTCPConnPool()}
		t.Cleanup(func() { h.tcpConnPool.Close() })

		_, err := h.queryTCP(req, "tcp://127.0.0.1")
		assertNoMissingPort(t, err)

		h.tcpConnPool.mu.RLock()
		_, ok := h.tcpConnPool.clients["127.0.0.1:53"]
		h.tcpConnPool.mu.RUnlock()
		if !ok {
			t.Error("TCP 连接池键应为 127.0.0.1:53")
		}
	})

	t.Run("DoTConnPool.GetConn", func(t *testing.T) {
		pool := NewDoTConnPool()
		t.Cleanup(pool.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_, err := pool.GetConn(ctx, "tls://127.0.0.1")
		if err == nil {
			t.Skip("本机 127.0.0.1:853 可连通，跳过错误断言")
		}
		assertNoMissingPort(t, err)
	})

	t.Run("SimpleModernOptimizer.queryServer", func(t *testing.T) {
		opt := NewSimpleModernOptimizer(logger, cfg.Timeout, cfg.ModernTimeout)
		res := opt.queryServer(req, "udp://127.0.0.1")
		if res == nil {
			t.Fatal("结果不应为空")
		}
		assertNoMissingPort(t, res.Error)
	})

	t.Run("FastQueryOptimizer.Query", func(t *testing.T) {
		opt := NewFastQueryOptimizer(logger, nil, cfg.Timeout)
		t.Cleanup(opt.Close)

		res := opt.Query(req, []string{"udp://127.0.0.1"})
		if res == nil {
			t.Fatal("结果不应为空")
		}
		for _, r := range res.AllResults {
			assertNoMissingPort(t, r.Error)
		}
	})
}

// 带端口的正常上游必须仍能解析成功（确认归一化没有破坏既有链路）
func TestUpstreamWithPortStillResolves(t *testing.T) {
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	up := startFakeUpstream(t)
	logger := utils.NewEnhancedLogger("error", "test", false)
	cfg := config.DefaultConfig()
	cfg.Timeout = 2 * time.Second

	h := &RefactoredHandler{config: cfg, Logger: logger, udpConnPool: NewUDPConnPool()}
	t.Cleanup(func() { h.udpConnPool.Close() })

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := h.queryUDP(req, "udp://"+up.addr)
	if err != nil {
		t.Fatalf("带端口的 udp:// 上游应查询成功: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("应返回 A 记录")
	}
}

func assertNoMissingPort(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "missing port") {
		t.Errorf("上游缺端口未补默认端口，仍报 missing port: %v", err)
	}
}

func poolKeys(m map[string][]*UDPClientInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
