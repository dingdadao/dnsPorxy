package dns

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// FastQueryOptimizer 快速DNS查询优化器（移除健康状态跟踪）
type FastQueryOptimizer struct {
	logger *utils.EnhancedLogger

	// 配置
	cfgMu          sync.RWMutex
	timeout        time.Duration
	retryCount     int
	enableFallback bool
}

// UpdateTimeouts 热更新查询超时配置
func (qo *FastQueryOptimizer) UpdateTimeouts(timeout time.Duration) {
	qo.cfgMu.Lock()
	qo.timeout = timeout
	qo.cfgMu.Unlock()
}

// getTimeout 读取查询超时
func (qo *FastQueryOptimizer) getTimeout() time.Duration {
	qo.cfgMu.RLock()
	defer qo.cfgMu.RUnlock()
	return qo.timeout
}

// QueryResult 查询结果
type QueryResult struct {
	Response     *dns.Msg
	Server       string
	ResponseTime time.Duration
	FromCache    bool
	IsSuccess    bool // 新增：标记查询是否成功
	Error        error
}

// ConcurrentQueryResult 并发查询结果
type ConcurrentQueryResult struct {
	FastestResult  *QueryResult   // 最快的结果（返回给客户端）
	SuccessResult  *QueryResult   // 最快的成功结果（用于缓存）
	AllResults     []*QueryResult // 所有结果
	HasSuccess     bool           // 是否有成功的结果
	FastestTime    time.Duration  // 最快响应时间
	TotalQueryTime time.Duration  // 总查询时间
}

// NewFastQueryOptimizer 创建快速查询优化器
func NewFastQueryOptimizer(logger *utils.EnhancedLogger, metrics interface{}, timeout time.Duration) *FastQueryOptimizer {
	return &FastQueryOptimizer{
		logger:         logger,
		timeout:        timeout,
		retryCount:     2, // 减少重试次数
		enableFallback: true,
	}
}

// Query 执行并发DNS查询（返回最快的结果，但缓存最快的成功结果）
func (qo *FastQueryOptimizer) Query(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	if len(upstreams) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no upstream servers available"),
			},
			HasSuccess: false,
		}
	}

	return qo.concurrentQuery(req, upstreams)
}

// concurrentQuery 并发查询多个上游服务器
func (qo *FastQueryOptimizer) concurrentQuery(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	// 创建结果通道
	resultChan := make(chan *QueryResult, len(upstreams))
	var wg sync.WaitGroup

	qo.logger.Debug("🚀 开始并发DNS查询", map[string]interface{}{
		"upstreams": len(upstreams),
		"domain":    req.Question[0].Name,
	})

	// 并发查询所有上游服务器
	for _, upstream := range upstreams {
		wg.Add(1)
		go func(server string) {
			// panic恢复机制
			defer func() {
				if r := recover(); r != nil {
					qo.logger.Error("💥 [DNS查询panic] ", map[string]interface{}{
						"rule":        "DNS_QUERY_PANIC",
						"server":      server,
						"panic_msg":   fmt.Sprintf("%v", r),
						"stack_trace": string(debug.Stack()),
					})
					// 创建错误结果
					result := &QueryResult{
						Server:       server,
						Error:        fmt.Errorf("query panic: %v", r),
						ResponseTime: time.Since(start),
					}
					select {
					case resultChan <- result:
					case <-ctx.Done():
					}
				}
				wg.Done()
			}()

			result := qo.queryServer(req, server)
			select {
			case resultChan <- result:
			case <-ctx.Done():
				// 超时或取消
			}
		}(upstream)
	}

	// 启动一个 goroutine 等待所有查询完成后关闭通道
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	var allResults []*QueryResult
	var fastestResult *QueryResult
	var successResult *QueryResult
	var fastestTime time.Duration
	hasSuccess := false

	// 从通道中收集结果
	for result := range resultChan {
		allResults = append(allResults, result)

		// 记录最快的结果（无论成功失败）
		if fastestResult == nil {
			fastestResult = result
			fastestTime = result.ResponseTime
		}

		// 记录最快的成功结果
		if result.Error == nil && result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
			result.IsSuccess = true
			if !hasSuccess {
				successResult = result
				hasSuccess = true
			}
		}
	}

	totalTime := time.Since(start)

	// 确保始终有 FastestResult，即使所有查询都失败
	if fastestResult == nil {
		fastestResult = &QueryResult{
			Error:        fmt.Errorf("all %d upstream queries failed", len(upstreams)),
			Server:       "none",
			ResponseTime: totalTime,
		}
	}

	// 记录统计信息
	if hasSuccess && successResult != nil {
		qo.logger.Info("✅ 并发查询成功", map[string]interface{}{
			"fastest_server": fastestResult.Server,
			"fastest_time":   fastestTime.String(),
			"success_server": successResult.Server,
			"success_time":   successResult.ResponseTime.String(),
			"total_results":  len(allResults),
			"total_time":     totalTime.String(),
		})
	} else {
		if fastestResult != nil {
			qo.logger.Warn("⚠️ 并发查询全部失败", map[string]interface{}{
				"fastest_server": fastestResult.Server,
				"fastest_time":   fastestTime.String(),
				"total_results":  len(allResults),
				"total_time":     totalTime.String(),
			})
		} else {
			qo.logger.Error("❌ 并发查询无任何结果", map[string]interface{}{
				"total_results": len(allResults),
				"total_time":    totalTime.String(),
			})
		}
	}

	return &ConcurrentQueryResult{
		FastestResult:  fastestResult,
		SuccessResult:  successResult,
		AllResults:     allResults,
		HasSuccess:     hasSuccess,
		FastestTime:    fastestTime,
		TotalQueryTime: totalTime,
	}
}

// queryServer 查询特定服务器
func (qo *FastQueryOptimizer) queryServer(req *dns.Msg, server string) *QueryResult {
	start := time.Now()

	// 归一化为 host:port：本函数把地址直接交给 dns.Client，缺端口会报 "missing port in address"
	// （旧格式上游可能写成 udp://1.1.1.1 或裸 1.1.1.1）
	addr := config.UpstreamDialAddr(server)

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	// 优先尝试UDP
	client := &dns.Client{
		Net:     "udp",
		Timeout: qo.getTimeout(),
	}

	resp, rtt, err := client.ExchangeContext(ctx, req, addr)

	// UDP失败时尝试TCP（可能是响应太大）
	if err != nil && qo.enableFallback {
		client.Net = "tcp"
		resp, rtt, err = client.ExchangeContext(ctx, req, addr)
	}

	result := &QueryResult{
		Response:     resp,
		Server:       server,
		ResponseTime: time.Since(start),
		Error:        err,
	}

	if err == nil && resp != nil {
		qo.logger.Debug("🔍 DNS查询成功", map[string]interface{}{
			"server":  server,
			"rtt":     rtt.String(),
			"answers": len(resp.Answer),
			"rcode":   dns.RcodeToString[resp.Rcode],
			// "resp.name": resp.Question[0].Name,
			// "resp.type": dns.TypeToString[resp.Question[0].Qtype],
		})
	} else if err != nil {
		qo.logger.Debug("❌ DNS查询失败", map[string]interface{}{
			"server": server,
			"error":  err.Error(),
		})
	}

	return result
}

// Close 关闭查询优化器
func (qo *FastQueryOptimizer) Close() {
	qo.logger.Info("📪 快速DNS查询优化器已关闭")
}
