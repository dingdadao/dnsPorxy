package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// SimpleModernOptimizer 简化的现代DNS查询优化器
type SimpleModernOptimizer struct {
	logger *utils.EnhancedLogger

	// 配置
	cfgMu          sync.RWMutex
	timeout        time.Duration // 传统协议超时时间
	modernTimeout  time.Duration // 现代协议超时时间
	retryCount     int
	enableFallback bool

	// HTTP客户端池
	httpClient *http.Client
	tlsConfig  *tls.Config

	// 连接缓存
	connCache map[string]interface{}
	cacheMu   sync.RWMutex

	// Handler提供的方法（用于各种协议的连接池查询）
	udpQueryFunc  func(*dns.Msg, string) (*dns.Msg, error)
	tcpQueryFunc  func(*dns.Msg, string) (*dns.Msg, error)
	doHQueryFunc  func(*dns.Msg, string) (*dns.Msg, error)
	doTQueryFunc  func(*dns.Msg, string) (*dns.Msg, error)
	doH3QueryFunc func(*dns.Msg, string) (*dns.Msg, error)
}

// NewSimpleModernOptimizer 创建简化的现代DNS查询优化器
func NewSimpleModernOptimizer(logger *utils.EnhancedLogger, timeout time.Duration, modernTimeout ...time.Duration) *SimpleModernOptimizer {
	// 现代协议超时，默认比传统协议更短
	modTimeout := timeout
	if len(modernTimeout) > 0 {
		modTimeout = modernTimeout[0]
	} else {
		// 默认现代协议是传统协议的3/4时间
		modTimeout = time.Duration(float64(timeout) * 0.75)
	}

	optimizer := &SimpleModernOptimizer{
		logger:         logger,
		timeout:        timeout,
		modernTimeout:  modTimeout,
		retryCount:     2,
		enableFallback: true,
		connCache:      make(map[string]interface{}),
	}

	// 初始化HTTP客户端
	optimizer.initHTTPClient()

	logger.Info("🚀 [简化现代DNS查询优化器初始化] ", map[string]interface{}{
		"rule":           "SIMPLE_MODERN_OPTIMIZER_INIT",
		"protocols":      []string{"udp", "tcp", "https", "tls", "h3"},
		"timeout":        timeout.String(),
		"modern_timeout": modTimeout.String(),
	})

	return optimizer
}

// UpdateTimeouts 热更新查询超时配置
func (qo *SimpleModernOptimizer) UpdateTimeouts(timeout, modernTimeout time.Duration) {
	qo.cfgMu.Lock()
	qo.timeout = timeout
	qo.modernTimeout = modernTimeout
	qo.cfgMu.Unlock()
}

// getTimeout 读取传统协议超时
func (qo *SimpleModernOptimizer) getTimeout() time.Duration {
	qo.cfgMu.RLock()
	defer qo.cfgMu.RUnlock()
	return qo.timeout
}

// getModernTimeout 读取现代协议超时
func (qo *SimpleModernOptimizer) getModernTimeout() time.Duration {
	qo.cfgMu.RLock()
	defer qo.cfgMu.RUnlock()
	return qo.modernTimeout
}

// initHTTPClient 初始化HTTP客户端
func (qo *SimpleModernOptimizer) initHTTPClient() {
	// 配置TLS
	qo.tlsConfig = &tls.Config{
		InsecureSkipVerify: false,
	}

	// HTTP客户端（支持HTTP/1.1, HTTP/2, 和部分HTTP/3）
	// 使用更短的超时时间给现代协议
	qo.httpClient = &http.Client{
		Timeout: qo.getModernTimeout(), // 使用现代协议超时
		Transport: &http.Transport{
			MaxIdleConns:          200,                   // 增加空闲连接到200
			MaxIdleConnsPerHost:   20,                    // 增加每个主机的空闲连接到20
			IdleConnTimeout:       90 * time.Second,      // 延长空闲超时到90秒
			TLSHandshakeTimeout:   qo.getModernTimeout(), // 使用现代协议超时
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       qo.tlsConfig,
			DisableKeepAlives:     false, // 启用keep-alive
			DialContext: (&net.Dialer{
				Timeout:   qo.getModernTimeout(), // 连接超时
				KeepAlive: 30 * time.Second,      // 启用TCP keep-alive并设置更长时间
			}).DialContext,
		},
	}
}

// Query 执行并发DNS查询（简化版本）
func (qo *SimpleModernOptimizer) Query(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
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

// ServerStats 服务器统计信息
type ServerStats struct {
	Server          string
	AvgResponseTime time.Duration
	SuccessRate     float64
	QueryCount      int
	LastSuccess     time.Time
}

// concurrentQuery 并发查询多个上游服务器
func (qo *SimpleModernOptimizer) concurrentQuery(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	start := time.Now()

	// 过滤有效的上游服务器
	validUpstreams := qo.filterValidUpstreams(upstreams)
	if len(validUpstreams) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no valid upstream servers after filtering"),
			},
			HasSuccess: false,
		}
	}

	// 如果只有一个有效的上游服务器，直接查询而不使用并发
	if len(validUpstreams) == 1 {
		server := validUpstreams[0]
		qo.logger.Debug("📡 单一服务器直接查询", map[string]interface{}{
			"server": server,
			"domain": req.Question[0].Name,
		})

		result := qo.queryServer(req, server)

		// 添加空指针检查
		if result == nil {
			result = &QueryResult{
				Server: server,
				Error:  fmt.Errorf("query result is nil"),
			}
		}

		var allResults []*QueryResult
		allResults = append(allResults, result)

		// 检查结果是否有效
		hasSuccess := false
		hasValidResponse := false
		var successResult *QueryResult
		var fastestValidResult *QueryResult

		if result.Error == nil && result.Response != nil &&
			(result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError) {
			// NXDOMAIN 是权威否定答案（RFC 2308），同样属于终态有效结果，
			// 不能当成"查询失败"交给备用DNS去改写
			result.IsSuccess = true
			successResult = result
			hasSuccess = true

			if len(result.Response.Answer) > 0 {
				fastestValidResult = result
				hasValidResponse = true
			}
		}

		// 安全地获取答案数量
		answerCount := 0
		if result.Response != nil {
			answerCount = len(result.Response.Answer)
		}

		qo.logger.Debug("✅ 单一服务器查询完成", map[string]interface{}{
			"server":      server,
			"time":        result.ResponseTime.String(),
			"has_success": hasSuccess,
			"has_valid":   hasValidResponse,
			"answers":     answerCount,
			"total_time":  time.Since(start).String(),
		})

		// 返回结果：优先使用有效结果作为 SuccessResult
		var finalSuccessResult *QueryResult
		if hasValidResponse && fastestValidResult != nil {
			finalSuccessResult = fastestValidResult
		} else if hasSuccess && successResult != nil {
			finalSuccessResult = successResult
		}

		return &ConcurrentQueryResult{
			FastestResult:  result,             // 最快结果（可能是错误）
			SuccessResult:  finalSuccessResult, // 最优有效结果
			AllResults:     allResults,
			HasSuccess:     hasValidResponse || hasSuccess, // 有效结果或成功结果
			FastestTime:    result.ResponseTime,
			TotalQueryTime: time.Since(start),
		}
	}

	// 多个上游服务器时使用并发查询
	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	// 创建结果通道
	resultChan := make(chan *QueryResult, len(validUpstreams))
	var wg sync.WaitGroup

	qo.logger.Debug("🚀 开始智能并发DNS查询", map[string]interface{}{
		"total_upstreams": len(upstreams),
		"valid_upstreams": len(validUpstreams),
		"domain":          req.Question[0].Name,
	})

	// 并发查询所有有效的上游服务器
	for _, upstream := range validUpstreams {
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

	// 收集结果，优先处理有效结果
	var allResults []*QueryResult
	var fastestResult *QueryResult
	var successResult *QueryResult
	var fastestValidResult *QueryResult // 最快的有效结果
	var fastestValidTime time.Duration
	var fastestTime time.Duration
	hasSuccess := false
	hasValidResponse := false

	// 优化：实现智能快速返回策略
	// 创建一个用于快速返回的通道
	quickReturnChan := make(chan *QueryResult, 1)

	// 启动一个goroutine来处理结果收集
	// 一旦发现有效结果就立即停止等待其他结果
	resultProcessingDone := make(chan struct{})
	go func() {
		defer close(resultProcessingDone)

		for result := range resultChan {
			allResults = append(allResults, result)

			// 记录最快的结果（无论成功失败）
			if fastestResult == nil {
				fastestResult = result
				fastestTime = result.ResponseTime
			} else if result.ResponseTime < fastestTime {
				fastestResult = result
				fastestTime = result.ResponseTime
			}

			// 检查是否为有效响应
			if result.Error == nil && result.Response != nil {
				if result.Response.Rcode == dns.RcodeSuccess {
					result.IsSuccess = true

					// 记录第一个成功结果
					if !hasSuccess {
						successResult = result
						hasSuccess = true
					}

					// 检查是否有答案（更优先的结果）
					if len(result.Response.Answer) > 0 {
						// 记录最快的有效结果
						if !hasValidResponse || result.ResponseTime < fastestValidTime {
							fastestValidResult = result
							fastestValidTime = result.ResponseTime
							hasValidResponse = true
							qo.logger.Debug("🏆 发现有效结果", map[string]interface{}{
								"server":  result.Server,
								"time":    result.ResponseTime.String(),
								"answers": len(result.Response.Answer),
								"rcode":   dns.RcodeToString[result.Response.Rcode],
							})

							// 智能快速返回策略：
							// 1. 首个有效应答立即返回，避免被挂起的慢上游拖到整体超时
							// 2. 若未提前返回，则在收尾时选择最快的有效结果
							if result.ResponseTime < qo.getModernTimeout() {
								// 竞速中所有上游同时发起，先到者即最快者，立即返回
								select {
								case quickReturnChan <- result:
									// 发现快速有效结果后，取消上下文以停止其他查询
									cancel()
								default:
									// 如果通道已满，忽略
								}
								// 发现快速有效结果后立即返回
								return
							}
						}
					} else if !hasValidResponse {
						// NOERROR 但无应答（NODATA，RFC 2308）：海外权威对不存在的子域常返回
						// NODATA。它和 NXDOMAIN 一样是终态有效结果，必须立即收尾，
						// 否则会一直等到 modern_timeout（曾把境外域名查询拖满 3s）
						result.IsSuccess = true
						qo.logger.Debug("📭 收到 NOERROR 空应答 NODATA", map[string]interface{}{
							"server": result.Server,
							"time":   result.ResponseTime.String(),
						})
						select {
						case quickReturnChan <- result:
							cancel()
						default:
						}
						return
					}
				} else if result.Response.Rcode == dns.RcodeNameError && !hasValidResponse {
					// NXDOMAIN 是权威否定答案（RFC 2308）：本身就是终态有效结果。
					// 立即收尾，既不必等其它上游超时，也不能让备用DNS把它改写成垃圾IP
					result.IsSuccess = true
					successResult = result
					hasSuccess = true
					qo.logger.Debug("🚫 收到权威否定答案 NXDOMAIN", map[string]interface{}{
						"server": result.Server,
						"time":   result.ResponseTime.String(),
					})
					select {
					case quickReturnChan <- result:
						cancel()
					default:
					}
					return
				}
			}
		}

		// 所有查询完成后，如果有有效结果，选择最快的返回
		if hasValidResponse && fastestValidResult != nil {
			select {
			case quickReturnChan <- fastestValidResult:
			default:
				// 如果通道已满，忽略
			}
		}
	}()

	// 等待第一个有效结果或超时
	var bestResult *QueryResult
	select {
	case bestResult = <-quickReturnChan:
		// 收到有效结果，立即使用
		qo.logger.Debug("⚡ 快速返回最优结果", map[string]interface{}{
			"server":  bestResult.Server,
			"answers": len(bestResult.Response.Answer),
			"time":    bestResult.ResponseTime.String(),
		})
		// 等待结果处理完成（应该很快）
		<-resultProcessingDone
	case <-time.After(qo.getModernTimeout()):
		// 超时后等待结果处理完成
		<-resultProcessingDone
		qo.logger.Debug("⏰ 等待超时，使用已收集的结果")

		// 选择最优结果：有效结果 > 成功结果 > 最快结果
		if hasValidResponse && fastestValidResult != nil {
			bestResult = fastestValidResult
			qo.logger.Debug("🏅 使用最优有效结果", map[string]interface{}{
				"server":  bestResult.Server,
				"answers": len(bestResult.Response.Answer),
			})
		} else if hasSuccess && successResult != nil {
			bestResult = successResult
			qo.logger.Debug("🥈 使用成功结果（无答案）", map[string]interface{}{
				"server": bestResult.Server,
				"rcode":  dns.RcodeToString[bestResult.Response.Rcode],
			})
		} else {
			bestResult = fastestResult
			serverName := "none"
			if bestResult != nil {
				serverName = bestResult.Server
			}
			qo.logger.Debug("🚔 使用最快结果（可能失败）", map[string]interface{}{
				"server": serverName,
			})
		}
	}

	// 确保始终有 FastestResult，即使所有查询都失败
	if fastestResult == nil {
		fastestResult = &QueryResult{
			Error:        fmt.Errorf("all %d upstream queries failed", len(validUpstreams)),
			Server:       "none",
			ResponseTime: time.Since(start),
		}
	}

	// 记录统计信息
	totalQueryTime := time.Since(start)
	if hasValidResponse && fastestValidResult != nil {
		qo.logger.Debug("✅ 智能并发查询成功（有效结果）", map[string]interface{}{
			"fastest_server":      fastestResult.Server,
			"fastest_time":        fastestTime.String(),
			"valid_result_server": fastestValidResult.Server,
			"valid_result_time":   fastestValidResult.ResponseTime.String(),
			"valid_answers":       len(fastestValidResult.Response.Answer),
			"total_results":       len(allResults),
			"total_time":          totalQueryTime.String(),
		})
	} else if hasSuccess && successResult != nil {
		qo.logger.Debug("🥈 智能并发查询成功（无答案）", map[string]interface{}{
			"fastest_server": fastestResult.Server,
			"fastest_time":   fastestTime.String(),
			"success_server": successResult.Server,
			"success_time":   successResult.ResponseTime.String(),
			"total_results":  len(allResults),
			"total_time":     totalQueryTime.String(),
		})
	} else {
		qo.logger.Warn("⚠️ 智能并发查询全部失败", map[string]interface{}{
			"fastest_server": fastestResult.Server,
			"fastest_time":   fastestTime.String(),
			"total_results":  len(allResults),
			"total_time":     totalQueryTime.String(),
		})
	}

	// 返回结果：优先使用有效结果作为 SuccessResult
	var finalSuccessResult *QueryResult
	if hasValidResponse && fastestValidResult != nil {
		finalSuccessResult = fastestValidResult
	} else if hasSuccess && successResult != nil {
		finalSuccessResult = successResult
	}

	return &ConcurrentQueryResult{
		FastestResult:  fastestResult,      // 最快结果（可能是错误）
		SuccessResult:  finalSuccessResult, // 最优有效结果
		AllResults:     allResults,
		HasSuccess:     hasValidResponse || hasSuccess, // 有效结果或成功结果
		FastestTime:    fastestTime,
		TotalQueryTime: totalQueryTime,
	}
}

// QueryFailover 串行故障转移：按上游顺序逐个查询，第一个成功（NOERROR）即返回，
// 前一台失败/超时才用下一台。用于分流列表选择 failover 模式时，避免把上游 QPS 放大 N 倍。
func (qo *SimpleModernOptimizer) QueryFailover(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	start := time.Now()

	validUpstreams := qo.filterValidUpstreams(upstreams)
	if len(validUpstreams) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no valid upstream servers after filtering"),
			},
			HasSuccess: false,
		}
	}

	var allResults []*QueryResult
	var last *QueryResult

	for i, server := range validUpstreams {
		result := qo.queryServer(req, server)
		if result == nil {
			continue
		}
		allResults = append(allResults, result)
		last = result

		if result.Error == nil && result.Response != nil &&
			(result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError) {
			// NXDOMAIN 与 NOERROR 一样是终态答案（RFC 2308），无需再试下一台
			result.IsSuccess = true
			qo.logger.Debug("✅ 串行模式查询成功", map[string]interface{}{
				"server":       server,
				"attempt":      i + 1,
				"total":        len(validUpstreams),
				"time":         result.ResponseTime.String(),
				"total_time":   time.Since(start).String(),
				"answer_count": len(result.Response.Answer),
				"rcode":        dns.RcodeToString[result.Response.Rcode],
			})
			return &ConcurrentQueryResult{
				FastestResult:  result,
				SuccessResult:  result,
				AllResults:     allResults,
				HasSuccess:     true,
				FastestTime:    result.ResponseTime,
				TotalQueryTime: time.Since(start),
			}
		}

		qo.logger.Debug("⏭️ 串行模式当前上游未成功，尝试下一个", map[string]interface{}{
			"server":  server,
			"attempt": i + 1,
			"total":   len(validUpstreams),
			"error":   result.Error,
		})
	}

	if last == nil {
		last = &QueryResult{
			Server:       "none",
			Error:        fmt.Errorf("all %d upstream queries failed", len(validUpstreams)),
			ResponseTime: time.Since(start),
		}
	}

	qo.logger.Warn("⚠️ 串行模式所有上游均未成功", map[string]interface{}{
		"total":      len(validUpstreams),
		"server":     last.Server,
		"total_time": time.Since(start).String(),
	})

	return &ConcurrentQueryResult{
		FastestResult:  last,
		AllResults:     allResults,
		HasSuccess:     false,
		FastestTime:    last.ResponseTime,
		TotalQueryTime: time.Since(start),
	}
}

// weightedUpstream 加权上游：server 为剥离权重后的净地址，weight 为相对权重
type weightedUpstream struct {
	server string
	weight int
}

// defaultUpstreamWeight 未显式指定权重时的默认权重（等价于等权）
const defaultUpstreamWeight = 1

// parseWeightedUpstreams 过滤无效上游并解析 "#权重" 后缀。
//   - "#<n>"：显式权重（n=0 视为禁用，不参与随机）
//   - 无后缀：默认权重 defaultUpstreamWeight（等权）
//
// 返回的 server 均为剥离权重后的净地址，可直接交给 queryServer。
func (qo *SimpleModernOptimizer) parseWeightedUpstreams(upstreams []string) []weightedUpstream {
	out := make([]weightedUpstream, 0, len(upstreams))
	for _, raw := range upstreams {
		addr, weight, hasWeight := config.SplitUpstreamWeight(raw)
		if !qo.isValidUpstream(addr) {
			qo.logger.Warn("⚠️ 跳过不支持的上游服务器", map[string]interface{}{
				"server": raw,
				"reason": "unsupported_protocol_or_format",
			})
			continue
		}
		if !hasWeight {
			weight = defaultUpstreamWeight
		}
		out = append(out, weightedUpstream{server: addr, weight: weight})
	}
	return out
}

// pickWeightedIndex 按权重随机返回一台上游的下标；weight<=0 的条目不参与。
// 全部权重<=0 时退化为等权随机，保证仍能选出一台。
func pickWeightedIndex(ups []weightedUpstream, rnd *rand.Rand) int {
	total := 0
	for _, u := range ups {
		if u.weight > 0 {
			total += u.weight
		}
	}
	if total <= 0 {
		return rnd.Intn(len(ups))
	}
	n := rnd.Intn(total)
	for i, u := range ups {
		if u.weight <= 0 {
			continue
		}
		n -= u.weight
		if n < 0 {
			return i
		}
	}
	return 0
}

// QueryWeightedRandom 权重随机：按 "#权重" 从有效上游中随机选一台发起查询（每次 miss 只发 1 次），
// 失败/超时后从其余上游再随机选一台重试，最多尝试 2 台，避免单点故障导致解析失败。
// 返回结构与 Query/QueryFailover 保持一致，便于上层统一处理。
func (qo *SimpleModernOptimizer) QueryWeightedRandom(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	start := time.Now()

	weighted := qo.parseWeightedUpstreams(upstreams)
	if len(weighted) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no valid upstream servers after filtering"),
			},
			HasSuccess: false,
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	// 最多尝试 2 台（首选 + 一次回退），候选不足时以实际数量为准
	const maxAttempts = 2
	attempts := maxAttempts
	if len(weighted) < attempts {
		attempts = len(weighted)
	}

	remaining := make([]weightedUpstream, len(weighted))
	copy(remaining, weighted)

	var allResults []*QueryResult
	var last *QueryResult

	for i := 0; i < attempts; i++ {
		idx := pickWeightedIndex(remaining, rnd)
		choice := remaining[idx]
		// 移除已尝试的项，避免回退时再次选中同一台
		remaining = append(remaining[:idx], remaining[idx+1:]...)

		result := qo.queryServer(req, choice.server)
		if result == nil {
			continue
		}
		allResults = append(allResults, result)
		last = result

		if result.Error == nil && result.Response != nil &&
			(result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError) {
			// NOERROR / NXDOMAIN 均为终态答案（RFC 2308），无需回退
			result.IsSuccess = true
			qo.logger.Debug("✅ 权重随机模式查询成功", map[string]interface{}{
				"server":       choice.server,
				"weight":       choice.weight,
				"attempt":      i + 1,
				"time":         result.ResponseTime.String(),
				"total_time":   time.Since(start).String(),
				"answer_count": len(result.Response.Answer),
				"rcode":        dns.RcodeToString[result.Response.Rcode],
			})
			return &ConcurrentQueryResult{
				FastestResult:  result,
				SuccessResult:  result,
				AllResults:     allResults,
				HasSuccess:     true,
				FastestTime:    result.ResponseTime,
				TotalQueryTime: time.Since(start),
			}
		}

		qo.logger.Debug("⏭️ 权重随机模式当前上游未成功，尝试回退", map[string]interface{}{
			"server":  choice.server,
			"attempt": i + 1,
			"error":   result.Error,
		})
	}

	if last == nil {
		last = &QueryResult{
			Server:       "none",
			Error:        fmt.Errorf("all %d upstream queries failed", len(weighted)),
			ResponseTime: time.Since(start),
		}
	}

	qo.logger.Warn("⚠️ 权重随机模式所有尝试均失败", map[string]interface{}{
		"total":      len(weighted),
		"attempts":   len(allResults),
		"server":     last.Server,
		"total_time": time.Since(start).String(),
	})

	return &ConcurrentQueryResult{
		FastestResult:  last,
		AllResults:     allResults,
		HasSuccess:     false,
		FastestTime:    last.ResponseTime,
		TotalQueryTime: time.Since(start),
	}
}

// filterValidUpstreams 过滤有效的上游服务器（剥离 "#权重" 后缀后校验，返回净地址）
func (qo *SimpleModernOptimizer) filterValidUpstreams(upstreams []string) []string {
	var validUpstreams []string

	for _, upstream := range upstreams {
		addr, _, _ := config.SplitUpstreamWeight(upstream)
		if qo.isValidUpstream(addr) {
			validUpstreams = append(validUpstreams, addr)
		} else {
			qo.logger.Warn("⚠️ 跳过不支持的上游服务器", map[string]interface{}{
				"server": upstream,
				"reason": "unsupported_protocol_or_format",
			})
		}
	}

	return validUpstreams
}

// isValidUpstream 检查上游服务器是否有效
func (qo *SimpleModernOptimizer) isValidUpstream(upstream string) bool {
	// 兼容带 "#权重" 后缀的写法：校验时先剥离权重
	upstream, _, _ = config.SplitUpstreamWeight(upstream)

	// 支持的协议前缀
	supportedSchemes := []string{"udp://", "tcp://", "https://", "tls://", "h3://"}

	// 检查是否是URL格式
	for _, scheme := range supportedSchemes {
		if strings.HasPrefix(upstream, scheme) {
			return true
		}
	}

	// 兼容旧格式：IP:PORT 格式（自动识别为UDP）
	if strings.Contains(upstream, ":") && !strings.Contains(upstream, "://") {
		// 尝试解析为 host:port 格式
		if host, port, err := net.SplitHostPort(upstream); err == nil {
			// 简单验证
			if host != "" && port != "" {
				qo.logger.Debug("🔄 兼容旧格式，自动识别为UDP", map[string]interface{}{
					"server": upstream,
				})
				return true
			}
		}
	}

	return false
}

// queryServer 查询特定服务器（根据URL scheme自动选择协议）
func (qo *SimpleModernOptimizer) queryServer(req *dns.Msg, server string) *QueryResult {
	start := time.Now()

	var resp *dns.Msg
	var err error
	var protocol string
	var timeout time.Duration

	// 根据URL scheme选择协议和超时时间
	if strings.HasPrefix(server, "udp://") {
		protocol = "UDP"
		timeout = qo.getTimeout() // 传统协议使用普通超时
		// 使用外部提供的UDP查询函数（如果已设置，即使用连接池）
		if qo.udpQueryFunc != nil {
			resp, err = qo.udpQueryFunc(req, server)
		} else {
			resp, err = qo.queryUDP(req, server)
		}
	} else if strings.HasPrefix(server, "tcp://") {
		protocol = "TCP"
		timeout = qo.getTimeout() // 传统协议使用普通超时
		// 使用外部提供的TCP查询函数（如果已设置，即使用连接池）
		if qo.tcpQueryFunc != nil {
			resp, err = qo.tcpQueryFunc(req, server)
		} else {
			resp, err = qo.queryTCP(req, server)
		}
	} else if strings.HasPrefix(server, "https://") {
		protocol = "DoH"
		timeout = qo.getModernTimeout() // 现代协议使用更短超时
		// 使用外部提供的DoH查询函数（如果已设置）
		if qo.doHQueryFunc != nil {
			resp, err = qo.doHQueryFunc(req, server)
		} else {
			resp, err = qo.queryDoH(req, server)
		}
	} else if strings.HasPrefix(server, "tls://") {
		protocol = "DoT"
		timeout = qo.getModernTimeout() // 现代协议使用更短超时
		// 使用外部提供的DoT查询函数（如果已设置）
		if qo.doTQueryFunc != nil {
			resp, err = qo.doTQueryFunc(req, server)
		} else {
			resp, err = qo.queryDoT(req, server)
		}
	} else if strings.HasPrefix(server, "h3://") {
		protocol = "DoH3"
		timeout = qo.getModernTimeout() // 现代协议使用更短超时
		// 使用外部提供的 DoH3 查询函数（如果已设置）
		if qo.doH3QueryFunc != nil {
			resp, err = qo.doH3QueryFunc(req, server)
		} else {
			resp, err = qo.queryDoH3(req, server)
		}
	} else {
		// 兼容旧格式：传统UDP/TCP
		protocol = "UDP/TCP"
		timeout = qo.getTimeout()
		resp, err = qo.queryTraditional(req, server)
	}

	result := &QueryResult{
		Response:     resp,
		Server:       server,
		ResponseTime: time.Since(start),
		Error:        err,
	}

	if err == nil && resp != nil {
		qo.logger.Debug("✅ DNS查询成功", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"time":           result.ResponseTime.String(),
			"timeout_config": timeout.String(),
			"answers":        len(resp.Answer),
			"rcode":          dns.RcodeToString[resp.Rcode],
		})
	} else if err != nil {
		qo.logger.Debug("❌ DNS查询失败", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"timeout_config": timeout.String(),
			"error":          err.Error(),
		})
	}

	return result
}

// queryUDP 纯UDP查询
func (qo *SimpleModernOptimizer) queryUDP(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 归一化为 host:port（udp://1.1.1.1 → 1.1.1.1:53；IPv6 补成 [::1]:53）
	// 不能用 strings.Contains(address, ":") 判断，否则 ::1 这类 IPv6 字面量会被误判为「已含端口」
	address := config.UpstreamDialAddr(serverURL)

	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: qo.getTimeout(),
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)
	return resp, err
}

// queryTCP 纯TCP查询
func (qo *SimpleModernOptimizer) queryTCP(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 归一化为 host:port（tcp://1.1.1.1 → 1.1.1.1:53；IPv6 补成 [::1]:53）
	address := config.UpstreamDialAddr(serverURL)

	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	client := &dns.Client{
		Net:     "tcp",
		Timeout: qo.getTimeout(),
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)
	return resp, err
}

// queryTraditional 传统UDP/TCP查询（兼容旧格式）
func (qo *SimpleModernOptimizer) queryTraditional(req *dns.Msg, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), qo.getTimeout())
	defer cancel()

	// 旧格式可能仍带 scheme，统一归一化为 host:port 再 dial
	address := config.UpstreamDialAddr(server)

	// 优先尝试UDP
	client := &dns.Client{
		Net:     "udp",
		Timeout: qo.getTimeout(),
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)

	// UDP失败时尝试TCP（可能是响应太大）
	if err != nil && qo.enableFallback {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, address)
	}

	return resp, err
}

// queryDoH DNS over HTTPS查询 - 这个方法现在被Handler替代，此处保留是为了兼容性
func (qo *SimpleModernOptimizer) queryDoH(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	return nil, fmt.Errorf("queryDoH should be handled by RefactoredHandler, not SimpleModernOptimizer directly")
}

// queryDoT DNS over TLS查询 - 这个方法现在被Handler替代，此处保留是为了兼容性
func (qo *SimpleModernOptimizer) queryDoT(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	return nil, fmt.Errorf("queryDoT should be handled by RefactoredHandler, not SimpleModernOptimizer directly")
}

// queryDoH3 DNS over HTTP/3查询 - 实现已上移到 RefactoredHandler.queryDoH3（经 doH3QueryFunc 注入）。
// 此保留方法的目的是：当外部未注入 doH3QueryFunc 时，明确报错而不是静默降级为 DoH，
// 避免「配置了 h3:// 却实际走 HTTPS/2」的误导。
func (qo *SimpleModernOptimizer) queryDoH3(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	return nil, fmt.Errorf("queryDoH3 should be handled by RefactoredHandler (h3:// requires QUIC), not SimpleModernOptimizer directly")
}

// Close 关闭查询优化器
func (qo *SimpleModernOptimizer) Close() {
	qo.cacheMu.Lock()
	defer qo.cacheMu.Unlock()

	// 清理连接缓存
	for key, conn := range qo.connCache {
		if closer, ok := conn.(io.Closer); ok {
			closer.Close()
		}
		delete(qo.connCache, key)
	}

	qo.logger.Info("📪 [简化现代DNS查询优化器已关闭] ", map[string]interface{}{
		"rule": "SIMPLE_MODERN_OPTIMIZER_CLOSE",
	})
}
