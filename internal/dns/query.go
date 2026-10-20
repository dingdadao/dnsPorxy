package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dnsPorxy/internal/config"

	"github.com/miekg/dns"
)

// proxyQuery 内部通用查询入口（云替换/CNAME/刷新等链路）：按并发竞速执行并带 BackupDNS 兜底
func (h *RefactoredHandler) proxyQuery(req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	resp, _, err := h.queryWithFallback(req, upstreams, config.DNSModeRace)
	return resp, err
}

// queryWithFallback 执行上游查询（按 mode 选择竞速/串行），无有效结果时回退 BackupDNS
// 第二个返回值是实际给出应答的上游服务器（用于解析日志），失败时为空
func (h *RefactoredHandler) queryWithFallback(req *dns.Msg, upstreams []string, mode string) (*dns.Msg, string, error) {
	if len(upstreams) == 0 {
		return nil, "", errors.New("no upstream servers available")
	}

	result := h.queryUpstream(req, upstreams, mode)

	// 优先返回有效结果给客户端，如果没有有效结果才返回最快结果
	if result.HasSuccess && result.SuccessResult != nil && result.SuccessResult.Response != nil {
		return result.SuccessResult.Response, result.SuccessResult.Server, nil
	}

	// 没有有效结果，尝试使用备份DNS服务器
	if resp, ok := h.queryBackupDNS(req); ok {
		return resp, h.getConfig().BackupDNS, nil
	}

	// 没有有效结果，返回最快结果（可能是错误）
	if result.FastestResult == nil || result.FastestResult.Error != nil {
		if result.FastestResult != nil {
			return nil, "", result.FastestResult.Error
		}
		return nil, "", errors.New("all upstream queries failed")
	}

	return result.FastestResult.Response, result.FastestResult.Server, nil
}

// queryBackupDNS 用备份DNS做单台兜底查询，成功返回响应与 true
func (h *RefactoredHandler) queryBackupDNS(req *dns.Msg) (*dns.Msg, bool) {
	backup := h.getConfig().BackupDNS
	if backup == "" {
		return nil, false
	}

	h.Logger.Debug("🔄 所有上游服务器查询失败，尝试使用备份DNS", map[string]interface{}{
		"backup_dns": backup,
	})
	backupResult := h.querySingleServer(req, backup)
	if backupResult != nil && backupResult.Response != nil && backupResult.Error == nil {
		h.Logger.Debug("✅ 备份DNS查询成功", map[string]interface{}{
			"backup_dns": backup,
		})
		return backupResult.Response, true
	}
	h.Logger.Debug("❌ 备份DNS查询也失败", map[string]interface{}{
		"backup_dns": backup,
		"error":      backupResult.Error,
	})
	return nil, false
}

// queryUpstream 按解析模式执行上游查询
// failover/wrandom 仅现代优化器支持（传统优化器为旧格式 host:port 的兼容路径，不支持模式选择）
func (h *RefactoredHandler) queryUpstream(req *dns.Msg, upstreams []string, mode string) *ConcurrentQueryResult {
	if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		switch mode {
		case config.DNSModeFailover:
			return modernOptimizer.QueryFailover(req, upstreams)
		case config.DNSModeWRandom:
			return modernOptimizer.QueryWeightedRandom(req, upstreams)
		default:
			return modernOptimizer.Query(req, upstreams)
		}
	}
	if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		return traditionalOptimizer.Query(req, upstreams)
	}
	return &ConcurrentQueryResult{
		FastestResult: &QueryResult{Error: errors.New("unknown query optimizer type")},
		HasSuccess:    false,
	}
}

// flightOutcome 单飞行回源的结果载体（resp/server/err 一次性带出）
type flightOutcome struct {
	resp   *dns.Msg
	server string
	err    error
}

// proxyQueryWithCaching 代理查询并缓存原始上游响应。
// 同一（scope、域名、qtype、模式、上游集合）的并发 miss 由 single-flight 合并为一次回源，
// 避免「并发冷启动的同一域名各自竞速」把对外请求放大为 客户端数 × 上游数。
// 第二个返回值是实际给出应答的上游服务器（用于解析日志）
func (h *RefactoredHandler) proxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16, mode, scope string) (*dns.Msg, string, error) {
	key := fmt.Sprintf("%s|%s|%d|%s|%s", scope, domain, qtype, mode, strings.Join(upstreams, ","))

	v, _, shared := h.upstreamFlight.Do(key, func() (interface{}, error) {
		resp, server, err := h.doProxyQueryWithCaching(req, upstreams, domain, qtype, mode, scope)
		return flightOutcome{resp: resp, server: server, err: err}, nil
	})

	out := v.(flightOutcome)
	resp := out.resp
	// 结果被多个并发请求共享时必须复制：调用方随即会用 writeResponse 原地改写
	// ID/Question/OPT 等字段，直接共享同一 *dns.Msg 会并发污染。
	if shared && resp != nil {
		resp = resp.Copy()
	}
	return resp, out.server, out.err
}

// doProxyQueryWithCaching 执行一次真正的回源查询并缓存结果（由 proxyQueryWithCaching 经单飞行调用）
func (h *RefactoredHandler) doProxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16, mode, scope string) (*dns.Msg, string, error) {
	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query_detailed")

	if len(upstreams) == 0 {
		upstreamTimer.End() // 确保计时器关闭
		return nil, "", errors.New("no upstream servers available")
	}

	result := h.queryUpstream(req, upstreams, mode)

	// 获取上游查询时间
	upstreamTime := upstreamTimer.End()

	// 有成功结果：缓存原始响应（负缓存TTL由cacheManager.Set按RFC 2308处理）并返回
	if result.HasSuccess && result.SuccessResult != nil && result.SuccessResult.Response != nil {
		resp := result.SuccessResult.Response
		h.cacheManager.SetScoped(scope, domain, qtype, resp, false)
		h.Logger.Debug("✅ 上游查询成功并缓存原始响应", map[string]interface{}{
			"domain":         domain,
			"qtype":          dns.TypeToString[qtype],
			"success_server": result.SuccessResult.Server,
			"rcode":          dns.RcodeToString[resp.Rcode],
			"answers":        len(resp.Answer),
			"upstream_time":  upstreamTime,
		})
		return resp, result.SuccessResult.Server, nil
	}

	// 上游（含分流列表 DNS）全部失败时回退 BackupDNS，与非IP记录路径保持一致
	if resp, ok := h.queryBackupDNS(req); ok {
		if resp.Rcode == dns.RcodeSuccess {
			h.cacheManager.SetScoped(scope, domain, qtype, resp, false)
		}
		h.Logger.Debug("✅ 已回退备份DNS", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"rcode":  dns.RcodeToString[resp.Rcode],
		})
		return resp, h.getConfig().BackupDNS, nil
	}

	// 没有有效结果，返回最快结果（可能是错误）
	if result.FastestResult != nil {
		if result.FastestResult.Error != nil {
			return nil, "", result.FastestResult.Error
		}
		if result.FastestResult.Response != nil {
			return result.FastestResult.Response, result.FastestResult.Server, nil
		}
	}

	return nil, "", errors.New("all upstream queries failed")
}

// ValidateDNSResult 验证查询结果是否包含有效的 DNS 记录
func (h *RefactoredHandler) ValidateDNSResult(result *ConcurrentQueryResult) (bool, string) {
	if result == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "result == nil"})
		return false, "result == nil"
	}
	if result.SuccessResult == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "SuccessResult == nil"})
		return false, "SuccessResult == nil"
	}
	r := result.SuccessResult
	if r.Error != nil {
		h.Logger.Debug("DNS 响应错误", map[string]interface{}{"error": r.Error.Error()})
		return false, r.Error.Error()
	}
	if r.Response == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "Response == nil"})
		return false, "Response == nil"
	}
	resp := r.Response
	if resp.Rcode != dns.RcodeSuccess {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "Rcode != Success", "rcode": resp.Rcode})
		return false, fmt.Sprintf("Rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		// 根据DNS NOERROR空答案处理规范，当DNS查询返回NOERROR但Answer为空时，
		// 表示域名存在但无请求的记录类型，此响应应被视为有效并进行缓存
		h.Logger.Debug("DNS NOERROR空答案响应", map[string]interface{}{"reason": "Answer 为空但rcode为success"})
		// 返回true表示这是一个有效的响应，需要缓存
		return true, "NOERROR空答案响应有效"
	}

	h.Logger.Debug("DNS 验证成功", map[string]interface{}{"answer_count": len(resp.Answer)})
	return true, "验证成功"
}

// ValidateNonIPDNSResult 验证非IP记录DNS查询结果
func (h *RefactoredHandler) ValidateNonIPDNSResult(result *ConcurrentQueryResult) (bool, string) {
	if result == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "result == nil"})
		return false, "result == nil"
	}
	if result.FastestResult == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "FastestResult == nil"})
		return false, "FastestResult == nil"
	}

	r := result.FastestResult
	if r.Error != nil {
		h.Logger.Debug("非IP记录DNS响应错误", map[string]interface{}{"error": r.Error.Error()})
		return false, r.Error.Error()
	}
	if r.Response == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "Response == nil"})
		return false, "Response == nil"
	}
	resp := r.Response
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "Rcode != Success and Rcode != NameError", "rcode": resp.Rcode})
		return false, fmt.Sprintf("Rcode=%d", resp.Rcode)
	}
	// 对于非IP记录，即使Answer为空也被视为有效响应（如NOERROR响应）
	h.Logger.Debug("非IP记录DNS验证成功", map[string]interface{}{"answer_count": len(resp.Answer), "rcode": dns.RcodeToString[resp.Rcode]})
	return true, "验证成功"
}

// IsValidDNSResult 只返回 bool
func (h *RefactoredHandler) IsValidDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateDNSResult(result)
	return ok
}

// IsValidNonIPDNSResult 验证非IP记录DNS结果
func (h *RefactoredHandler) IsValidNonIPDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateNonIPDNSResult(result)
	return ok
}

// querySingleServer 查询单个DNS服务器
func (h *RefactoredHandler) querySingleServer(req *dns.Msg, server string) *QueryResult {
	start := time.Now()

	var resp *dns.Msg
	var err error
	var protocol string
	var timeout time.Duration

	// 根据URL scheme选择协议和超时时间
	if strings.HasPrefix(server, "udp://") {
		protocol = "UDP"
		timeout = h.getConfig().Timeout // 传统协议使用普通超时
		resp, err = h.queryUDP(req, server)
	} else if strings.HasPrefix(server, "tcp://") {
		protocol = "TCP"
		timeout = h.getConfig().Timeout // 传统协议使用普通超时
		resp, err = h.queryTCP(req, server)
	} else if strings.HasPrefix(server, "https://") {
		protocol = "DoH"
		timeout = h.getConfig().ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoH(req, server)
	} else if strings.HasPrefix(server, "tls://") {
		protocol = "DoT"
		timeout = h.getConfig().ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoT(req, server)
	} else if strings.HasPrefix(server, "h3://") {
		protocol = "DoH3"
		timeout = h.getConfig().ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoH3(req, server)
	} else {
		// 兼容旧格式：传统UDP/TCP
		protocol = "UDP/TCP"
		timeout = h.getConfig().Timeout
		resp, err = h.queryTraditional(req, server)
	}

	result := &QueryResult{
		Response:     resp,
		Server:       server,
		ResponseTime: time.Since(start),
		Error:        err,
	}

	if err == nil && resp != nil {
		h.Logger.Debug("✅ 备份DNS查询成功", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"time":           result.ResponseTime.String(),
			"timeout_config": timeout.String(),
			"answers":        len(resp.Answer),
			"rcode":          dns.RcodeToString[resp.Rcode],
		})
	} else if err != nil {
		h.Logger.Debug("❌ 备份DNS查询失败", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"timeout_config": timeout.String(),
			"error":          err.Error(),
		})
	}

	return result
}

// queryUDP 执行UDP DNS查询
func (h *RefactoredHandler) queryUDP(req *dns.Msg, server string) (*dns.Msg, error) {
	// 归一化为 host:port（udp://1.1.1.1 → 1.1.1.1:53）
	// 不补默认端口时 dns.Client 会直接报 "missing port in address"，且该函数通过
	// udpQueryFunc 注入给现代优化器，会完全绕开其他地方带 :53 兜底的实现
	addr := config.UpstreamDialAddr(server)

	// 使用连接池获取客户端
	client := h.udpConnPool.GetClient(addr, h.getConfig().Timeout)

	// 确保在函数结束时归还客户端到池中
	defer func() {
		h.udpConnPool.PutClient(addr)
	}()

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryTCP 执行TCP DNS查询
func (h *RefactoredHandler) queryTCP(req *dns.Msg, server string) (*dns.Msg, error) {
	// 归一化为 host:port（tcp://1.1.1.1 → 1.1.1.1:53）
	addr := config.UpstreamDialAddr(server)

	// 使用连接池获取客户端
	client := h.tcpConnPool.GetClient(addr, h.getConfig().Timeout)

	// 确保在函数结束时归还客户端到池中
	defer func() {
		h.tcpConnPool.PutClient(addr)
	}()

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryDoH 执行DoH DNS查询
func (h *RefactoredHandler) queryDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用连接池获取HTTP客户端
	client := h.dohConnPool.GetClient(server)

	// 解析URL
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// 如果没有路径，使用默认的/dns-query
	if u.Path == "" || u.Path == "/" {
		u.Path = "/dns-query"
	}

	// 将DNS消息编码为wireformat
	wireData, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), h.getConfig().ModernTimeout)
	defer cancel()

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// 设置DoH头部
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// 发送请求
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// 检查HTTP状态码
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %d", httpResp.StatusCode)
	}

	// 读取响应数据
	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// 解析DNS响应
	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return resp, nil
}

// queryDoT 执行DoT DNS查询
func (h *RefactoredHandler) queryDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	// 单次尝试：取连接→写入→读取。实测阿里 DoT 空闲约 5s 即 EOF 断开连接，
	// 复用已被断开的连接会报写入/读取失败；失败时丢弃死连接并强制新建连接重试一次，
	// 客户端无感，错误日志大幅减少。
	tryOnce := func(getConn func(context.Context, string) (*DoTConn, error)) (*dns.Msg, error) {
		// 从连接池获取DoT连接
		conn, err := getConn(context.Background(), server)
		if err != nil {
			return nil, err
		}

		// 确保在函数结束时归还连接到池中
		discarded := false
		defer func() {
			if !discarded {
				h.dotConnPool.PutConn(conn)
			}
		}()

		// 使用TLS连接创建dns.Conn并执行查询
		dnsConn := &dns.Conn{Conn: conn.tlsConn}
		if err := dnsConn.WriteMsg(req); err != nil {
			// 写入失败说明连接已损坏（如服务器端断开导致的 broken pipe），
			// 丢弃而非归还，避免后续复用死连接反复失败。
			discarded = true
			h.dotConnPool.DiscardConn(conn)
			return nil, err
		}

		resp, err := dnsConn.ReadMsg()
		if err != nil {
			// 读取出错同样视为连接不可用，丢弃从池中移除并关闭。
			discarded = true
			h.dotConnPool.DiscardConn(conn)
			return nil, err
		}

		return resp, nil
	}

	resp, err := tryOnce(h.dotConnPool.GetConn)
	if err == nil {
		return resp, nil
	}
	// 首次失败（复用的连接已被服务端断开），丢弃死连接后重试一次。
	// 重试必须用 GetFreshConn 强制新建：池中可能还残留其它同样已死的连接，
	// 若继续复用它们，重试会以相同方式再次失败。
	resp, err2 := tryOnce(h.dotConnPool.GetFreshConn)
	if err2 == nil {
		return resp, nil
	}
	// 重试仍失败才是真实错误
	h.Logger.Error("DoT查询失败", map[string]interface{}{
		"server": server,
		"error":  err2,
	})
	return nil, err2
}

// queryDoH3 执行 DoH3 DNS 查询（真实 HTTP/3 over QUIC）
func (h *RefactoredHandler) queryDoH3(req *dns.Msg, server string) (*dns.Msg, error) {
	client := h.doh3ConnPool.GetClient(server)

	// 解析 URL：h3://host/path → https://host/path（http3.RoundTripper 内部走 QUIC）
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH3 URL: %w", err)
	}
	u.Scheme = "https"
	if u.Path == "" || u.Path == "/" {
		u.Path = "/dns-query"
	}

	wireData, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.getConfig().ModernTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP/3 request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH3 request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH3 request failed with status: %d", httpResp.StatusCode)
	}

	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH3 response: %w", err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack DoH3 response: %w", err)
	}
	return resp, nil
}

// queryTraditional 执行传统DNS查询
func (h *RefactoredHandler) queryTraditional(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用SimpleModernOptimizer的方法
	optimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer)
	if !ok {
		return nil, fmt.Errorf("not a SimpleModernOptimizer")
	}
	return optimizer.queryTraditional(req, server)
}
