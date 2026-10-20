package dns

import (
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/querylog"

	"github.com/miekg/dns"
)

// effectiveIPPrefer 生效档位：列表级优先，列表未配置（空值）时回退全局默认
func effectiveIPPrefer(global string, d SplitDecision) string {
	if d.IPPrefer != "" {
		return d.IPPrefer
	}
	return global
}

// filterAAAA 按 A/AAAA 偏好档位决定是否抑制本次查询。
// 语义前提：客户端 QTYPE 永远被尊重（查A回A、查AAAA回AAAA），"优先A"只能靠抑制被查类型（返回空 NODATA）实现。
//   - only_a：查询AAAA一律置空
//   - prefer_a：仅当域名确有 A 记录时置空（纯 v6 域名照常返回 AAAA，避免整体不可达）
//   - prefer_aaaa / 不干预：不抑制（查A与查AAAA都照常解析）
//
// 返回 true 表示已写出空 NODATA 响应，调用方应立即返回。
func (h *RefactoredHandler) filterAAAA(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, scope string) bool {
	if qtype != dns.TypeAAAA {
		return false // 查A的请求永不被本策略影响，也不会因此触发任何额外查询
	}
	d := h.matcherHandler.MatchDomain(domain)
	prefer := effectiveIPPrefer(h.getConfig().IPPrefer, d)
	if prefer != config.IPPreferOnlyA && prefer != config.IPPreferA {
		return false
	}

	// prefer_a 需要确认域名存在 A 记录，这是该档位唯一的上游额外开销（缓存优先）
	lookupDNS := ""
	reason := "只能A：AAAA 一律置空"
	if prefer == config.IPPreferA {
		hasA, server := h.hasARecord(domain, d, scope)
		if !hasA {
			return false // 无 A 记录（纯 v6 域名）：放行，照常返回上游 AAAA
		}
		lookupDNS = server
		reason = "优先A：域名存在 A 记录，置空 AAAA"
	}

	start := time.Now()
	resp := &dns.Msg{}
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Authoritative = false
	h.writeResponse(w, req, resp)

	h.Logger.Info("🚫 [A/AAAA 偏好策略置空] ", map[string]interface{}{
		"rule":        "IP_PREFER_FILTERED",
		"domain":      domain,
		"qtype":       dns.TypeToString[dns.TypeAAAA],
		"client_addr": clientAddr(w),
		"ip_prefer":   prefer,
		"list":        d.ListName,
	})

	e := querylog.Entry{
		Domain: domain, QType: dns.TypeToString[dns.TypeAAAA],
		Action: querylog.ActionFiltered, ListName: d.ListName,
		Rcode: dns.RcodeToString[dns.RcodeSuccess], Answers: reason,
		ElapsedMS: time.Since(start).Milliseconds(),
	}
	// prefer_a 为判定确实发过 A 查询时才记录上游与解析模式
	if lookupDNS != "" {
		e.DNS = lookupDNS
		e.DNSMode = d.DNSMode
	}
	h.recordQuery(w, e)
	return true
}

// hasARecord 判断域名是否存在 A 记录：先读缓存，未命中才补查一次 A
// 补查复用分流路由（上游、解析模式、ECS），结果由缓存层缓存，后续 AAAA 查询不再重复回源
func (h *RefactoredHandler) hasARecord(domain string, d SplitDecision, scope string) (bool, string) {
	if resp, hit, _, _ := h.cacheManager.GetScoped(scope, domain, dns.TypeA); hit {
		return hasIPv4Answer(resp), ""
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	resp, server, err := h.proxyQueryWithCaching(applySplitECS(req, d), h.upstreamsFor(domain, d), domain, dns.TypeA, d.DNSMode, scope)
	if err != nil {
		h.Logger.Debug("⚠️ [A/AAAA 偏好判定补查 A 失败，放行 AAAA] ", map[string]interface{}{
			"rule":   "IP_PREFER_LOOKUP_A_FAILED",
			"domain": domain,
			"error":  err.Error(),
		})
		return false, ""
	}
	return hasIPv4Answer(resp), server
}

// hasIPv4Answer 响应中是否存在 A 记录（仅成功响应才算有）
func hasIPv4Answer(resp *dns.Msg) bool {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.A); ok {
			return true
		}
	}
	return false
}
