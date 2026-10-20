package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// ReplaceConfig 生效的云替换目标：全局配置，或命中的客户端分组覆写后的目标
type ReplaceConfig struct {
	CFDomain  string // CF 替换域名
	AWSDomain string // AWS 替换域名
	CFAPI     string // CF 替换接口（非空则从接口取 IP）
	APICount  int    // 接口取前 N 条
}

// CloudHandler 处理云服务相关功能
type CloudHandler struct {
	cfgMu         sync.RWMutex
	config        *config.Config
	logger        *utils.EnhancedLogger
	cacheManager  *CacheManager
	cloudDetector *CloudDetector
	proxyQuery    func(*dns.Msg, []string) (*dns.Msg, error)   // 代理查询函数
	respond       func(dns.ResponseWriter, *dns.Msg, *dns.Msg) // 统一响应出口（保证EDNS/TC处理一致）

	apiMu      sync.RWMutex                 // 保护 apiClients
	apiClients map[string]*ReplaceAPIClient // 按 (url,count) 索引的 CF 替换接口客户端
}

// getConfig 获取当前配置（web保存后热切换）
func (ch *CloudHandler) getConfig() *config.Config {
	ch.cfgMu.RLock()
	defer ch.cfgMu.RUnlock()
	return ch.config
}

// UpdateConfig 热更新配置引用，并预建/预取所有用到的 CF 替换接口客户端
func (ch *CloudHandler) UpdateConfig(cfg *config.Config) {
	ch.cfgMu.Lock()
	ch.config = cfg
	ch.cfgMu.Unlock()
	ch.WarmReplaceAPIs(cfg)
}

// replaceAPIKey 生成接口客户端的索引键
func replaceAPIKey(url string, count int) string {
	if count <= 0 {
		count = 1
	}
	return url + "|" + strconv.Itoa(count)
}

// apiClientFor 按 (url,count) 惰性获取/创建 CF 接口客户端；首次创建时后台预取
func (ch *CloudHandler) apiClientFor(url string, count int) *ReplaceAPIClient {
	if url == "" {
		return nil
	}
	key := replaceAPIKey(url, count)

	ch.apiMu.RLock()
	c := ch.apiClients[key]
	ch.apiMu.RUnlock()
	if c != nil {
		return c
	}

	ch.apiMu.Lock()
	if c = ch.apiClients[key]; c == nil {
		if ch.apiClients == nil {
			ch.apiClients = make(map[string]*ReplaceAPIClient)
		}
		c = NewReplaceAPIClient(url, count, ch.getConfig().ReplaceCacheTime, ch.logger)
		ch.apiClients[key] = c
		go c.Prefetch() // 提前预取：查询路径无需等 HTTP
	}
	ch.apiMu.Unlock()
	return c
}

// WarmReplaceAPIs 依据配置预建并预取所有用到的接口客户端（全局 + 各分组覆写），
// 并清理不再使用的客户端，避免配置反复变更导致条目堆积
func (ch *CloudHandler) WarmReplaceAPIs(cfg *config.Config) {
	targets := []ReplaceConfig{{CFAPI: cfg.ReplaceCFAPI, APICount: cfg.ReplaceAPICount}}
	for _, g := range cfg.ISPGroups {
		if g.CloudReplace.Override {
			targets = append(targets, ReplaceConfig{CFAPI: g.CloudReplace.CFAPI, APICount: g.CloudReplace.APICount})
		}
	}
	for _, g := range cfg.CustomGroups {
		if g.CloudReplace.Override {
			targets = append(targets, ReplaceConfig{CFAPI: g.CloudReplace.CFAPI, APICount: g.CloudReplace.APICount})
		}
	}
	keep := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t.CFAPI == "" {
			continue
		}
		keep[replaceAPIKey(t.CFAPI, t.APICount)] = struct{}{}
		ch.apiClientFor(t.CFAPI, t.APICount)
	}
	ch.apiMu.Lock()
	for k := range ch.apiClients {
		if _, ok := keep[k]; !ok {
			delete(ch.apiClients, k)
		}
	}
	ch.apiMu.Unlock()
}

// NewCloudHandler 创建新的云服务处理器
func NewCloudHandler(config *config.Config, logger *utils.EnhancedLogger, cacheManager *CacheManager, cloudDetector *CloudDetector, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error), respond func(dns.ResponseWriter, *dns.Msg, *dns.Msg)) *CloudHandler {
	ch := &CloudHandler{
		config:        config,
		logger:        logger,
		cacheManager:  cacheManager,
		cloudDetector: cloudDetector,
		proxyQuery:    proxyQuery,
		respond:       respond,
	}
	ch.WarmReplaceAPIs(config)
	return ch
}

// HandleCloudReplacement 处理云IP替换
// 保持上游原始响应结构（CNAME链、owner、TTL均不变），仅将A/AAAA记录的IP值替换为替换域名的IP；
// 云检测已在processQuery完成，此处不再重复检测；
// 替换不可用（替换域名解析失败/无可用IP）时降级返回上游原始应答，不整条请求失败
// ipPrefer 为生效的 A/AAAA 偏好档位：prefer_aaaa 时 AAAA 不再被置空，降级返回上游真实 AAAA
// scope 为客户端线路的缓存隔离标识；rc 为本次生效的云替换目标（全局或分组覆写）
// 返回值是实际写给客户端的响应（供解析日志记录结果），失败时为 nil
func (ch *CloudHandler) HandleCloudReplacement(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, cloudType int, originalResp *dns.Msg, ipPrefer string, scope string, rc ReplaceConfig) (*dns.Msg, error) {
	var cloudTypeName string
	switch CloudType(cloudType) {
	case CloudTypeCloudflare:
		cloudTypeName = "Cloudflare"
	case CloudTypeAWS:
		cloudTypeName = "AWS"
	default:
		ch.logger.Warn("⚠️ 未知云服务类型", map[string]interface{}{
			"cloud_type": cloudType,
			"domain":     domain,
		})
		ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return nil, fmt.Errorf("unknown cloud type %d", cloudType)
	}

	ch.logger.Debug("开始云IP替换查询", map[string]interface{}{
		"original_domain": domain,
		"cloud_type":      cloudTypeName,
	})

	// 查询替换域名IP（含缓存与CNAME链解析）
	v4, v6, err := ch.ResolveReplaceIPs(req.Id, domain, qtype, cloudType, rc)
	if err != nil {
		return ch.respondFallback(w, req, domain, qtype, originalResp, "替换域名查询失败: "+err.Error())
	}

	// AAAA查询无IPv6替换：默认返回空answer让客户端降级到A查询；
	// 优先AAAA档位下不置空，降级返回上游真实AAAA（IPv6 客户端不被静默丢弃）
	if qtype == dns.TypeAAAA && len(v6) == 0 {
		if ipPrefer == config.IPPreferAAAA {
			return ch.respondFallback(w, req, domain, qtype, originalResp, "优先AAAA：无IPv6替换，返回上游真实AAAA")
		}
		ch.logger.Debug("🔄 AAAA查询无结果，返回空响应让客户端降级到A查询", map[string]interface{}{
			"domain": domain,
		})
		resp := &dns.Msg{}
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Authoritative = false
		ch.respond(w, req, resp)
		ch.logger.Info("✅ [DNS查询完成-AAAA无结果降级] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"source":      "aaaa_fallback",
			"result":      "success",
		})
		return resp, nil
	}

	// A查询无IPv4替换：降级返回上游原始应答
	if qtype == dns.TypeA && len(v4) == 0 {
		return ch.respondFallback(w, req, domain, qtype, originalResp, "替换域名无有效IPv4记录")
	}

	// 基于上游原始响应构建替换响应
	finalResp := buildCloudResponse(originalResp, qtype, v4, v6)
	if finalResp == nil {
		return ch.respondFallback(w, req, domain, qtype, originalResp, "构建云替换响应失败")
	}

	// 缓存云替换响应（使用替换缓存时间，按客户端线路 scope 隔离）
	if ch.getConfig().ReplaceCacheTime > 0 {
		ch.cacheManager.SetCloudResponseScoped(scope, domain, qtype, finalResp, cloudType, ch.getConfig().ReplaceCacheTime)
	} else {
		ch.cacheManager.SetCloudResponseScoped(scope, domain, qtype, finalResp, cloudType)
	}

	ch.logger.Info("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"client_addr":  w.RemoteAddr().String(),
		"source":       "cloud_replacement",
		"cloud_type":   cloudTypeName,
		"answer_count": len(finalResp.Answer),
		"result":       "success",
	})

	ch.respond(w, req, finalResp)
	return finalResp, nil
}

// respondFallback 替换不可用时的降级出口：返回上游原始应答（真实云 IP），避免整条请求 SERVFAIL
// 返回值是实际写给客户端的响应（供解析日志记录结果）
func (ch *CloudHandler) respondFallback(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, originalResp *dns.Msg, reason string) (*dns.Msg, error) {
	ch.logger.Warn("⚠️ 云IP替换不可用，降级返回上游原始应答", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"reason": reason,
	})
	if originalResp == nil {
		ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return nil, errors.New(reason)
	}
	ch.respond(w, req, originalResp)
	ch.logger.Info("✅ [DNS查询完成-云替换降级] ", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"client_addr":  w.RemoteAddr().String(),
		"source":       "cloud_fallback",
		"answer_count": len(originalResp.Answer),
		"result":       "success",
	})
	return originalResp, nil
}

// ResolveReplaceIPs 获取替换IP：CF 配置了接口时直接从接口取（缓存+预取），否则查询替换域名
// （先查缓存，未命中回源并缓存），返回去重后的A/AAAA记录；替换目标取自 rc（全局或分组覆写）
func (ch *CloudHandler) ResolveReplaceIPs(reqID uint16, domain string, qtype uint16, cloudType int, rc ReplaceConfig) ([]*dns.A, []*dns.AAAA, error) {
	// CF 走接口：跳过替换域名的 DNS 解析（接口只提供 IPv4，AAAA 交由上层按无 v6 替换处理）
	if apiClient := ch.apiClientFor(rc.CFAPI, rc.APICount); apiClient != nil && CloudType(cloudType) == CloudTypeCloudflare {
		if qtype != dns.TypeA {
			return nil, nil, nil
		}
		addrs, err := apiClient.IPs()
		if err == nil {
			v4 := make([]*dns.A, 0, len(addrs))
			for _, addr := range addrs {
				v4 = append(v4, &dns.A{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: replaceAPIRecordTTL},
					A:   net.IP(addr.AsSlice()),
				})
			}
			ch.logger.Debug("🌐 使用替换接口 IP", map[string]interface{}{
				"url":      apiClient.url,
				"ip_count": len(v4),
			})
			return v4, nil, nil
		}
		// 接口不可用时回退替换域名解析，避免整条请求失败
		ch.logger.Warn("⚠️ 替换接口取数失败，回退替换域名解析", map[string]interface{}{
			"url":   apiClient.url,
			"error": err.Error(),
		})
	}

	var replaceDomain string
	switch CloudType(cloudType) {
	case CloudTypeCloudflare:
		replaceDomain = rc.CFDomain
	case CloudTypeAWS:
		replaceDomain = rc.AWSDomain
	default:
		return nil, nil, fmt.Errorf("unknown cloud type %d", cloudType)
	}
	if replaceDomain == "" {
		return nil, nil, fmt.Errorf("replace domain not configured for cloud type %d", cloudType)
	}

	// 先查缓存（缓存的是原始响应，CNAME链在下方统一解析）
	replaceResp, hit, _, _ := ch.cacheManager.Get(replaceDomain, qtype)
	if !hit {
		replaceReq := &dns.Msg{}
		replaceReq.SetQuestion(dns.Fqdn(replaceDomain), qtype)
		// 保持请求ID一致，避免响应匹配问题
		replaceReq.Id = reqID

		var err error
		replaceResp, err = ch.proxyQuery(replaceReq, ch.getConfig().Upstream)
		// 无应答或上游返回非成功rcode时也要给出可读原因（err为nil时不能直接 %w）
		if err == nil && (replaceResp == nil || replaceResp.Rcode != dns.RcodeSuccess) {
			why := "no response"
			if replaceResp != nil {
				why = "upstream returned " + dns.RcodeToString[replaceResp.Rcode]
			}
			err = errors.New(why)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("replace domain query failed: %w", err)
		}
		ch.logger.Debug("🔍 替换域名查询成功", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
		})
	} else {
		ch.logger.Debug("🎯 使用替换域名缓存", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
		})
	}

	// 对替换域名的响应进行CNAME链解析，获取最终IP（替换域名不再做云检测）
	processedReplaceResp := ch.processReplaceDomainResponse(replaceResp, replaceDomain, ch.getConfig().Upstream)
	if processedReplaceResp == nil {
		return nil, nil, fmt.Errorf("replace domain processing failed")
	}

	// 首次查询且缓存未命中时，缓存处理后的结果（遵循上游TTL，由缓存层递减）
	if !hit {
		ch.cacheManager.Set(replaceDomain, qtype, processedReplaceResp, false)
		ch.logger.Debug("💾 缓存替换域名查询结果", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
			"answer_count":   len(processedReplaceResp.Answer),
		})
	}

	var v4 []*dns.A
	var v6 []*dns.AAAA
	seenIPs := make(map[string]bool)
	for _, rr := range processedReplaceResp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if ipStr := record.A.String(); !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				v4 = append(v4, record)
			}
		case *dns.AAAA:
			if ipStr := record.AAAA.String(); !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				v6 = append(v6, record)
			}
		}
	}
	return v4, v6, nil
}

// buildCloudResponse 基于上游原始响应构建云替换响应
// 保持上游响应结构（CNAME链、owner、TTL均不变），仅将A/AAAA记录的IP值替换为替换域名的IP（轮询分配）
// 若上游原始响应中无A/AAAA记录，回退为owner=查询域名的仅IP简单形状
func buildCloudResponse(originalResp *dns.Msg, qtype uint16, v4 []*dns.A, v6 []*dns.AAAA) *dns.Msg {
	if originalResp == nil {
		return nil
	}

	// 判断原始响应是否含IP记录
	hasIP := false
	for _, rr := range originalResp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			hasIP = true
		}
	}

	queryName := "."
	if len(originalResp.Question) > 0 {
		queryName = originalResp.Question[0].Name
	}

	if !hasIP {
		// 回退形状：owner=查询域名，仅包含替换IP
		resp := &dns.Msg{}
		resp.MsgHdr = originalResp.MsgHdr
		resp.Question = originalResp.Question
		resp.Ns = originalResp.Ns
		resp.Extra = originalResp.Extra
		for _, rr := range v4 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: queryName, Rrtype: dns.TypeA, Class: rr.Hdr.Class, Ttl: rr.Hdr.Ttl},
				A:   rr.A,
			})
		}
		for _, rr := range v6 {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: queryName, Rrtype: dns.TypeAAAA, Class: rr.Hdr.Class, Ttl: rr.Hdr.Ttl},
				AAAA: rr.AAAA,
			})
		}
		return resp
	}

	// 结构保持：复制原始响应，仅替换IP值
	resp := originalResp.Copy()
	v4i, v6i := 0, 0
	answer := make([]dns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if len(v4) == 0 {
				continue // 无可替换IPv4，剔除云IP
			}
			rep := v4[v4i%len(v4)]
			v4i++
			answer = append(answer, &dns.A{Hdr: record.Hdr, A: rep.A})
		case *dns.AAAA:
			if len(v6) == 0 {
				continue // 无可替换IPv6，剔除云IP
			}
			rep := v6[v6i%len(v6)]
			v6i++
			answer = append(answer, &dns.AAAA{Hdr: record.Hdr, AAAA: rep.AAAA})
		default:
			answer = append(answer, rr)
		}
	}
	resp.Answer = answer
	return resp
}

// replaceCloudIPs 用替换域名的IP替换原始响应中的云服务IP
func (ch *CloudHandler) replaceCloudIPs(originalResp *dns.Msg, originalDetection *CloudDetectionResult) *dns.Msg {
	if originalResp == nil || originalDetection == nil {
		return originalResp
	}

	// 查询替换域名获取IP地址
	replaceDomain := originalDetection.ReplaceDomain
	if replaceDomain == "" {
		return originalResp
	}

	// 查询替换域名的A和AAAA记录
	replaceReqA := &dns.Msg{}
	replaceReqA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeA)

	replaceReqAAAA := &dns.Msg{}
	replaceReqAAAA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeAAAA)

	var replaceIPs []netip.Addr

	// 获取替换域名的A记录
	if replaceRespA, err := ch.proxyQuery(replaceReqA, ch.getConfig().Upstream); err == nil && replaceRespA != nil && replaceRespA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespA.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, err := netip.ParseAddr(a.A.String()); err == nil {
					// 检查IP是否已存在，避免重复
					isDuplicate := false
					for _, existingIP := range replaceIPs {
						if existingIP.Compare(ip) == 0 {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						replaceIPs = append(replaceIPs, ip)
					}
				}
			}
		}
	}

	// 获取替换域名的AAAA记录
	if replaceRespAAAA, err := ch.proxyQuery(replaceReqAAAA, ch.getConfig().Upstream); err == nil && replaceRespAAAA != nil && replaceRespAAAA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				if ip, err := netip.ParseAddr(aaaa.AAAA.String()); err == nil {
					// 检查IP是否已存在，避免重复
					isDuplicate := false
					for _, existingIP := range replaceIPs {
						if existingIP.Compare(ip) == 0 {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						replaceIPs = append(replaceIPs, ip)
					}
				}
			}
		}
	}

	if len(replaceIPs) == 0 {
		ch.logger.Warn("⚠️ 替换域名无有效IP记录", map[string]interface{}{
			"replace_domain": replaceDomain,
		})
		return originalResp
	}

	// 创建新的响应，保留原始响应的基本结构，但只包含非IP记录和替换后的IP记录
	newResp := &dns.Msg{}
	*newResp = *originalResp // 复制原始响应结构
	newResp.Answer = nil     // 清空答案部分

	// 复制非IP的记录（如CNAME等）
	for _, rr := range originalResp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 跳过云服务IP记录，稍后用替换IP替换
		default:
			// 保留非IP记录
			newResp.Answer = append(newResp.Answer, dns.Copy(rr))
		}
	}

	// 添加替换IP，根据原始查询类型决定添加哪些类型的IP
	seenIPs := make(map[string]bool) // 用于去重
	for _, ip := range replaceIPs {
		if ip.Is4() && originalResp.Question[0].Qtype == dns.TypeA {
			// 查找原始响应中的任意一个A记录来获取TTL和Header信息作为参考
			var referenceTTL uint32 = 1800 // 默认TTL
			for _, originalRR := range originalResp.Answer {
				if originalA, ok := originalRR.(*dns.A); ok {
					referenceTTL = originalA.Hdr.Ttl
					break
				}
			}

			newA := &dns.A{
				Hdr: dns.RR_Header{
					Name:   originalResp.Question[0].Name, // 使用原始查询的域名
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    referenceTTL, // 使用参考TTL
				},
				A: ip.AsSlice(),
			}
			ipStr := ip.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				newResp.Answer = append(newResp.Answer, newA)
			}
		} else if ip.Is6() && originalResp.Question[0].Qtype == dns.TypeAAAA {
			// 查找原始响应中的任意一个AAAA记录来获取TTL和Header信息作为参考
			var referenceTTL uint32 = 1800 // 默认TTL
			for _, originalRR := range originalResp.Answer {
				if originalAAAA, ok := originalRR.(*dns.AAAA); ok {
					referenceTTL = originalAAAA.Hdr.Ttl
					break
				}
			}

			newAAAA := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   originalResp.Question[0].Name, // 使用原始查询的域名
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    referenceTTL, // 使用参考TTL
				},
				AAAA: ip.AsSlice(),
			}
			ipStr := ip.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				newResp.Answer = append(newResp.Answer, newAAAA)
			}
		}
	}

	ch.logger.Debug("🔄 云IP替换完成", map[string]interface{}{
		"original_ips_count": len(originalDetection.DetectedIPs),
		"replace_ips_count":  len(replaceIPs),
		"final_answer_count": len(newResp.Answer),
	})

	return newResp
}

// processCloudResponse 处理云域名响应，确保符合DNS协议标准
func (ch *CloudHandler) processCloudResponse(resp *dns.Msg, domain string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 检查响应中是否只有IP记录，如果是则跳过CNAME处理
	// 只有在响应中包含CNAME记录时才进行递归处理
	containsCNAME := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			containsCNAME = true
			break
		}
	}

	if !containsCNAME {
		// 如果没有CNAME记录，直接返回响应，只处理TTL
		ch.ensureMinimumTTL(resp, ch.getConfig().Cache.TTL)
		return resp
	}

	// 只有在存在CNAME记录时才进行递归处理
	return ch.processDNSResponseWithCNAME(resp, domain, ch.getConfig().Upstream)
}

// ProcessDNSResponseWithCNAMEAggressive 更积极地解析CNAME记录以收集更多IP
// 与常规CNAME解析不同，此函数会解析所有CNAME记录以收集尽可能多的IP
func (ch *CloudHandler) processDNSResponseWithCNAMEAggressive(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	ch.logger.Debug("🔍 开始CNAME积极解析", map[string]interface{}{
		"domain":          domain,
		"initial_answers": len(resp.Answer),
	})

	// 存储所有收集到的IP
	var allIPRecords []dns.RR

	// 使用map来快速去重
	seenIPs := make(map[string]bool)

	// 首先处理原始响应中的IP记录
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			ipStr := record.A.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制A记录，但使用原始查询域名
				newA := &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain), // 使用原始域名
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					A: record.A,
				}
				allIPRecords = append(allIPRecords, newA)
				ch.logger.Debug("📡 收集到原始A记录IP", map[string]interface{}{
					"domain":      domain,
					"ip":          ipStr,
					"total_count": len(allIPRecords),
				})
			}
		case *dns.AAAA:
			ipStr := record.AAAA.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制AAAA记录，但使用原始查询域名
				newAAAA := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain), // 使用原始域名
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					AAAA: record.AAAA,
				}
				allIPRecords = append(allIPRecords, newAAAA)
				ch.logger.Debug("📡 收集到原始AAAA记录IP", map[string]interface{}{
					"domain":      domain,
					"ip":          ipStr,
					"total_count": len(allIPRecords),
				})
			}
		}
	}

	// 检查是否已达到最大IP数量限制
	maxIPRecords := ch.getConfig().MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	ch.logger.Debug("📊 初始IP收集完成", map[string]interface{}{
		"domain":           domain,
		"initial_ip_count": len(allIPRecords),
		"max_limit":        maxIPRecords,
		"need_more":        len(allIPRecords) < maxIPRecords,
		"missing_count":    maxIPRecords - len(allIPRecords),
	})

	// 如果已达到最大IP数量限制，直接返回
	if len(allIPRecords) >= maxIPRecords {
		ch.logger.Debug("✅ 初始IP已满足需求，无需解析CNAME", map[string]interface{}{
			"collected": len(allIPRecords),
			"limit":     maxIPRecords,
		})
		// 创建并返回响应
		processedResp := &dns.Msg{
			MsgHdr: resp.MsgHdr,
			Question: []dns.Question{
				{
					Name:   dns.Fqdn(domain),
					Qtype:  resp.Question[0].Qtype,
					Qclass: resp.Question[0].Qclass,
				},
			},
			Answer: []dns.RR{},
			Ns:     append([]dns.RR{}, resp.Ns...),
			Extra:  append([]dns.RR{}, resp.Extra...),
		}
		processedResp.Id = resp.Id

		// 添加所有收集到的IP记录
		for _, record := range allIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

		return processedResp
	}

	// 如果还有需要收集的IP，才继续解析CNAME链
	remainingIPs := maxIPRecords - len(allIPRecords)
	if remainingIPs <= 0 {
		// 创建并返回响应
		processedResp := &dns.Msg{
			MsgHdr: resp.MsgHdr,
			Question: []dns.Question{
				{
					Name:   dns.Fqdn(domain),
					Qtype:  resp.Question[0].Qtype,
					Qclass: resp.Question[0].Qclass,
				},
			},
			Answer: []dns.RR{},
			Ns:     append([]dns.RR{}, resp.Ns...),
			Extra:  append([]dns.RR{}, resp.Extra...),
		}
		processedResp.Id = resp.Id

		// 添加所有收集到的IP记录
		for _, record := range allIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

		return processedResp
	}

	// 只有在需要更多IP时才解析CNAME
	// 收集原始响应中的CNAME记录
	var initialCNAMEs []*dns.CNAME
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			initialCNAMEs = append(initialCNAMEs, cname)
		}
	}

	// 使用DFS（深度优先搜索）来遍历CNAME图
	type DomainInfo struct {
		name      string
		upstreams []string
	}

	// 使用栈来实现迭代式DFS，避免递归导致的栈溢出
	stack := []DomainInfo{}
	processed := make(map[string]bool)      // 记录已处理的域名，避免重复处理
	alreadyInStack := make(map[string]bool) // 记录已在栈中的域名，避免重复添加

	// 先将原始CNAME目标添加到处理队列
	for _, cname := range initialCNAMEs {
		target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
		origin := strings.ToLower(strings.TrimSuffix(cname.Hdr.Name, "."))

		// 避免自引用CNAME
		if target != origin && !processed[target] && !alreadyInStack[target] {
			stack = append(stack, DomainInfo{name: target, upstreams: upstreams})
			alreadyInStack[target] = true
			processed[target] = true // 立即标记为已处理，避免其他路径重复添加
		}
	}

	for len(stack) > 0 && len(allIPRecords) < maxIPRecords {
		// 取出栈顶元素
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		delete(alreadyInStack, current.name) // 从待处理集合中移除

		ch.logger.Debug("🔄 处理CNAME链", map[string]interface{}{
			"domain":           current.name,
			"from_stack":       len(stack),
			"current_ip_count": len(allIPRecords),
			"max_limit":        maxIPRecords,
		})

		// 检查缓存中是否已有该域名的响应
		cachedResp, hit, _, _ := ch.cacheManager.Get(current.name, resp.Question[0].Qtype)
		var queryResp *dns.Msg
		var err error

		if hit && cachedResp != nil {
			ch.logger.Debug("🎯 使用缓存响应", map[string]interface{}{
				"domain":        current.name,
				"answers_count": len(cachedResp.Answer),
			})
			queryResp = cachedResp
		} else {
			// 如果缓存中没有，再发起查询
			queryReq := &dns.Msg{}
			queryReq.SetQuestion(dns.Fqdn(current.name), resp.Question[0].Qtype)

			queryResp, err = ch.proxyQuery(queryReq, current.upstreams)
			if err != nil || queryResp == nil || queryResp.Rcode != dns.RcodeSuccess {
				ch.logger.Debug("❌ 域名查询失败", map[string]interface{}{
					"domain": current.name,
					"error":  err,
				})
				continue
			}

			// 将查询结果缓存
			ch.cacheManager.Set(current.name, resp.Question[0].Qtype, queryResp, false)
		}

		ch.logger.Debug("📥 域名查询成功", map[string]interface{}{
			"domain":        current.name,
			"answers_count": len(queryResp.Answer),
		})

		// 遍历响应中的所有记录
		for _, rr := range queryResp.Answer {
			if len(allIPRecords) >= maxIPRecords {
				break // 已达到最大IP数量限制
			}

			switch record := rr.(type) {
			case *dns.A:
				ipStr := record.A.String()
				ch.logger.Debug("📡 收集到A记录IP", map[string]interface{}{
					"domain":       current.name,
					"ip":           ipStr,
					"already_seen": seenIPs[ipStr],
				})

				if !seenIPs[ipStr] {
					seenIPs[ipStr] = true
					// 复制A记录，但使用原始查询域名
					newA := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(domain), // 使用原始域名
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    record.Hdr.Ttl,
						},
						A: record.A,
					}
					allIPRecords = append(allIPRecords, newA)
					ch.logger.Debug("✅ 添加IP到结果", map[string]interface{}{
						"ip":          ipStr,
						"total_count": len(allIPRecords),
					})
				}
			case *dns.AAAA:
				ipStr := record.AAAA.String()
				ch.logger.Debug("📡 收集到AAAA记录IP", map[string]interface{}{
					"domain":       current.name,
					"ip":           ipStr,
					"already_seen": seenIPs[ipStr],
				})

				if !seenIPs[ipStr] {
					seenIPs[ipStr] = true
					// 复制AAAA记录，但使用原始查询域名
					newAAAA := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(domain), // 使用原始域名
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    record.Hdr.Ttl,
						},
						AAAA: record.AAAA,
					}
					allIPRecords = append(allIPRecords, newAAAA)
					ch.logger.Debug("✅ 添加IPV6到结果", map[string]interface{}{
						"ip":          ipStr,
						"total_count": len(allIPRecords),
					})
				}
			case *dns.CNAME:
				ch.logger.Debug("🔗 发现CNAME记录", map[string]interface{}{
					"domain": current.name,
					"target": record.Target,
				})

				// 将CNAME目标加入待处理队列
				target := strings.ToLower(strings.TrimSuffix(record.Target, "."))
				origin := strings.ToLower(strings.TrimSuffix(record.Hdr.Name, "."))

				// 避免自引用CNAME，且只有在还需要IP时才继续解析
				if target != origin && !processed[target] && !alreadyInStack[target] && len(allIPRecords) < maxIPRecords {
					ch.logger.Debug("📋 将CNAME目标加入处理队列", map[string]interface{}{
						"target": target,
						"origin": origin,
					})
					stack = append(stack, DomainInfo{name: target, upstreams: current.upstreams})
					alreadyInStack[target] = true
					processed[target] = true // 立即标记为已处理，避免重复添加
				} else {
					ch.logger.Debug("⚠️ 检测到自引用CNAME或已达IP限制，跳过", map[string]interface{}{
						"domain":    target,
						"need_more": len(allIPRecords) < maxIPRecords,
					})
				}
			}
		}

		ch.logger.Debug("📊 当前收集状态", map[string]interface{}{
			"domain":              current.name,
			"total_ips_collected": len(allIPRecords),
			"max_limit":           maxIPRecords,
		})

		// 检查是否已达到最大IP数量限制
		if len(allIPRecords) >= maxIPRecords {
			ch.logger.Debug("🏁 达到最大IP数量限制，停止处理", map[string]interface{}{
				"limit":     maxIPRecords,
				"collected": len(allIPRecords),
			})
			break
		}
	}

	// 创建最终响应
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	processedResp.Id = resp.Id

	// 添加所有收集到的IP记录
	for _, record := range allIPRecords {
		processedResp.Answer = append(processedResp.Answer, record)
	}

	ch.logger.Debug("✅ CNAME积极解析完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  ch.countType(processedResp.Answer, "A"),
		"ipv6_count":  ch.countType(processedResp.Answer, "AAAA"),
		"all_collected_ips": func() []string {
			var ips []string
			for _, record := range allIPRecords {
				switch r := record.(type) {
				case *dns.A:
					ips = append(ips, r.A.String())
				case *dns.AAAA:
					ips = append(ips, r.AAAA.String())
				}
			}
			return ips
		}(),
	})

	return processedResp
}

// isSameIP 比较两个DNS记录是否包含相同的IP地址
func (ch *CloudHandler) isSameIP(rr1, rr2 dns.RR) bool {
	a1, ok1 := rr1.(*dns.A)
	a2, ok2 := rr2.(*dns.A)
	if ok1 && ok2 {
		return a1.A.Equal(a2.A)
	}

	aaaa1, ok1 := rr1.(*dns.AAAA)
	aaaa2, ok2 := rr2.(*dns.AAAA)
	if ok1 && ok2 {
		return aaaa1.AAAA.Equal(aaaa2.AAAA)
	}

	// 如果类型不同，则不是相同的IP
	return false
}

// processDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录
// 完整实现：收集所有CNAME记录并递归解析，获取IP后按需补充原始IP记录
func (ch *CloudHandler) processDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 分离CNAME记录和IP记录
	var cnames []*dns.CNAME
	var ipRecords []dns.RR

	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, cname)
		} else if _, ok := rr.(*dns.A); ok || ch.isAAAARecord(rr) {
			ipRecords = append(ipRecords, rr)
		}
	}

	// 获取最大IP记录数配置，默认为2
	maxIPRecords := ch.getConfig().MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	// 创建结果存储
	var finalIPRecords []dns.RR

	// 如果有CNAME记录，优先递归解析
	if len(cnames) > 0 {
		ch.logger.Debug("🔍 检测到CNAME记录，开始递归解析", map[string]interface{}{
			"domain":         domain,
			"cname_count":    len(cnames),
			"max_ip_records": maxIPRecords,
		})

		// 递归解析所有CNAME记录
		for _, cname := range cnames {
			if len(finalIPRecords) >= maxIPRecords {
				break // 已达到最大数量
			}

			ch.logger.Debug("🔄 解析CNAME记录", map[string]interface{}{
				"domain": domain,
				"target": cname.Target,
			})

			// 递归解析CNAME目标，使用传入的上游DNS服务器
			cnameTargetReq := &dns.Msg{}
			cnameTargetReq.SetQuestion(cname.Target, resp.Question[0].Qtype)

			cnameTargetResp, err := ch.proxyQuery(cnameTargetReq, upstreams)
			if err == nil && cnameTargetResp != nil {
				// 递归处理CNAME目标的响应
				// 注意：这里不应该再次应用IP数量限制，而是获取所有可能的IP，
				// 然后由外层逻辑统一控制最终数量
				processedCnameResp := ch.processDNSResponseWithCNAME(cnameTargetResp, cname.Target, upstreams)
				if processedCnameResp != nil {
					// 收集解析出的IP记录，不超过剩余配额
					for _, targetRR := range processedCnameResp.Answer {
						if len(finalIPRecords) >= maxIPRecords {
							break
						}
						if _, ok := targetRR.(*dns.A); ok || ch.isAAAARecord(targetRR) {
							// 检查是否已存在相同的IP记录，避免重复
							isDuplicate := false
							for _, existing := range finalIPRecords {
								if existing.String() == targetRR.String() {
									isDuplicate = true
									break
								}
							}
							if !isDuplicate {
								finalIPRecords = append(finalIPRecords, targetRR)
							}
						}
					}
				}
			} else {
				ch.logger.Debug("❌ CNAME解析失败", map[string]interface{}{
					"domain": domain,
					"target": cname.Target,
					"error":  err,
				})
			}
		}
	}

	// 按IPv4和IPv6分别计数
	var ipv4Records []dns.RR
	var ipv6Records []dns.RR

	for _, record := range finalIPRecords {
		if _, ok := record.(*dns.A); ok {
			ipv4Records = append(ipv4Records, record)
		} else if ch.isAAAARecord(record) {
			ipv6Records = append(ipv6Records, record)
		}
	}

	// IPv4和IPv6各自独立限制为配置的最大值
	maxIPv4 := maxIPRecords
	maxIPv6 := maxIPRecords

	// 截取IPv4和IPv6记录
	var resultRecords []dns.RR

	// 添加IPv4记录（最多maxIPv4个）
	for i, record := range ipv4Records {
		if i >= maxIPv4 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 添加IPv6记录（最多maxIPv6个）
	for i, record := range ipv6Records {
		if i >= maxIPv6 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 如果数量不足，尝试补充原始IP记录
	remainingSlots := maxIPRecords - len(resultRecords)
	if remainingSlots > 0 {
		// 按IPv4和IPv6分别补充
		var additionalIPv4 []dns.RR
		var additionalIPv6 []dns.RR

		for _, record := range ipRecords {
			if _, ok := record.(*dns.A); ok {
				// 检查是否已达到IPv4最大数量
				currentIPv4Count := 0
				for _, res := range resultRecords {
					if _, ok := res.(*dns.A); ok {
						currentIPv4Count++
					}
				}
				if currentIPv4Count < maxIPv4 {
					additionalIPv4 = append(additionalIPv4, record)
				}
			} else if ch.isAAAARecord(record) {
				// 检查是否已达到IPv6最大数量
				currentIPv6Count := 0
				for _, res := range resultRecords {
					if ch.isAAAARecord(res) {
						currentIPv6Count++
					}
				}
				if currentIPv6Count < maxIPv6 {
					additionalIPv6 = append(additionalIPv6, record)
				}
			}
		}

		// 补充IPv4记录
		for _, record := range additionalIPv4 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}

		// 补充IPv6记录
		for _, record := range additionalIPv6 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}
	}

	// 创建并填充最终响应
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	processedResp.Id = resp.Id

	// 添加IP记录到响应
	for _, record := range resultRecords {
		newRecord := dns.Copy(record)
		newRecord.Header().Name = dns.Fqdn(domain)
		processedResp.Answer = append(processedResp.Answer, newRecord)
	}

	ch.logger.Debug("✅ CNAME处理完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  ch.countType(processedResp.Answer, "A"),
		"ipv6_count":  ch.countType(processedResp.Answer, "AAAA"),
	})

	return processedResp
}

// processDNSResponseWithCNAMERFC 符合RFC 1034/1035标准的CNAME解析
// 只解析指定深度的CNAME链，并返回完整的CNAME链和最终IP记录
func (ch *CloudHandler) processDNSResponseWithCNAMERFC(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	ch.logger.Debug("🔍 开始RFC兼容CNAME解析", map[string]interface{}{
		"domain":          domain,
		"initial_answers": len(resp.Answer),
		"recursion_depth": ch.getConfig().CNAMERecursionDepth,
	})

	// 创建结果响应
	resultResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	resultResp.Id = resp.Id

	// 使用辅助函数进行递归解析，保留完整的CNAME链
	visited := make(map[string]bool) // 防止循环引用
	resultResp = ch.processCNAMEChainWithFullPath(resp, domain, upstreams, visited, 0, ch.getConfig().CNAMERecursionDepth)

	// 限制IP记录数量，但保持CNAME记录在前的正确顺序
	maxIPRecords := ch.getConfig().MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	// 按照DNS协议推荐顺序重新组织记录：CNAME在前，IP在后
	var orderedRecords []dns.RR

	// 首先添加所有CNAME记录
	for _, record := range resultResp.Answer {
		if _, ok := record.(*dns.CNAME); ok {
			orderedRecords = append(orderedRecords, record)
		}
	}

	// 然后添加IP记录（A和AAAA），但限制数量
	var ipRecords []dns.RR
	for _, record := range resultResp.Answer {
		switch record.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, record)
		}
	}

	// 限制IP记录数量并去重
	var finalIPRecords []dns.RR
	uniqueIPs := make(map[string]bool)
	var ipv4Count, ipv6Count int

	for _, record := range ipRecords {
		var ipStr string
		switch r := record.(type) {
		case *dns.A:
			ipStr = r.A.String()
		case *dns.AAAA:
			ipStr = r.AAAA.String()
		}
		if ipStr != "" && !uniqueIPs[ipStr] {
			uniqueIPs[ipStr] = true
			switch record.(type) {
			case *dns.A:
				if ipv4Count < maxIPRecords {
					finalIPRecords = append(finalIPRecords, record)
					ipv4Count++
				}
			case *dns.AAAA:
				if ipv6Count < maxIPRecords {
					finalIPRecords = append(finalIPRecords, record)
					ipv6Count++
				}
			}
			// 总数也不能超过maxIPRecords
			if len(finalIPRecords) >= maxIPRecords {
				break
			}
		}
	}

	// 合并记录：CNAME在前，IP在后
	orderedRecords = append(orderedRecords, finalIPRecords...)

	// 更新结果响应
	resultResp.Answer = orderedRecords

	ch.logger.Debug("✅ RFC兼容CNAME解析完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(resultResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  ch.countType(resultResp.Answer, "A"),
		"ipv6_count":  ch.countType(resultResp.Answer, "AAAA"),
		"cname_count": ch.countType(resultResp.Answer, "CNAME"),
	})

	return resultResp
}

// processCNAMEChainWithFullPath 递归处理CNAME链，保留完整的解析路径
func (ch *CloudHandler) processCNAMEChainWithFullPath(resp *dns.Msg, originalDomain string, upstreams []string, visited map[string]bool, currentDepth, maxDepth int) *dns.Msg {
	if resp == nil || currentDepth > maxDepth {
		return resp
	}

	// 创建结果响应
	resultResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(originalDomain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	resultResp.Id = resp.Id

	// 首先处理当前响应中的所有记录
	// 根据RFC标准，我们只处理第一条CNAME记录
	var firstCNAME *dns.CNAME
	var otherRecords []dns.RR

	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.CNAME:
			// 防止自引用
			target := strings.ToLower(strings.TrimSuffix(record.Target, "."))
			source := strings.ToLower(strings.TrimSuffix(record.Hdr.Name, "."))

			if target == source {
				ch.logger.Debug("⚠️ 跳过自引用CNAME", map[string]interface{}{
					"domain": target,
				})
				continue
			}

			// 检查是否已访问过此目标（防止循环）
			if visited[target] {
				ch.logger.Debug("⚠️ 检测到CNAME循环引用，但仍保留CNAME记录", map[string]interface{}{
					"target": target,
					"source": source,
				})
				// 即使是循环，也添加CNAME记录到结果中，但不继续解析
				newCNAME := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(originalDomain), // 使用原始查询域名
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					Target: record.Target,
				}
				resultResp.Answer = append(resultResp.Answer, newCNAME)
				continue
			}

			// 只保留第一条CNAME记录，根据RFC标准
			if firstCNAME == nil {
				firstCNAME = record
				// 添加CNAME记录到结果（使用原始查询域名作为名称）
				newCNAME := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(originalDomain), // 使用原始查询域名
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					Target: record.Target,
				}
				resultResp.Answer = append(resultResp.Answer, newCNAME)

				// 如果还有深度可以解析，继续处理CNAME目标
				if currentDepth+1 <= maxDepth {
					// 标记为已访问，防止循环
					visited[target] = true
					visited[source] = true

					queryReq := &dns.Msg{}
					queryReq.SetQuestion(dns.Fqdn(target), resp.Question[0].Qtype)

					// 尝试从缓存获取中间域名的响应
					cachedResp, hit, _, _ := ch.cacheManager.Get(target, resp.Question[0].Qtype)
					var queryResp *dns.Msg
					var err error

					if hit && cachedResp != nil {
						ch.logger.Debug("🎯 使用缓存的CNAME目标响应", map[string]interface{}{
							"target": target,
							"qtype":  dns.TypeToString[resp.Question[0].Qtype],
						})
						queryResp = cachedResp
					} else {
						// 如果缓存中没有，执行查询
						queryResp, err = ch.proxyQuery(queryReq, upstreams)
						if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
							// 将查询结果缓存
							ch.cacheManager.Set(target, resp.Question[0].Qtype, queryResp, false)
							ch.logger.Debug("💾 缓存CNAME目标查询结果", map[string]interface{}{
								"target":       target,
								"qtype":        dns.TypeToString[resp.Question[0].Qtype],
								"answer_count": len(queryResp.Answer),
							})
						}
					}

					if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
						// 递归处理CNAME目标的响应
						subResult := ch.processCNAMEChainWithFullPath(queryResp, originalDomain, upstreams, visited, currentDepth+1, maxDepth)

						// 将子结果中的所有记录（除了已添加的当前CNAME）添加到当前结果
						// 但我们只需要添加IP记录，避免重复添加CNAME
						for _, subRR := range subResult.Answer {
							switch subRR.(type) {
							case *dns.A, *dns.AAAA:
								// 只添加IP记录
								resultResp.Answer = append(resultResp.Answer, subRR)
							}
						}
					} else {
						ch.logger.Debug("❌ CNAME目标查询失败", map[string]interface{}{
							"target": target,
							"error":  err,
						})
					}

					// 移除标记，允许其他分支访问相同的域名
					delete(visited, target)
				}
			} else {
				// 如果不是第一条CNAME，将其作为其他记录处理
				otherRecords = append(otherRecords, record)
			}
		case *dns.A, *dns.AAAA:
			// 直接添加IP记录，使用原始域名
			newRecord := dns.Copy(record)
			newRecord.Header().Name = dns.Fqdn(originalDomain) // 使用原始域名
			otherRecords = append(otherRecords, newRecord)
		default:
			// 添加其他类型的记录，使用原始域名
			newRecord := dns.Copy(record)
			newRecord.Header().Name = dns.Fqdn(originalDomain) // 使用原始域名
			otherRecords = append(otherRecords, newRecord)
		}
	}

	// 添加非CNAME记录
	for _, record := range otherRecords {
		resultResp.Answer = append(resultResp.Answer, record)
	}

	return resultResp
}

// isAAAARecord 检查记录是否为AAAA记录
func (ch *CloudHandler) isAAAARecord(rr dns.RR) bool {
	_, ok := rr.(*dns.AAAA)
	return ok
}

// countType 计算指定类型的记录数量
func (ch *CloudHandler) countType(records []dns.RR, recordType string) int {
	count := 0
	for _, record := range records {
		switch recordType {
		case "A":
			if _, ok := record.(*dns.A); ok {
				count++
			}
		case "AAAA":
			if _, ok := record.(*dns.AAAA); ok {
				count++
			}
		}
	}
	return count
}

// extractFinalIPs 递归提取CNAME链的最终IP记录
func (ch *CloudHandler) extractFinalIPs(resp *dns.Msg, originalDomain string, upstreams []string, visited map[string]bool, currentDepth, maxDepth int) []dns.RR {
	if resp == nil || currentDepth > maxDepth {
		return []dns.RR{}
	}

	var finalIPs []dns.RR

	// 查找当前响应中的CNAME记录
	var cnameRecord *dns.CNAME
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			// 防止自引用
			target := strings.ToLower(strings.TrimSuffix(c.Target, "."))
			source := strings.ToLower(strings.TrimSuffix(c.Hdr.Name, "."))

			if target == source {
				ch.logger.Debug("⚠️ 跳过自引用CNAME", map[string]interface{}{
					"domain": target,
				})
				continue
			}

			// 检查是否已访问过此目标（防止循环）
			if visited[target] {
				ch.logger.Debug("⚠️ 检测到CNAME循环引用", map[string]interface{}{
					"target": target,
					"source": source,
				})
				continue
			}

			cnameRecord = c
			break // 只处理第一条CNAME记录，符合RFC标准
		}
	}

	if cnameRecord != nil && currentDepth < maxDepth {
		// 有CNAME记录且还有递归深度，继续递归查询
		target := strings.ToLower(strings.TrimSuffix(cnameRecord.Target, "."))

		// 标记为已访问，防止循环
		visited[target] = true
		source := strings.ToLower(strings.TrimSuffix(cnameRecord.Hdr.Name, "."))
		visited[source] = true

		queryReq := &dns.Msg{}
		queryReq.SetQuestion(dns.Fqdn(target), resp.Question[0].Qtype)

		// 尝试从缓存获取中间域名的响应
		cachedResp, hit, _, _ := ch.cacheManager.Get(target, resp.Question[0].Qtype)
		var queryResp *dns.Msg
		var err error

		if hit && cachedResp != nil {
			ch.logger.Debug("🎯 使用缓存的CNAME目标响应", map[string]interface{}{
				"target": target,
				"qtype":  dns.TypeToString[resp.Question[0].Qtype],
			})
			queryResp = cachedResp
		} else {
			// 如果缓存中没有，执行查询
			queryResp, err = ch.proxyQuery(queryReq, upstreams)
			if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
				// 将查询结果缓存
				ch.cacheManager.Set(target, resp.Question[0].Qtype, queryResp, false)
				ch.logger.Debug("💾 缓存CNAME目标查询结果", map[string]interface{}{
					"target":       target,
					"qtype":        dns.TypeToString[resp.Question[0].Qtype],
					"answer_count": len(queryResp.Answer),
				})
			}
		}

		if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
			// 递归处理CNAME目标的响应
			subIPs := ch.extractFinalIPs(queryResp, originalDomain, upstreams, visited, currentDepth+1, maxDepth)
			finalIPs = append(finalIPs, subIPs...)
		} else {
			ch.logger.Debug("❌ CNAME目标查询失败", map[string]interface{}{
				"target": target,
				"error":  err,
			})
		}

		// 移除标记，允许其他分支访问相同的域名
		delete(visited, target)
	} else {
		// 没有CNAME记录或达到最大递归深度，提取IP记录
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.A, *dns.AAAA:
				finalIPs = append(finalIPs, rr)
			}
		}
	}

	return finalIPs
}

// processReplaceDomainResponse 专门处理替换域名响应，不进行云服务检测
func (ch *CloudHandler) processReplaceDomainResponse(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	ch.logger.Debug("🔍 开始处理替换域名响应", map[string]interface{}{
		"domain":          domain,
		"initial_answers": len(resp.Answer),
	})

	// 检查查询类型，如果是A或AAAA查询，我们只返回最终的IP记录
	qtype := resp.Question[0].Qtype
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		// 对于A/AAAA查询，只返回最终的IP记录，不返回CNAME记录
		finalResp := &dns.Msg{
			MsgHdr: resp.MsgHdr,
			Question: []dns.Question{
				{
					Name:   dns.Fqdn(domain),
					Qtype:  qtype,
					Qclass: resp.Question[0].Qclass,
				},
			},
			Answer: []dns.RR{},
			Ns:     append([]dns.RR{}, resp.Ns...),
			Extra:  append([]dns.RR{}, resp.Extra...),
		}
		finalResp.Id = resp.Id

		// 使用辅助函数进行递归解析，获取最终的IP记录
		visited := make(map[string]bool) // 防止循环引用
		ipRecords := ch.extractFinalIPs(resp, domain, upstreams, visited, 0, ch.getConfig().CNAMERecursionDepth)

		// 限制IP记录数量
		maxIPRecords := ch.getConfig().MaxIPRecords
		if maxIPRecords <= 0 {
			maxIPRecords = 2 // 默认值
		}

		// 对IP进行去重
		uniqueIPs := make(map[string]bool)
		var filteredIPRecords []dns.RR
		for _, record := range ipRecords {
			var ipStr string
			switch r := record.(type) {
			case *dns.A:
				ipStr = r.A.String()
			case *dns.AAAA:
				ipStr = r.AAAA.String()
			}
			if ipStr != "" && !uniqueIPs[ipStr] {
				uniqueIPs[ipStr] = true
				filteredIPRecords = append(filteredIPRecords, record)
				if len(filteredIPRecords) >= maxIPRecords {
					break
				}
			}
		}

		// 添加去重后的IP记录
		for _, record := range filteredIPRecords {
			// 更新记录的域名名称为原始查询域名
			switch r := record.(type) {
			case *dns.A:
				newRecord := &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    r.Hdr.Ttl,
					},
					A: r.A,
				}
				finalResp.Answer = append(finalResp.Answer, newRecord)
			case *dns.AAAA:
				newRecord := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    r.Hdr.Ttl,
					},
					AAAA: r.AAAA,
				}
				finalResp.Answer = append(finalResp.Answer, newRecord)
			}
		}

		ch.logger.Debug("✅ 替换域名响应处理完成", map[string]interface{}{
			"domain":      domain,
			"final_count": len(finalResp.Answer),
			"max_allowed": maxIPRecords,
			"ipv4_count":  ch.countType(finalResp.Answer, "A"),
			"ipv6_count":  ch.countType(finalResp.Answer, "AAAA"),
			"cname_count": ch.countType(finalResp.Answer, "CNAME"),
		})

		return finalResp
	} else {
		// 对于非A/AAAA查询，返回原始响应（不做云服务检测）
		return resp
	}
}

// ensureMinimumTTL 确保响应中的 TTL 不小于指定的最小值
func (ch *CloudHandler) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
	if resp == nil {
		return
	}

	minTTLSeconds := uint32(minTTL.Seconds())

	// 更新 Answer 部分的 TTL
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Authority 部分的 TTL
	for _, rr := range resp.Ns {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Additional 部分的 TTL
	for _, rr := range resp.Extra {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}
}

// sendErrorResponse 发送错误响应（走统一响应出口，保证EDNS/TC处理一致）
func (ch *CloudHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	ch.respond(w, req, resp)
	return nil
}
