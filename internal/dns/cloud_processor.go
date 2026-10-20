package dns

import (
	"net/netip"
	"sync"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// CloudProcessor 处理云服务IP替换逻辑
type CloudProcessor struct {
	cfgMu      sync.RWMutex
	config     *config.Config
	Logger     *utils.EnhancedLogger
	proxyQuery func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
}

// getConfig 获取当前配置（web保存后热切换）
func (cp *CloudProcessor) getConfig() *config.Config {
	cp.cfgMu.RLock()
	defer cp.cfgMu.RUnlock()
	return cp.config
}

// UpdateConfig 热更新配置引用
func (cp *CloudProcessor) UpdateConfig(cfg *config.Config) {
	cp.cfgMu.Lock()
	cp.config = cfg
	cp.cfgMu.Unlock()
}

// NewCloudProcessor 创建新的云服务处理器
func NewCloudProcessor(config *config.Config, logger *utils.EnhancedLogger, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *CloudProcessor {
	return &CloudProcessor{
		config:     config,
		Logger:     logger,
		proxyQuery: proxyQuery,
	}
}

// ReplaceCloudIPs 用替换域名的IP替换原始响应中的云服务IP
func (cp *CloudProcessor) ReplaceCloudIPs(originalResp *dns.Msg, originalDetection *CloudDetectionResult) *dns.Msg {
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
	if replaceRespA, err := cp.proxyQuery(replaceReqA, cp.getConfig().Upstream); err == nil && replaceRespA != nil && replaceRespA.Rcode == dns.RcodeSuccess {
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
	if replaceRespAAAA, err := cp.proxyQuery(replaceReqAAAA, cp.getConfig().Upstream); err == nil && replaceRespAAAA != nil && replaceRespAAAA.Rcode == dns.RcodeSuccess {
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
		cp.Logger.Warn("⚠️ 替换域名无有效IP记录", map[string]interface{}{
			"replace_domain": replaceDomain,
		})
		return originalResp
	}

	// 创建新的响应并替换IP
	newResp := &dns.Msg{}
	*newResp = *originalResp // 复制原始响应结构
	newResp.Answer = nil     // 清空答案部分

	// 复制非IP的记录
	for _, rr := range originalResp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 跳过云服务IP记录，稍后用替换IP替换
		default:
			// 保留非IP记录
			newResp.Answer = append(newResp.Answer, dns.Copy(rr))
		}
	}

	// 添加替换IP，保持原始查询类型
	for _, ip := range replaceIPs {
		// 根据IP类型创建相应的记录
		if ip.Is4() && originalResp.Question[0].Qtype == dns.TypeA {
			for _, originalRR := range originalResp.Answer {
				if _, ok := originalRR.(*dns.A); ok {
					newA := &dns.A{
						Hdr: dns.RR_Header{
							Name:   originalRR.Header().Name,
							Rrtype: dns.TypeA,
							Class:  originalRR.Header().Class,
							Ttl:    originalRR.Header().Ttl,
						},
						A: ip.AsSlice(),
					}
					newResp.Answer = append(newResp.Answer, newA)
					// 移除break，允许添加多个相同类型的IP
				}
			}
		} else if ip.Is6() && originalResp.Question[0].Qtype == dns.TypeAAAA {
			for _, originalRR := range originalResp.Answer {
				if _, ok := originalRR.(*dns.AAAA); ok {
					newAAAA := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   originalRR.Header().Name,
							Rrtype: dns.TypeAAAA,
							Class:  originalRR.Header().Class,
							Ttl:    originalRR.Header().Ttl,
						},
						AAAA: ip.AsSlice(),
					}
					newResp.Answer = append(newResp.Answer, newAAAA)
					// 移除break，允许添加多个相同类型的IP
				}
			}
		}
	}

	return newResp
}

// ProcessCloudResponse 处理云域名响应，确保符合DNS协议标准
func (cp *CloudProcessor) ProcessCloudResponse(resp *dns.Msg, domain string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 使用通用的CNAME处理方法，传入上游DNS服务器为默认上游
	// 使用不带缓存功能的CNAME处理器，因为CloudProcessor不需要缓存中间结果
	cnameProcessor := NewCNAMEProcessorWithoutCache(cp.config, cp.Logger, cp.proxyQuery)
	return cnameProcessor.ProcessDNSResponseWithCNAME(resp, domain, cp.getConfig().Upstream)
}

// ensureMinimumTTL 确保响应中的TTL不低于最小值
func (cp *CloudProcessor) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
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
