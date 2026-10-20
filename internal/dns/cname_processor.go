package dns

import (
	"strings"
	"sync"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// CNAMEProcessor 处理CNAME相关逻辑
//
// 重要设计原则（RFC 1034 §3.6.2 / RFC 2181 §5.2）：
// 上游递归服务器已经追完CNAME链并返回完整链，本代理不再对返回给客户端的
// answer做任何owner重写或RRset裁剪——客户端可见的响应与上游原样一致。
// CNAME链递归仅作为内部云检测的IP收集手段（CollectChainIPs），其结果
// 不会返回给客户端。
type CNAMEProcessor struct {
	cfgMu        sync.RWMutex
	config       *config.Config
	Logger       *utils.EnhancedLogger
	proxyQuery   func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
	cacheManager *CacheManager                              // 添加缓存管理器
}

// getConfig 获取当前配置（web保存后热切换）
func (cp *CNAMEProcessor) getConfig() *config.Config {
	cp.cfgMu.RLock()
	defer cp.cfgMu.RUnlock()
	return cp.config
}

// UpdateConfig 热更新配置引用
func (cp *CNAMEProcessor) UpdateConfig(cfg *config.Config) {
	cp.cfgMu.Lock()
	cp.config = cfg
	cp.cfgMu.Unlock()
}

// NewCNAMEProcessor 创建新的CNAME处理器
func NewCNAMEProcessor(config *config.Config, logger *utils.EnhancedLogger, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error), cacheManager *CacheManager) *CNAMEProcessor {
	return &CNAMEProcessor{
		config:       config,
		Logger:       logger,
		proxyQuery:   proxyQuery,
		cacheManager: cacheManager,
	}
}

// NewCNAMEProcessorWithoutCache 创建不带缓存功能的CNAME处理器（用于某些特殊场景）
func NewCNAMEProcessorWithoutCache(config *config.Config, logger *utils.EnhancedLogger, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *CNAMEProcessor {
	return &CNAMEProcessor{
		config:       config,
		Logger:       logger,
		proxyQuery:   proxyQuery,
		cacheManager: nil, // 不设置缓存管理器
	}
}

// ProcessDNSResponseWithCNAME 处理DNS响应
// 上游（递归服务器）已返回完整CNAME链，直接透传，不做owner重写或RRset裁剪
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	return resp
}

// ProcessDNSResponseWithCNAMERFC 兼容旧接口，行为与ProcessDNSResponseWithCNAME一致：透传
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAMERFC(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	return resp
}

// ProcessDNSResponseWithCNAMEAggressive 兼容旧接口，行为与ProcessDNSResponseWithCNAME一致：透传
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAMEAggressive(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	return resp
}

// ProcessNonIPResponseWithCNAME 处理非IP记录类型的DNS响应
// 与A/AAAA查询同理：上游已追完CNAME链，直接透传
func (cp *CNAMEProcessor) ProcessNonIPResponseWithCNAME(resp *dns.Msg, domain string, qtype uint16, upstreams []string) *dns.Msg {
	return resp
}

// CollectChainIPs 沿CNAME链收集IP记录，仅用于云检测，不改写客户端响应
// 优先读取缓存中的链上目标响应，未命中则停止（不在查询热路径上产生额外网络IO）
func (cp *CNAMEProcessor) CollectChainIPs(resp *dns.Msg, domain string, qtype uint16) []dns.RR {
	if resp == nil || cp.cacheManager == nil {
		return nil
	}

	seen := make(map[string]bool)
	var ips []dns.RR

	collect := func(msg *dns.Msg) {
		for _, rr := range msg.Answer {
			switch r := rr.(type) {
			case *dns.A:
				if s := r.A.String(); s != "" && !seen[s] {
					seen[s] = true
					ips = append(ips, rr)
				}
			case *dns.AAAA:
				if s := r.AAAA.String(); s != "" && !seen[s] {
					seen[s] = true
					ips = append(ips, rr)
				}
			}
		}
	}

	collect(resp)

	// 沿CNAME链在缓存中查找更多IP（最多CNAMERecursionDepth跳）
	maxDepth := cp.getConfig().CNAMERecursionDepth
	visited := map[string]bool{strings.ToLower(strings.TrimSuffix(domain, ".")): true}
	current := resp
	for depth := 0; depth < maxDepth && current != nil; depth++ {
		var next *dns.Msg
		for _, rr := range current.Answer {
			cname, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
			if visited[target] {
				continue
			}
			visited[target] = true

			cached, hit, _, _ := cp.cacheManager.Get(target, qtype)
			if !hit || cached == nil {
				continue
			}
			collect(cached)
			if next == nil {
				next = cached
			}
		}
		current = next
	}

	return ips
}

// countType 计算指定类型的记录数量
func (cp *CNAMEProcessor) countType(records []dns.RR, recordType string) int {
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
		case "CNAME":
			if _, ok := record.(*dns.CNAME); ok {
				count++
			}
		}
	}
	return count
}
