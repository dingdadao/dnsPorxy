package dns

import (
	"os"
	"sync"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// MatcherHandler 处理域名匹配相关功能
type MatcherHandler struct {
	// mu 保护 config 与 matchers：配置热更新（含顺序变更重建）与请求路径并发访问
	mu            sync.RWMutex
	config        *config.Config
	logger        *utils.EnhancedLogger
	matchers      []*YAMLMatcher // 与 config.SplitLists 一一对应
	cloudDetector *CloudDetector
	proxyQuery    func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
}

// NewMatcherHandler 创建新的匹配处理器
func NewMatcherHandler(config *config.Config, logger *utils.EnhancedLogger, handler *RefactoredHandler) *MatcherHandler {
	mh := &MatcherHandler{
		config:     config,
		logger:     logger,
		proxyQuery: handler.proxyQuery, // 从handler获取proxyQuery函数
	}

	// 为每个分流列表初始化一个匹配器
	mh.matchers = mh.buildMatchers(config)

	// 从handler获取cloudDetector实例
	if handler != nil && handler.cloudDetector != nil {
		mh.cloudDetector = handler.cloudDetector
	}

	return mh
}

// buildMatchers 按给定配置重建分流列表匹配器（DNS 来自列表配置，规则待文件加载）
func (mh *MatcherHandler) buildMatchers(cfg *config.Config) []*YAMLMatcher {
	matchers := make([]*YAMLMatcher, len(cfg.SplitLists))
	for i, l := range cfg.SplitLists {
		ym := NewYAMLMatcher(mh.logger)
		ym.SetDefaultDNS(l.DNS)
		matchers[i] = ym
	}
	return matchers
}

// rebuildMatchersWithRules 重建匹配器并从本地文件重载规则
// 顺序变更后必须重建，否则会出现「A 列表的规则配 B 列表的 DNS」错配
func (mh *MatcherHandler) rebuildMatchersWithRules(cfg *config.Config) []*YAMLMatcher {
	matchers := mh.buildMatchers(cfg)
	for i, l := range cfg.SplitLists {
		if !l.Enabled || l.DomainFile == "" {
			continue
		}
		if _, err := os.Stat(l.DomainFile); err != nil {
			mh.logger.Warn("⚠️ [顺序变更后重载分流列表跳过：文件不存在] ", map[string]interface{}{
				"rule": "SPLIT_LIST_RELOAD_MISSING",
				"list": l.Name,
				"file": l.DomainFile,
			})
			continue
		}
		if err := matchers[i].LoadYAMLConfig(l.DomainFile); err != nil {
			mh.logger.Error("❌ [顺序变更后重载分流列表失败] ", map[string]interface{}{
				"rule":  "SPLIT_LIST_RELOAD_FAILED",
				"list":  l.Name,
				"file":  l.DomainFile,
				"error": err.Error(),
			})
		}
	}
	return matchers
}

// sameSplitListOrder 判断分流列表的顺序与身份（名称/本地文件/远程URL）是否一致
func sameSplitListOrder(old, cur []config.SplitList) bool {
	if len(old) != len(cur) {
		return false
	}
	for i := range old {
		if old[i].Name != cur[i].Name || old[i].DomainFile != cur[i].DomainFile ||
			old[i].DomainURL != cur[i].DomainURL {
			return false
		}
	}
	return true
}

// UpdateConfig 应用最新配置：DNS 变更原地热更新；顺序/身份变更时重建匹配器并重载规则
// （列表增删/文件路径/刷新间隔/enabled 变更仍需重启，见 ApplyConfig 的 restart 判定）
func (mh *MatcherHandler) UpdateConfig(cfg *config.Config) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	if !sameSplitListOrder(mh.config.SplitLists, cfg.SplitLists) {
		mh.config = cfg
		mh.matchers = mh.rebuildMatchersWithRules(cfg)
		mh.logger.Info("🔀 [分流列表顺序变更，已重建匹配器] ", map[string]interface{}{
			"rule":  "SPLIT_LIST_REORDERED",
			"lists": len(cfg.SplitLists),
		})
		return
	}

	mh.config = cfg
	for i, l := range cfg.SplitLists {
		if i < len(mh.matchers) && mh.matchers[i] != nil {
			mh.matchers[i].SetDefaultDNS(l.DNS)
		}
	}
}

// MatcherFor 返回第 i 条分流列表的匹配器
func (mh *MatcherHandler) MatcherFor(i int) *YAMLMatcher {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	if i < 0 || i >= len(mh.matchers) {
		return nil
	}
	return mh.matchers[i]
}

// SplitDecision 分流匹配决策：命中第一条启用中的列表后，其 DNS、解析模式、云检测开关、ECS 策略与 A/AAAA 偏好一并生效
type SplitDecision struct {
	Matched          bool
	DNS              []string
	DNSMode          string
	ListName         string
	EnableCloudCheck bool
	ECS              config.ECSPolicy
	IPPrefer         string // 列表级 A/AAAA 偏好档位（空值=由调用方回退全局默认）
}

// MatchDomain 按配置顺序匹配分流列表，命中第一条启用中的列表即返回其决策（未命中时 Matched=false）
// 取反列表（Invert）在域名「不在清单内」时命中；清单为空或未配置 DNS 时跳过，避免无差别命中
func (mh *MatcherHandler) MatchDomain(domain string) SplitDecision {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	for i, l := range mh.config.SplitLists {
		if !l.Enabled || i >= len(mh.matchers) {
			continue
		}
		m := mh.matchers[i]
		if m == nil {
			continue
		}

		if l.Invert {
			// 取反匹配依赖已加载的清单与非空 DNS，否则会退化成「命中一切」
			if m.RuleCount() == 0 || len(l.DNS) == 0 {
				continue
			}
			if _, hit := m.MatchDomain(domain); !hit {
				return splitDecisionFrom(l, l.DNS)
			}
			continue
		}

		if dns, hit := m.MatchDomain(domain); hit {
			return splitDecisionFrom(l, dns)
		}
	}
	return SplitDecision{}
}

// MatchDomainWithin 仅在 refs 指定的分流列表内匹配（客户端分组引用的子集）。
// 按 refs 的顺序生效（即用户在分组里拖出来的引用顺序），未命中返回 Matched=false。
func (mh *MatcherHandler) MatchDomainWithin(domain string, refs []string) SplitDecision {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	if len(refs) == 0 {
		return SplitDecision{}
	}
	idx := make(map[string]int, len(mh.config.SplitLists))
	for i, l := range mh.config.SplitLists {
		idx[l.Name] = i
	}
	for _, ref := range refs {
		i, ok := idx[ref]
		if !ok || i >= len(mh.config.SplitLists) || i >= len(mh.matchers) {
			continue // 悬空引用（校验已拦，这里再兜一层）
		}
		l := mh.config.SplitLists[i]
		m := mh.matchers[i]
		if !l.Enabled || m == nil {
			continue
		}
		if l.Invert {
			if m.RuleCount() == 0 || len(l.DNS) == 0 {
				continue
			}
			if _, hit := m.MatchDomain(domain); !hit {
				return splitDecisionFrom(l, l.DNS)
			}
			continue
		}
		if dns, hit := m.MatchDomain(domain); hit {
			return splitDecisionFrom(l, dns)
		}
	}
	return SplitDecision{}
}

// splitDecisionFrom 由分流列表配置与命中的 DNS 组装决策
func splitDecisionFrom(l config.SplitList, dns []string) SplitDecision {
	return SplitDecision{
		Matched:          true,
		DNS:              dns,
		DNSMode:          normDNSMode(l.DNSMode),
		ListName:         l.Name,
		EnableCloudCheck: l.EnableCloudCheck,
		ECS:              l.ECS,
		IPPrefer:         l.IPPrefer,
	}
}

// normDNSMode 空值按默认的并发竞速（race）处理，与解析路径的判定保持一致
func normDNSMode(mode string) string {
	if mode == "" {
		return config.DNSModeRace
	}
	return mode
}

// InitializeConfig 加载各分流列表的域名规则文件（不存在则跳过，等待定时任务下载）
func (mh *MatcherHandler) InitializeConfig() error {
	for i, l := range mh.config.SplitLists {
		if !l.Enabled {
			mh.logger.Info("⏭️ 分流列表已禁用，跳过加载", map[string]interface{}{
				"list": l.Name,
			})
			continue
		}
		if l.DomainFile == "" {
			continue
		}

		ym := mh.MatcherFor(i)
		if _, err := os.Stat(l.DomainFile); err != nil {
			mh.logger.Info("📋 分流列表文件不存在，等待定时任务下载", map[string]interface{}{
				"list": l.Name,
				"file": l.DomainFile,
			})
			continue
		}
		if err := ym.LoadYAMLConfig(l.DomainFile); err != nil {
			mh.logger.Error("❌ 分流列表加载失败", map[string]interface{}{
				"list":  l.Name,
				"file":  l.DomainFile,
				"error": err.Error(),
			})
			return err
		}
		mh.logger.Info("✅ 分流列表加载成功", map[string]interface{}{
			"list": l.Name,
			"file": l.DomainFile,
		})
	}
	return nil
}

// HandleYAMLMatcher 处理YAML定向域名匹配
func (mh *MatcherHandler) HandleYAMLMatcher(domain string, qtype uint16, upstream string) (*dns.Msg, error) {
	// 创建DNS查询请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 使用定向域名配置的DNS服务器进行查询
	resp, err := mh.proxyQuery(req, []string{upstream})
	if err != nil {
		mh.logger.Error("❌ YAML定向域名查询失败", map[string]interface{}{
			"domain":   domain,
			"upstream": upstream,
			"error":    err.Error(),
		})
		return nil, err
	}

	return resp, nil
}

// HandleChinaDomain 处理中国域名匹配
func (mh *MatcherHandler) HandleChinaDomain(domain string, qtype uint16, upstreams []string) (*dns.Msg, error) {
	// 创建DNS查询请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 使用中国域名配置的DNS服务器进行查询
	resp, err := mh.proxyQuery(req, upstreams)
	if err != nil {
		mh.logger.Error("❌ 中国域名查询失败", map[string]interface{}{
			"domain":    domain,
			"upstreams": upstreams,
			"error":     err.Error(),
		})
		return nil, err
	}

	return resp, nil
}
