package dns

import (
	"net/netip"
	"sort"
	"strings"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/source"
)

// ISPLookup 客户端运营商识别抽象（注入到匹配器，便于替换实现与测试）
type ISPLookup interface {
	Lookup(addr netip.Addr) (source.ISP, bool)
}

// GroupForISP 把段库识别出的运营商收敛到 4 个固定分组。
// 教育网/广电/长宽/其他 ISP，以及"判不出"，一律归入 other。
func GroupForISP(isp source.ISP, ok bool) config.ISPKey {
	if !ok {
		return config.ISPGroupOther
	}
	switch isp {
	case source.ISPTelecom:
		return config.ISPGroupTelecom
	case source.ISPUnicom:
		return config.ISPGroupUnicom
	case source.ISPCMCC:
		return config.ISPGroupCMCC
	default: // cernet / chinabtn / gwbn / othernet / 未识别
		return config.ISPGroupOther
	}
}

// ClientDecision 客户端分组决策：命中分组后先按 SplitRefs 引用的域名分流列表匹配
// （命中哪条复用哪条的策略），全部未命中时用 FallbackDNS 兜底（覆盖全局上游）。
// FallbackDNS 为空时调用方回退全局 upstream。
type ClientDecision struct {
	Matched      bool
	Scope        string                    // 缓存隔离标识：内置分组为 ISP key，自定义组为 "c:<name>"
	Label        string                    // 日志/展示用名称
	SplitRefs    []string                  // 引用「上游与域名分流」里的列表名，顺序即匹配顺序
	FallbackDNS  []string                  // 兜底上游：引用分流全部未命中时使用
	DNSMode      string                    // race / failover，仅作用于兜底查询
	IPPrefer     string                    // 兜底查询的 A/AAAA 偏好档位（空值=跟随全局默认）
	ECS          config.ECSPolicy          // 兜底查询的 EDNS Client Subnet 策略
	CloudReplace config.CloudReplacePolicy // 本线路的云替换目标（可覆写全局）
}

// ClientGroupMatcher 客户端分组匹配器
type ClientGroupMatcher struct {
	ispGroups map[config.ISPKey]config.ISPGroup
	custom    []config.CustomGroup // 已按 Priority 降序
	isp       ISPLookup            // 可空；为空时运营商分组一律不命中（等价"未启用识别"）
}

// NewClientGroupMatcher 创建客户端分组匹配器（未注入运营商识别器）
func NewClientGroupMatcher(ispGroups []config.ISPGroup, customGroups []config.CustomGroup) *ClientGroupMatcher {
	m := &ClientGroupMatcher{}
	m.UpdateGroups(ispGroups, customGroups)
	return m
}

// NewClientGroupMatcherWithISPLookup 创建匹配器并注入运营商识别器
func NewClientGroupMatcherWithISPLookup(ispGroups []config.ISPGroup, customGroups []config.CustomGroup, sp ISPLookup) *ClientGroupMatcher {
	m := NewClientGroupMatcher(ispGroups, customGroups)
	m.SetISPLookup(sp)
	return m
}

// SetISPLookup 覆盖或清除运营商识别器
func (m *ClientGroupMatcher) SetISPLookup(sp ISPLookup) { m.isp = sp }

// UpdateGroups 更新分组（热更新入口）
func (m *ClientGroupMatcher) UpdateGroups(ispGroups []config.ISPGroup, customGroups []config.CustomGroup) {
	byISP := make(map[config.ISPKey]config.ISPGroup, len(ispGroups))
	for _, g := range ispGroups {
		byISP[g.ISP] = g
	}
	out := make([]config.CustomGroup, len(customGroups))
	copy(out, customGroups)
	// 自定义组按 Priority 降序、同值保持原顺序（稳定排序）
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })

	m.ispGroups = byISP
	m.custom = out
}

// Match 按客户端 IP 匹配分组：先自定义组（Priority 大者先），再按运营商收敛到固定组。
// 未启用运营商识别（isp 为空）时，运营商分组一律不命中 → 完全等价于"没有客户端分组"。
func (m *ClientGroupMatcher) Match(clientIP netip.Addr) ClientDecision {
	if !clientIP.IsValid() {
		return ClientDecision{}
	}

	// 1. 自定义组优先，保证"机房出口/专线"这类精确需求不被运营商组抢走
	for _, g := range m.custom {
		if !g.Enabled {
			continue
		}
		if matchAddrList(g.Match, clientIP) {
			return ClientDecision{
				Matched:      true,
				Scope:        config.CustomScope(g.Name),
				Label:        g.Name,
				SplitRefs:    g.SplitRefs,
				FallbackDNS:  g.FallbackDNS,
				DNSMode:      normDNSMode(g.DNSMode),
				IPPrefer:     g.IPPrefer,
				ECS:          g.ECS,
				CloudReplace: g.CloudReplace,
			}
		}
	}

	// 2. 运营商固定组
	if m.isp == nil {
		return ClientDecision{}
	}
	key := config.ISPGroupOther // 判不出 → 其他
	if isp, ok := m.isp.Lookup(clientIP); ok {
		key = GroupForISP(isp, true)
	}
	g, exists := m.ispGroups[key]
	if !exists || !g.Enabled {
		return ClientDecision{}
	}
	return ClientDecision{
		Matched:      true,
		Scope:        string(key),
		Label:        config.ISPGroupLabel(key),
		SplitRefs:    g.SplitRefs,
		FallbackDNS:  g.FallbackDNS,
		DNSMode:      normDNSMode(g.DNSMode),
		IPPrefer:     g.IPPrefer,
		ECS:          g.ECS,
		CloudReplace: g.CloudReplace,
	}
}

// DecisionForScope 由缓存 scope 反查分组决策（缓存命中路径复用）
func (m *ClientGroupMatcher) DecisionForScope(scope string) ClientDecision {
	if scope == "" || scope == "-" {
		return ClientDecision{}
	}
	if name, ok := strings.CutPrefix(scope, "c:"); ok {
		for _, g := range m.custom {
			if g.Name == name && g.Enabled {
				return ClientDecision{
					Matched:      true,
					Scope:        config.CustomScope(g.Name),
					Label:        g.Name,
					SplitRefs:    g.SplitRefs,
					FallbackDNS:  g.FallbackDNS,
					DNSMode:      normDNSMode(g.DNSMode),
					IPPrefer:     g.IPPrefer,
					ECS:          g.ECS,
					CloudReplace: g.CloudReplace,
				}
			}
		}
		return ClientDecision{}
	}
	key := config.ISPKey(scope)
	g, exists := m.ispGroups[key]
	if !exists || !g.Enabled {
		return ClientDecision{}
	}
	return ClientDecision{
		Matched:      true,
		Scope:        string(key),
		Label:        config.ISPGroupLabel(key),
		SplitRefs:    g.SplitRefs,
		FallbackDNS:  g.FallbackDNS,
		DNSMode:      normDNSMode(g.DNSMode),
		IPPrefer:     g.IPPrefer,
		ECS:          g.ECS,
		CloudReplace: g.CloudReplace,
	}
}

// matchAddrList 判断 IP 是否命中「裸 IP / CIDR」清单
func matchAddrList(items []string, ip netip.Addr) bool {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if p, err := netip.ParsePrefix(item); err == nil && p.Contains(ip) {
				return true
			}
			continue
		}
		if v, err := netip.ParseAddr(item); err == nil && v == ip {
			return true
		}
	}
	return false
}
