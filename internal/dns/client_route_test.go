package dns

import (
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"
)

// newRouteFixture 构造只含路由所需依赖的 handler（配置 + 分流匹配器），
// 不启动任何网络监听，因此可直接断言 resolveRoute 的决策结果。
func newRouteFixture(t *testing.T, cfg *config.Config) *RefactoredHandler {
	t.Helper()
	logger := utils.NewEnhancedLogger("error", "test", false)
	mh := NewMatcherHandler(cfg, logger, &RefactoredHandler{})
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}
	return &RefactoredHandler{config: cfg, Logger: logger, matcherHandler: mh}
}

// routeCfg 构造「国内 + 国外」两条全局分流列表与全局上游的基础配置。
func routeCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Upstream = []string{"udp://9.9.9.9:53"}
	cfg.SplitLists = []config.SplitList{
		{
			Name: "国内", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,cn.example.com"),
			DNS: []string{"udp://223.5.5.5:53"}, Refresh: time.Hour,
		},
		{
			Name: "国外", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,en.example.com"),
			DNS: []string{"udp://8.8.8.8:53"}, Refresh: time.Hour,
		},
	}
	return cfg
}

// 未命中客户端分组 → 沿用原有全局域名分流行为
func TestResolveRouteNoClientGroup(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	d, up := h.resolveRoute("www.cn.example.com", ClientDecision{})
	if !d.Matched || d.ListName != "国内" || up[0] != "udp://223.5.5.5:53" {
		t.Fatalf("未命中分组时应走全局分流：%+v / %v", d, up)
	}

	_, up = h.resolveRoute("www.unknown.com", ClientDecision{})
	if up[0] != "udp://9.9.9.9:53" {
		t.Fatalf("全局分流未命中时应回退全局上游，得到 %v", up)
	}
}

// 命中分组 → 引用分流命中时复用该分流列表的 DNS；引用未命中时走兜底 DNS
func TestResolveRouteMatchedGroupReuseSplitThenFallback(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	cd := ClientDecision{
		Matched:     true,
		Scope:       "c:机房",
		Label:       "机房",
		SplitRefs:   []string{"国内", "国外"},
		FallbackDNS: []string{"udp://10.0.0.1:53"},
		DNSMode:     "failover",
		IPPrefer:    config.IPPreferA,
	}

	// 命中引用的「国内」分流列表 → 复用该列表的 DNS，不展开组兜底
	d, up := h.resolveRoute("www.cn.example.com", cd)
	if !d.Matched || d.ListName != "国内" || up[0] != "udp://223.5.5.5:53" {
		t.Fatalf("命中引用分流应复用其 DNS：%+v / %v", d, up)
	}

	d, up = h.resolveRoute("www.en.example.com", cd)
	if !d.Matched || d.ListName != "国外" || up[0] != "udp://8.8.8.8:53" {
		t.Fatalf("命中引用分流应复用其 DNS：%+v / %v", d, up)
	}

	// 引用分流全部未命中 → 走兜底 DNS，并携带分组配置的偏好与 ECS 语义
	d, up = h.resolveRoute("www.other.org", cd)
	if len(up) != 1 || up[0] != "udp://10.0.0.1:53" {
		t.Fatalf("引用未命中应走兜底 DNS，得到 %v", up)
	}
	if !d.Matched || d.ListName != "机房" || d.DNSMode != "failover" || d.IPPrefer != config.IPPreferA {
		t.Fatalf("兜底决策应携带分组配置：%+v", d)
	}
}

// 命中分组但引用分流为空且兜底 DNS 为空 → 回退全局 upstream
func TestResolveRouteMatchedGroupEmptyFallbackFallsBack(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	cd := ClientDecision{Matched: true, Scope: "c:专线", Label: "专线", DNSMode: "failover"}
	_, up := h.resolveRoute("www.anything.example.org", cd)
	if len(up) != 1 || up[0] != "udp://9.9.9.9:53" {
		t.Fatalf("兜底 DNS 为空时应回退全局上游，得到 %v", up)
	}
}

// 命中引用分流，且分组开了 ECS 时：统一用分组 ECS 覆写列表自带 ECS（不论明文/加密上游）；
// 分组未开 ECS 时保留列表自身 ECS。
func TestResolveRouteMatchedGroupOverrideECS(t *testing.T) {
	cfg := routeCfg(t)
	groupECS := config.ECSPolicy{Enabled: true, ISPType: "telecom", Subnet: "59.51.78.211"}
	listECS := config.ECSPolicy{Enabled: true, ISPType: "unicom", Subnet: "31.59.174.0/23"}
	cd := ClientDecision{
		Matched:     true,
		Scope:       "c:电信",
		Label:       "电信",
		SplitRefs:   []string{"国内", "国外"},
		FallbackDNS: []string{"udp://10.0.0.1:53"},
		ECS:         groupECS,
	}

	// 明文 udp 分流列表，命中 → 分组开了 ECS 也覆写
	cfg.SplitLists = append(cfg.SplitLists, config.SplitList{
		Name: "明文", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,plain.example.com"),
		DNS: []string{"udp://223.5.5.5:53"}, ECS: listECS, Refresh: time.Hour,
	})
	// 加密 DoH 分流列表，命中 → 同样覆写
	cfg.SplitLists = append(cfg.SplitLists, config.SplitList{
		Name: "加密", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,tls.example.com"),
		DNS: []string{"https://8.8.8.8/dns-query"}, ECS: listECS, Refresh: time.Hour,
	})
	cd.SplitRefs = append(cd.SplitRefs, "明文", "加密")
	h := newRouteFixture(t, cfg)

	// 明文上游 + 分组 ECS 开启 → 覆写为分组 ECS
	d, _ := h.resolveRoute("www.plain.example.com", cd)
	if !d.Matched || d.ECS.ISPType != "telecom" || d.ECS.Subnet != "59.51.78.211" {
		t.Fatalf("明文上游 + 分组 ECS 开启应覆写为分组 ECS (telecom)，得到 %+v", d.ECS)
	}

	// 加密上游 + 分组 ECS 开启 → 同样覆写
	d2, _ := h.resolveRoute("www.tls.example.com", cd)
	if !d2.Matched || d2.ECS.ISPType != "telecom" {
		t.Fatalf("加密上游 + 分组 ECS 开启应覆写为分组 ECS (telecom)，得到 %+v", d2.ECS)
	}

	// 分组未开 ECS → 明文/加密都保留列表自带 ECS
	cd.ECS = config.ECSPolicy{Enabled: false}
	d3, _ := h.resolveRoute("www.plain.example.com", cd)
	if !d3.Matched || d3.ECS.ISPType != "unicom" {
		t.Fatalf("分组未开 ECS 时应保留列表 ECS (unicom)，得到 %+v", d3.ECS)
	}
	d4, _ := h.resolveRoute("www.tls.example.com", cd)
	if !d4.Matched || d4.ECS.ISPType != "unicom" {
		t.Fatalf("分组未开 ECS 时加密上游也应保留列表 ECS (unicom)，得到 %+v", d4.ECS)
	}
}

// 分组覆盖写关闭时跟随全局云替换目标；开启时使用分组自带的替换目标
func TestEffectiveReplaceConfigOverride(t *testing.T) {
	cfg := routeCfg(t)
	cfg.ReplaceCFDomain = "global.cf"
	cfg.ReplaceAWSDomain = "global.aws"
	cfg.ReplaceCFAPI = "https://global/api"
	cfg.ReplaceAPICount = 5
	h := newRouteFixture(t, cfg)

	// 未覆写 → 全局
	got := h.effectiveReplaceConfig(ClientDecision{})
	if got.CFDomain != "global.cf" || got.AWSDomain != "global.aws" || got.CFAPI != "https://global/api" || got.APICount != 5 {
		t.Fatalf("未覆写应跟随全局，得到 %+v", got)
	}

	// 覆写 → 分组自带（仅 CF 线路独立）
	got = h.effectiveReplaceConfig(ClientDecision{CloudReplace: config.CloudReplacePolicy{
		Override: true, CFDomain: "cm.cf", CFAPI: "https://cm/api?select=cm", APICount: 2,
	}})
	if got.CFDomain != "cm.cf" || got.CFAPI != "https://cm/api?select=cm" || got.APICount != 2 || got.AWSDomain != "" {
		t.Fatalf("覆写应使用分组自带目标（不回落全局 AWS），得到 %+v", got)
	}
}

// 分组兜底路径（引用分流未命中）也必须执行云检测：兜底决策的 EnableCloudCheck 置 true
func TestResolveRouteFallbackEnablesCloudCheck(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))
	cd := ClientDecision{
		Matched:     true,
		Scope:       "cmcc",
		Label:       "中国移动",
		FallbackDNS: []string{"udp://10.0.0.1:53"},
		SplitRefs:   []string{"国内"},
	}

	d, _ := h.resolveRoute("www.other.org", cd) // 命中分组但引用分流未命中 → 兜底
	if !d.Matched || !d.EnableCloudCheck {
		t.Fatalf("分组兜底路径应执行云检测，得到 %+v", d)
	}
}
