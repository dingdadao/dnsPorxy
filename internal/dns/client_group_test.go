package dns

import (
	"net/netip"
	"testing"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/source"
)

// fakeISP 测试用运营商识别器：按固定 IP 返回运营商，其余返回"判不出"
type fakeISP struct{}

func (fakeISP) Lookup(addr netip.Addr) (source.ISP, bool) {
	switch addr.String() {
	case "1.1.1.1":
		return source.ISPTelecom, true
	case "2.2.2.2":
		return source.ISPUnicom, true
	case "3.3.3.3":
		return source.ISPCMCC, true
	case "4.4.4.4":
		return source.ISPCernet, true // 教育网 → 归入 other
	case "9.9.9.9":
		return source.ISPOther, true
	}
	return source.ISPOther, false
}

func TestGroupForISP(t *testing.T) {
	cases := []struct {
		isp  source.ISP
		ok   bool
		want config.ISPKey
	}{
		{source.ISPTelecom, true, config.ISPGroupTelecom},
		{source.ISPUnicom, true, config.ISPGroupUnicom},
		{source.ISPCMCC, true, config.ISPGroupCMCC},
		{source.ISPCernet, true, config.ISPGroupOther},
		{source.ISPChinabtn, true, config.ISPGroupOther},
		{source.ISPGWBN, true, config.ISPGroupOther},
		{source.ISPOther, true, config.ISPGroupOther},
		{source.ISPOther, false, config.ISPGroupOther}, // 判不出
	}
	for _, c := range cases {
		if got := GroupForISP(c.isp, c.ok); got != c.want {
			t.Errorf("GroupForISP(%q,%v) = %q, want %q", c.isp, c.ok, got, c.want)
		}
	}
}

func ispGroups(enabled map[config.ISPKey]bool) []config.ISPGroup {
	out := make([]config.ISPGroup, 0, len(enabled))
	for _, k := range config.KnownISPGroups() {
		out = append(out, config.ISPGroup{
			ISP:         k,
			Enabled:     enabled[k],
			FallbackDNS: []string{"udp://" + string(k) + ".dns:53"},
		})
	}
	return out
}

func TestMatcherISPGroup(t *testing.T) {
	all := map[config.ISPKey]bool{
		config.ISPGroupTelecom: true,
		config.ISPGroupUnicom:  true,
		config.ISPGroupCMCC:    true,
		config.ISPGroupOther:   true,
	}
	m := NewClientGroupMatcherWithISPLookup(ispGroups(all), nil, fakeISP{})

	cases := []struct {
		ip   string
		want config.ISPKey
	}{
		{"1.1.1.1", config.ISPGroupTelecom},
		{"2.2.2.2", config.ISPGroupUnicom},
		{"3.3.3.3", config.ISPGroupCMCC},
		{"4.4.4.4", config.ISPGroupOther}, // 教育网并入其他
		{"9.9.9.9", config.ISPGroupOther}, // 段库显式给出 other
		{"8.8.8.8", config.ISPGroupOther}, // 判不出 → 其他
	}
	for _, c := range cases {
		d := m.Match(netip.MustParseAddr(c.ip))
		if !d.Matched {
			t.Errorf("%s 应命中分组，得到未命中", c.ip)
			continue
		}
		if d.Scope != string(c.want) {
			t.Errorf("%s scope = %q, want %q", c.ip, d.Scope, c.want)
		}
		if d.Label != config.ISPGroupLabel(c.want) {
			t.Errorf("%s label = %q, want %q", c.ip, d.Label, config.ISPGroupLabel(c.want))
		}
		if len(d.FallbackDNS) == 0 {
			t.Errorf("%s 应带上兜底 DNS", c.ip)
		}
	}
}

func TestMatcherISPGroupsDisabled(t *testing.T) {
	// 只启用电信：其余运营商（含判不出）不应命中
	m := NewClientGroupMatcherWithISPLookup(
		ispGroups(map[config.ISPKey]bool{config.ISPGroupTelecom: true}), nil, fakeISP{})

	if d := m.Match(netip.MustParseAddr("1.1.1.1")); !d.Matched {
		t.Errorf("1.1.1.1 应命中 telecom 分组")
	}
	for _, ip := range []string{"2.2.2.2", "3.3.3.3", "8.8.8.8"} {
		if d := m.Match(netip.MustParseAddr(ip)); d.Matched {
			t.Errorf("%s 未启用对应分组，不应命中，得到 %+v", ip, d)
		}
	}
}

func TestMatcherISPWithoutLookup(t *testing.T) {
	// 未注入识别器（等价"运营商识别关闭"）：运营商分组一律不命中
	m := NewClientGroupMatcher(ispGroups(map[config.ISPKey]bool{config.ISPGroupTelecom: true}), nil)
	if d := m.Match(netip.MustParseAddr("1.1.1.1")); d.Matched {
		t.Errorf("未注入识别器时运营商分组不应命中，得到 %+v", d)
	}
}

func TestMatcherCustomGroupPriority(t *testing.T) {
	custom := []config.CustomGroup{
		{Name: "low", Enabled: true, Priority: 1, Match: []string{"10.0.0.0/8"},
			FallbackDNS: []string{"udp://1.1.1.1:53"}},
		{Name: "high", Enabled: true, Priority: 9, Match: []string{"10.0.0.0/8"},
			FallbackDNS: []string{"udp://2.2.2.2:53"}},
		// 精确命中运营商 IP，但优先级最低，应被上面两个 IP 组压住
		{Name: "isp-override", Enabled: true, Priority: 0, Match: []string{"1.1.1.1"},
			FallbackDNS: []string{"udp://3.3.3.3:53"}},
	}
	m := NewClientGroupMatcherWithISPLookup(
		ispGroups(map[config.ISPKey]bool{config.ISPGroupTelecom: true}), custom, fakeISP{})

	if d := m.Match(netip.MustParseAddr("10.1.1.1")); d.Scope != config.CustomScope("high") {
		t.Errorf("同网段应取 Priority 大的自定义组，得到 %+v", d)
	}
	// 自定义组整体优先于运营商组
	if d := m.Match(netip.MustParseAddr("1.1.1.1")); d.Scope != config.CustomScope("isp-override") {
		t.Errorf("自定义组应优先于运营商组，得到 %+v", d)
	}
	// 内置运营商组用 ISP key 作 scope，与自定义组前缀区分
	if d := m.Match(netip.MustParseAddr("2.2.2.2")); d.Matched {
		t.Errorf("2.2.2.2 无自定义组命中且未启用 unicom，不应命中，得到 %+v", d)
	}
}

func TestMatcherCustomGroupDisabledAndInvalid(t *testing.T) {
	custom := []config.CustomGroup{
		{Name: "off", Enabled: false, Priority: 5, Match: []string{"10.0.0.0/8"}},
		{Name: "bad", Enabled: true, Priority: 4, Match: []string{"not-an-ip"}},
	}
	m := NewClientGroupMatcherWithISPLookup(nil, custom, fakeISP{})
	if d := m.Match(netip.MustParseAddr("10.1.1.1")); d.Matched {
		t.Errorf("禁用/非法 Match 不应命中，得到 %+v", d)
	}
}

func TestDecisionForScope(t *testing.T) {
	custom := []config.CustomGroup{
		{Name: "机房", Enabled: true, Priority: 1, Match: []string{"10.0.0.0/8"},
			FallbackDNS: []string{"udp://1.1.1.1:53"}, DNSMode: "failover"},
	}
	m := NewClientGroupMatcherWithISPLookup(
		ispGroups(map[config.ISPKey]bool{config.ISPGroupCMCC: true}), custom, fakeISP{})

	// 内置运营商 scope 直接就是 ISP key
	d := m.DecisionForScope(string(config.ISPGroupCMCC))
	if !d.Matched || d.Scope != string(config.ISPGroupCMCC) || d.DNSMode != config.DNSModeRace {
		t.Errorf("telecom scope 反查异常: %+v", d)
	}

	// 自定义 scope 带 c: 前缀
	d = m.DecisionForScope(config.CustomScope("机房"))
	if !d.Matched || d.Scope != config.CustomScope("机房") || d.DNSMode != "failover" {
		t.Errorf("自定义 scope 反查异常: %+v", d)
	}
	if len(d.FallbackDNS) != 1 || d.FallbackDNS[0] != "udp://1.1.1.1:53" {
		t.Errorf("自定义 scope 应带出兜底 DNS: %+v", d)
	}

	// 未命中 / 已删除的分组
	for _, scope := range []string{"", "-", "not-exist", config.CustomScope("不存在")} {
		if d := m.DecisionForScope(scope); d.Matched {
			t.Errorf("scope=%q 不应命中，得到 %+v", scope, d)
		}
	}
}

// 命中分组时，决策须携带该分组的云替换覆写策略（否则多线路云替换失效）
func TestMatcherCarriesCloudReplace(t *testing.T) {
	ispCR := config.CloudReplacePolicy{Override: true, CFDomain: "cm.cf.example", APICount: 2}
	ig := ispGroups(map[config.ISPKey]bool{config.ISPGroupCMCC: true})
	for i := range ig {
		if ig[i].ISP == config.ISPGroupCMCC {
			ig[i].CloudReplace = ispCR
		}
	}
	customCR := config.CloudReplacePolicy{Override: true, CFDomain: "idc.cf.example"}
	custom := []config.CustomGroup{{
		Name: "机房", Enabled: true, Priority: 9, Match: []string{"10.0.0.0/8"},
		FallbackDNS: []string{"udp://1.1.1.1:53"}, CloudReplace: customCR,
	}}
	m := NewClientGroupMatcherWithISPLookup(ig, custom, fakeISP{})

	// Match：运营商组 / 自定义组
	if d := m.Match(netip.MustParseAddr("3.3.3.3")); d.CloudReplace != ispCR {
		t.Errorf("运营商组 Match 应携带云替换策略，得到 %+v", d.CloudReplace)
	}
	if d := m.Match(netip.MustParseAddr("10.1.1.1")); d.CloudReplace != customCR {
		t.Errorf("自定义组 Match 应携带云替换策略，得到 %+v", d.CloudReplace)
	}
	// DecisionForScope：运营商 / 自定义
	if d := m.DecisionForScope(string(config.ISPGroupCMCC)); d.CloudReplace != ispCR {
		t.Errorf("运营商组 DecisionForScope 应携带云替换策略，得到 %+v", d.CloudReplace)
	}
	if d := m.DecisionForScope(config.CustomScope("机房")); d.CloudReplace != customCR {
		t.Errorf("自定义组 DecisionForScope 应携带云替换策略，得到 %+v", d.CloudReplace)
	}
}

func TestMatchAddrList(t *testing.T) {
	items := []string{"10.0.0.1", "192.168.0.0/16", "  ", "2001:db8::1", "2001:db8:1::/48"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.0.0.2", false},
		{"192.168.5.9", true},
		{"172.16.0.1", false},
		{"2001:db8::1", true},
		{"2001:db8:1::5", true},
		{"2001:db8:2::5", false},
	}
	for _, c := range cases {
		if got := matchAddrList(items, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("matchAddrList(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
