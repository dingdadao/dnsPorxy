package dns

import (
	"os"
	"testing"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

func TestNormalizePattern(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"}, // 大小写 + 尾点
		{"*.example.com", ".example.com"},
		{".example.com", ".example.com"},
		{"  example.com  ", "example.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizePattern(c.in); got != c.want {
			t.Errorf("normalizePattern(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func newTestMatcher(t *testing.T, records []*config.Override) *OverrideMatcher {
	t.Helper()
	// logger构造会写./logs目录，chdir到临时目录避免污染仓库
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })
	logger := utils.NewEnhancedLogger("error", "test", false)
	m := NewOverrideMatcher(logger)
	m.Reload(records)
	return m
}

func TestLookupExactAndSuffix(t *testing.T) {
	m := newTestMatcher(t, []*config.Override{
		{Domain: "exact.com", QType: "A", Value: "1.2.3.4", Enabled: true},
		{Domain: ".ad.com", QType: "AAAA", Value: "2001:db8::1", Enabled: true},
		{Domain: "disabled.com", QType: "A", Value: "9.9.9.9", Enabled: false},
	})

	// 精确命中（大小写不敏感）
	if got := m.Lookup("EXACT.com", dns.TypeA); len(got) != 1 || got[0].Value != "1.2.3.4" {
		t.Errorf("精确匹配失败: %v", got)
	}
	// 后缀命中：自身及任意深度子域名
	for _, d := range []string{"ad.com", "sub.ad.com", "a.b.ad.com"} {
		if got := m.Lookup(d, dns.TypeAAAA); len(got) == 0 {
			t.Errorf("后缀匹配失败: %s", d)
		}
	}
	// 未启用记录不参与匹配
	if got := m.Lookup("disabled.com", dns.TypeA); len(got) != 0 {
		t.Errorf("禁用规则被命中: %v", got)
	}
	// 类型不匹配不命中
	if got := m.Lookup("exact.com", dns.TypeAAAA); len(got) != 0 {
		t.Errorf("类型不匹配被命中: %v", got)
	}
}

func TestLookupCNAMEFallback(t *testing.T) {
	m := newTestMatcher(t, []*config.Override{
		{Domain: "go.example.org", QType: "CNAME", Value: "real.target.com", Enabled: true},
	})

	// A/AAAA 查询回退 CNAME 规则
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		got := m.Lookup("go.example.org", qtype)
		if len(got) != 1 || got[0].QType != "CNAME" {
			t.Errorf("qtype=%d CNAME回退失败: %v", qtype, got)
		}
	}
	// 精确CNAME规则不作用于子域名（精确即精确）
	if got := m.Lookup("x.go.example.org", dns.TypeA); len(got) != 0 {
		t.Errorf("精确CNAME不应命中子域名: %v", got)
	}
	// CNAME 查询本身命中
	if got := m.Lookup("go.example.org", dns.TypeCNAME); len(got) != 1 {
		t.Errorf("CNAME直查失败: %v", got)
	}
	// 其他类型不回退
	if got := m.Lookup("go.example.org", dns.TypeTXT); len(got) != 0 {
		t.Errorf("TXT不应回退CNAME: %v", got)
	}

	// 后缀CNAME规则：子域名A查询回退命中
	m2 := newTestMatcher(t, []*config.Override{
		{Domain: ".go.example.org", QType: "CNAME", Value: "real.target.com", Enabled: true},
	})
	if got := m2.Lookup("x.go.example.org", dns.TypeA); len(got) != 1 || got[0].QType != "CNAME" {
		t.Errorf("后缀CNAME回退失败: %v", got)
	}
}

func TestLookupPreciseWinsOverSuffix(t *testing.T) {
	m := newTestMatcher(t, []*config.Override{
		{Domain: ".example.com", QType: "A", Value: "1.1.1.1", Enabled: true},
		{Domain: "www.example.com", QType: "A", Value: "2.2.2.2", Enabled: true},
	})
	got := m.Lookup("www.example.com", dns.TypeA)
	if len(got) != 1 || got[0].Value != "2.2.2.2" {
		t.Errorf("精确应优先于后缀: %v", got)
	}
	got = m.Lookup("other.example.com", dns.TypeA)
	if len(got) != 1 || got[0].Value != "1.1.1.1" {
		t.Errorf("后缀兜底失败: %v", got)
	}
}

func TestMatchAnyType(t *testing.T) {
	m := newTestMatcher(t, []*config.Override{
		{Domain: "fn.example.com", QType: "A", Value: "10.0.0.4", Enabled: true},
		{Domain: ".ad.com", QType: "AAAA", Value: "2001:db8::1", Enabled: true},
		{Domain: "disabled.com", QType: "A", Value: "9.9.9.9", Enabled: false},
	})

	// 命中：不限记录类型（HTTPS等未配置类型也应命中，以便回NODATA）
	for _, d := range []string{"fn.example.com", "FN.Example.com.", "ad.com", "sub.ad.com"} {
		if !m.Match(d) {
			t.Errorf("Match(%q) 应为 true", d)
		}
	}
	// 未命中：无规则域名、未启用规则、非后缀子域
	for _, d := range []string{"other.com", "disabled.com", "xdisabled.com", ""} {
		if m.Match(d) {
			t.Errorf("Match(%q) 应为 false", d)
		}
	}
	// 精确规则不作用于子域名
	if m.Match("x.fn.example.com") {
		t.Error("精确规则不应匹配子域名")
	}
}

func TestBuildNODATAResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("fn.example.com"), dns.TypeHTTPS)
	req.RecursionDesired = true

	resp := buildNODATAResponse(req)
	if !resp.Response || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("NODATA响应标志错误: response=%v rcode=%d", resp.Response, resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("NODATA不应有Answer: %v", resp.Answer)
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != "fn.example.com." {
		t.Errorf("Question回写错误: %v", resp.Question)
	}
}

func TestBuildOverrideResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("Test.Com"), dns.TypeA) // 混合大小写验证owner保留

	// A + AAAA 混合记录：A查询只保留合法A
	resp := buildOverrideResponse(req, dns.TypeA, []*config.Override{
		{QType: "A", Value: "1.2.3.4", TTL: 60},
		{QType: "A", Value: "999.999.1.1", TTL: 60}, // 非法IP应被跳过
	})
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("A响应构造失败: %v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "1.2.3.4" {
		t.Errorf("A记录错误: %v", resp.Answer[0])
	}
	if a.Hdr.Name != "Test.Com." {
		t.Errorf("owner未保留原始大小写: %s", a.Hdr.Name)
	}
	if a.Hdr.Ttl != 60 {
		t.Errorf("TTL错误: %d", a.Hdr.Ttl)
	}
	if !resp.Response || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("响应标志错误: response=%v rcode=%d", resp.Response, resp.Rcode)
	}

	// 全部非法时返回nil
	if resp := buildOverrideResponse(req, dns.TypeA, []*config.Override{
		{QType: "A", Value: "not-an-ip", TTL: 60},
	}); resp != nil {
		t.Errorf("全非法记录应返回nil: %v", resp)
	}

	// TTL=0 使用默认值
	resp = buildOverrideResponse(req, dns.TypeA, []*config.Override{
		{QType: "A", Value: "1.2.3.4", TTL: 0},
	})
	if resp.Answer[0].Header().Ttl != overrideDefaultTTL {
		t.Errorf("TTL=0应使用默认值%d: %d", overrideDefaultTTL, resp.Answer[0].Header().Ttl)
	}

	// AAAA：IPv4地址应被拒绝
	if resp := buildOverrideResponse(req, dns.TypeAAAA, []*config.Override{
		{QType: "AAAA", Value: "1.2.3.4", TTL: 60},
	}); resp != nil {
		t.Errorf("AAAA记录不应接受IPv4: %v", resp)
	}

	// CNAME：目标自动补全FQDN
	resp = buildOverrideResponse(req, dns.TypeCNAME, []*config.Override{
		{QType: "CNAME", Value: "target.com", TTL: 300},
	})
	cn := resp.Answer[0].(*dns.CNAME)
	if cn.Target != "target.com." {
		t.Errorf("CNAME目标未补全FQDN: %s", cn.Target)
	}
}
