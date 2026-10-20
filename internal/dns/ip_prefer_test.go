package dns

import (
	"net"
	"os"
	"testing"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// captureWriter 捕获写出的响应，供偏好拦截用例断言
type captureWriter struct {
	nopWriter
	msg *dns.Msg
}

func (c *captureWriter) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }

// startEmptyUpstream 启动总是返回空 NOERROR 的假上游（模拟纯 v6 域名：解析不出 A 记录）
func startEmptyUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// setSplitIPPrefer 覆盖测试用分流列表的档位（mh.config 与 h.config 是同一指针，改完即对匹配生效）
func setSplitIPPrefer(h *RefactoredHandler, listPrefer, globalPrefer string) {
	h.config.SplitLists[0].IPPrefer = listPrefer
	h.config.IPPrefer = globalPrefer
}

func aaaaQuery(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	m.RecursionDesired = true
	return m
}

// 档位判定矩阵：只有 AAAA 查询可能被置空，且 prefer_a 需域名确有 A 记录
func TestFilterAAAA(t *testing.T) {
	cases := []struct {
		name       string
		listPref   string
		globalPref string
		qtype      uint16
		domain     string // 命中测试清单（test.example.com）用 a.test.example.com
		wantFilter bool
	}{
		{"不干预", "", "", dns.TypeAAAA, "a.test.example.com", false},
		{"只能A-列表", config.IPPreferOnlyA, "", dns.TypeAAAA, "a.test.example.com", true},
		{"优先A-列表-有A记录", config.IPPreferA, "", dns.TypeAAAA, "a.test.example.com", true},
		{"优先AAAA-列表", config.IPPreferAAAA, "", dns.TypeAAAA, "a.test.example.com", false},
		{"只能A-全局兜底", "", config.IPPreferOnlyA, dns.TypeAAAA, "a.test.example.com", true},
		{"列表档位压过全局", config.IPPreferAAAA, config.IPPreferOnlyA, dns.TypeAAAA, "a.test.example.com", false},
		{"未命中列表走全局", "", config.IPPreferOnlyA, dns.TypeAAAA, "other.example.com", true},
		{"未命中列表且全局不干预", "", "", dns.TypeAAAA, "other.example.com", false},
		{"查A永不受影响", config.IPPreferOnlyA, config.IPPreferOnlyA, dns.TypeA, "a.test.example.com", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := startFakeUpstream(t)
			h, _ := newSplitListTestHandler(t, up.addr, config.ECSPolicy{})
			setSplitIPPrefer(h, c.listPref, c.globalPref)

			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(c.domain), c.qtype)
			req.RecursionDesired = true
			w := &captureWriter{}

			if got := h.filterAAAA(w, req, c.domain, c.qtype, "-"); got != c.wantFilter {
				t.Fatalf("filterAAAA = %v，期望 %v", got, c.wantFilter)
			}
			if !c.wantFilter {
				if w.msg != nil {
					t.Fatalf("不应写出任何响应，实际 %v", w.msg)
				}
				return
			}
			// 置空形状：空 answer 的 NOERROR（客户端据此降级到 A 查询）
			if w.msg == nil {
				t.Fatal("应写出空 NODATA 响应")
			}
			if w.msg.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode 应为 NOERROR，实际 %s", dns.RcodeToString[w.msg.Rcode])
			}
			if len(w.msg.Answer) != 0 {
				t.Errorf("应答应为空，实际 %v", w.msg.Answer)
			}
			if !w.msg.RecursionAvailable {
				t.Error("应置 RA 位")
			}
			if len(w.msg.Question) != 1 || w.msg.Question[0].Qtype != dns.TypeAAAA {
				t.Errorf("应原样回带客户端问题段，实际 %v", w.msg.Question)
			}
		})
	}
}

// prefer_a 的放行分支：域名解析不出 A 记录（纯 v6）时不得置空，否则该域名整体不可达
func TestFilterAAAAPreferAPassesThroughWhenNoA(t *testing.T) {
	h, _ := newSplitListTestHandler(t, startEmptyUpstream(t), config.ECSPolicy{})
	setSplitIPPrefer(h, config.IPPreferA, "")

	req := aaaaQuery("a.test.example.com")
	w := &captureWriter{}
	if h.filterAAAA(w, req, "a.test.example.com", dns.TypeAAAA, "-") {
		t.Fatal("无 A 记录时不应置空 AAAA")
	}
	if w.msg != nil {
		t.Fatalf("不应写出任何响应，实际 %v", w.msg)
	}
}

// prefer_a 的判定依据是「上游确有 A 记录」，而非「列表里有这个域名」
func TestFilterAAAAPreferAQueriesUpstreamA(t *testing.T) {
	up := startFakeUpstream(t)
	h, _ := newSplitListTestHandler(t, up.addr, config.ECSPolicy{})
	setSplitIPPrefer(h, config.IPPreferA, "")

	req := aaaaQuery("a.test.example.com")
	if !h.filterAAAA(&captureWriter{}, req, "a.test.example.com", dns.TypeAAAA, "-") {
		t.Fatal("上游返回 A 记录时应置空 AAAA")
	}
	if got := up.lastRequest(t); got.Question[0].Qtype != dns.TypeA {
		t.Errorf("补查应为 A 查询，实际 %s", dns.TypeToString[got.Question[0].Qtype])
	}
}

// 优先AAAA：云替换缺少 IPv6 时不再置空，改为降级返回上游真实 AAAA
func TestCloudReplacementPreferAAAAKeepsUpstreamAAAA(t *testing.T) {
	// logger与缓存管理器构造会写./logs目录，chdir到临时目录避免污染仓库
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceCacheTime = 0
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	// 替换域名只解析出 A 记录（无 IPv6 可替换）
	proxy := func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(req)
		r.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("104.16.1.1"),
		}}
		return r, nil
	}

	req := aaaaQuery("cloud.example.com")
	original := new(dns.Msg)
	original.SetReply(req)
	original.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: "cloud.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("2606:4700::1"),
	}}

	for _, c := range []struct {
		name     string
		ipPrefer string
		wantAAAA bool
	}{
		{"不干预：仍置空让客户端降级到A", "", false},
		{"优先AAAA：保留上游真实AAAA", config.IPPreferAAAA, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var written *dns.Msg
			ch := NewCloudHandler(cfg, logger, cm, nil, proxy,
				func(_ dns.ResponseWriter, _ *dns.Msg, resp *dns.Msg) { written = resp })

			if _, err := ch.HandleCloudReplacement(nopWriter{}, req, "cloud.example.com", dns.TypeAAAA,
				int(CloudTypeCloudflare), original, c.ipPrefer, "-", ReplaceConfig{CFDomain: cfg.ReplaceCFDomain}); err != nil {
				t.Fatalf("HandleCloudReplacement 返回错误: %v", err)
			}
			if written == nil {
				t.Fatal("未写出任何响应")
			}
			if c.wantAAAA {
				if len(written.Answer) != 1 {
					t.Fatalf("应保留上游 AAAA 记录，实际 %v", written.Answer)
				}
				if aaaa, ok := written.Answer[0].(*dns.AAAA); !ok || aaaa.AAAA.String() != "2606:4700::1" {
					t.Errorf("应返回上游真实 AAAA，实际 %v", written.Answer[0])
				}
				return
			}
			if len(written.Answer) != 0 {
				t.Errorf("默认应置空 AAAA，实际 %v", written.Answer)
			}
		})
	}
}
