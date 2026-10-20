package dns

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// writeRuleFile 写入一个 mihomo 风格域名清单文件并返回路径
func writeRuleFile(t *testing.T, rules ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("payload:\n")
	for _, r := range rules {
		b.WriteString("  - " + r + "\n")
	}
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("写入规则文件失败: %v", err)
	}
	return p
}

// newTestMatcherHandler 构造只含分流匹配所需依赖的 MatcherHandler，并加载各列表清单
func newTestMatcherHandler(t *testing.T, lists []config.SplitList) *MatcherHandler {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.SplitLists = lists
	logger := utils.NewEnhancedLogger("error", "test", false)
	mh := NewMatcherHandler(cfg, logger, &RefactoredHandler{})
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}
	return mh
}

// 取反列表：域名不在清单内才命中本列表，且使用本列表的 DNS
func TestMatchDomainInvert(t *testing.T) {
	file := writeRuleFile(t, "DOMAIN-SUFFIX,internal.example.com")
	mh := newTestMatcherHandler(t, []config.SplitList{{
		Name: "排除清单", Enabled: true, Invert: true,
		DNS: []string{"udp://10.0.0.1:53"}, DomainFile: file, Refresh: time.Hour,
	}})

	if d := mh.MatchDomain("a.internal.example.com"); d.Matched {
		t.Errorf("域名在排除清单内时不应命中: %+v", d)
	}

	d := mh.MatchDomain("www.public.com")
	if !d.Matched || d.ListName != "排除清单" || !slices.Equal(d.DNS, []string{"udp://10.0.0.1:53"}) {
		t.Errorf("域名不在清单内时应命中本列表: %+v", d)
	}
}

// 取反列表的空清单保护：清单为空或未配置 DNS 时必须跳过，否则会退化成「命中一切」
func TestMatchDomainInvertEmptyListSkipped(t *testing.T) {
	t.Run("清单为空", func(t *testing.T) {
		mh := newTestMatcherHandler(t, []config.SplitList{{
			Name: "空清单", Enabled: true, Invert: true,
			DNS: []string{"udp://10.0.0.1:53"}, DomainFile: writeRuleFile(t), Refresh: time.Hour,
		}})
		if d := mh.MatchDomain("any.com"); d.Matched {
			t.Errorf("清单为空的取反列表不应命中: %+v", d)
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		mh := newTestMatcherHandler(t, []config.SplitList{{
			Name: "缺文件", Enabled: true, Invert: true,
			DNS:        []string{"udp://10.0.0.1:53"},
			DomainFile: filepath.Join(t.TempDir(), "missing.yaml"), Refresh: time.Hour,
		}})
		if d := mh.MatchDomain("any.com"); d.Matched {
			t.Errorf("清单未加载的取反列表不应命中: %+v", d)
		}
	})

	t.Run("未配置DNS", func(t *testing.T) {
		mh := newTestMatcherHandler(t, []config.SplitList{{
			Name: "无DNS", Enabled: true, Invert: true,
			DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,internal.example.com"), Refresh: time.Hour,
		}})
		if d := mh.MatchDomain("www.public.com"); d.Matched {
			t.Errorf("未配置 DNS 的取反列表不应命中: %+v", d)
		}
	})
}

// 相同域名命中多条列表时，按自上而下的优先级取第一条
func TestMatchDomainPriorityFollowsOrder(t *testing.T) {
	a := config.SplitList{Name: "A", Enabled: true, DNS: []string{"udp://10.0.0.1:53"},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,dup.example.com"), Refresh: time.Hour}
	b := config.SplitList{Name: "B", Enabled: true, DNS: []string{"udp://10.0.0.2:53"},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,dup.example.com"), Refresh: time.Hour}

	mh := newTestMatcherHandler(t, []config.SplitList{a, b})
	if d := mh.MatchDomain("x.dup.example.com"); !d.Matched || d.ListName != "A" {
		t.Fatalf("应按顺序命中第一条列表: %+v", d)
	}

	cfg := config.DefaultConfig()
	cfg.SplitLists = []config.SplitList{b, a}
	mh.UpdateConfig(cfg)

	d := mh.MatchDomain("x.dup.example.com")
	if !d.Matched || d.ListName != "B" || !slices.Equal(d.DNS, []string{"udp://10.0.0.2:53"}) {
		t.Errorf("调换顺序后应命中新的第一条: %+v", d)
	}
}

// 顺序变更后必须重建匹配器：每条列表仍要持有自己的规则与自己的 DNS（防止错配）
func TestUpdateConfigReorderKeepsRuleAndDNSAligned(t *testing.T) {
	a := config.SplitList{Name: "A", Enabled: true, DNS: []string{"udp://10.0.0.1:53"},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,a.example.com"), Refresh: time.Hour}
	b := config.SplitList{Name: "B", Enabled: true, DNS: []string{"udp://10.0.0.2:53"},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,b.example.com"), Refresh: time.Hour}

	mh := newTestMatcherHandler(t, []config.SplitList{a, b})

	cfg := config.DefaultConfig()
	cfg.SplitLists = []config.SplitList{b, a}
	mh.UpdateConfig(cfg)

	want := map[string]struct{ list, dns string }{
		"x.a.example.com": {"A", "udp://10.0.0.1:53"},
		"x.b.example.com": {"B", "udp://10.0.0.2:53"},
	}
	for domain, w := range want {
		d := mh.MatchDomain(domain)
		if !d.Matched || d.ListName != w.list || !slices.Equal(d.DNS, []string{w.dns}) {
			t.Errorf("%s 应命中 %s 且使用 %s，实际 %+v", domain, w.list, w.dns, d)
		}
	}
}

// 顺序不变时仅改 DNS，应原地热更新（不重建、不重载文件）
func TestUpdateConfigHotSwapsDNS(t *testing.T) {
	a := config.SplitList{Name: "A", Enabled: true, DNS: []string{"udp://10.0.0.1:53"},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,a.example.com"), Refresh: time.Hour}
	mh := newTestMatcherHandler(t, []config.SplitList{a})

	next := a
	next.DNS = []string{"udp://10.0.0.9:53", "https://1.1.1.1/dns-query"}
	cfg := config.DefaultConfig()
	cfg.SplitLists = []config.SplitList{next}
	mh.UpdateConfig(cfg)

	d := mh.MatchDomain("x.a.example.com")
	if !d.Matched || !slices.Equal(d.DNS, next.DNS) {
		t.Errorf("仅改 DNS 应热更新生效: %+v", d)
	}
}

// 重启判定必须与顺序无关，否则「排序」会被误判为需重启；结构性字段变更仍需重启
func TestSplitListsNeedRestartOrderIndependent(t *testing.T) {
	a := config.SplitList{Name: "A", Enabled: true, DomainFile: "a.yaml", Refresh: time.Hour}
	b := config.SplitList{Name: "B", Enabled: true, DomainFile: "b.yaml", Refresh: time.Hour}
	base := []config.SplitList{a, b}

	if splitListsNeedRestart(base, []config.SplitList{b, a}) {
		t.Error("仅调整顺序不应要求重启")
	}
	if splitListsNeedRestart(base, []config.SplitList{a, b}) {
		t.Error("无变化不应要求重启")
	}

	edit := func(f func(l *config.SplitList)) []config.SplitList {
		out := []config.SplitList{a, b}
		f(&out[1])
		return out
	}
	cases := map[string][]config.SplitList{
		"启用状态变更": edit(func(l *config.SplitList) { l.Enabled = false }),
		"刷新间隔变更": edit(func(l *config.SplitList) { l.Refresh = 2 * time.Hour }),
		"文件路径变更": edit(func(l *config.SplitList) { l.DomainFile = "c.yaml" }),
		"URL变更":  edit(func(l *config.SplitList) { l.DomainURL = "https://example.com/c.yaml" }),
		"名称变更":   edit(func(l *config.SplitList) { l.Name = "B2" }),
		"列表新增":   append(slices.Clone(base), config.SplitList{Name: "C", Enabled: true, DomainFile: "c.yaml", Refresh: time.Hour}),
	}
	for name, cur := range cases {
		if !splitListsNeedRestart(base, cur) {
			t.Errorf("%s 应要求重启", name)
		}
	}
}

// 路由变化（顺序/取反/DNS）必须清缓存；仅刷新间隔变化不影响路由
func TestSplitListsRoutingChanged(t *testing.T) {
	a := config.SplitList{Name: "A", Enabled: true, DNS: []string{"udp://10.0.0.1:53"}, DomainFile: "a.yaml", Refresh: time.Hour}
	b := config.SplitList{Name: "B", Enabled: true, DNS: []string{"udp://10.0.0.2:53"}, DomainFile: "b.yaml", Refresh: time.Hour}
	base := []config.SplitList{a, b}

	if splitListsRoutingChanged(base, slices.Clone(base)) {
		t.Error("无变化不应清缓存")
	}

	inv := a
	inv.Invert = true
	if !splitListsRoutingChanged(base, []config.SplitList{inv, b}) {
		t.Error("取反开关变更应清缓存")
	}
	if !splitListsRoutingChanged(base, []config.SplitList{b, a}) {
		t.Error("顺序变更应清缓存（旧结果按旧优先级写入）")
	}
	dnsChanged := a
	dnsChanged.DNS = []string{"udp://10.0.0.9:53"}
	if !splitListsRoutingChanged(base, []config.SplitList{dnsChanged, b}) {
		t.Error("DNS 变更应清缓存")
	}
	refreshed := a
	refreshed.Refresh = 2 * time.Hour
	if splitListsRoutingChanged(base, []config.SplitList{refreshed, b}) {
		t.Error("仅刷新间隔变更不应清缓存")
	}
	modeChanged := a
	modeChanged.DNSMode = config.DNSModeFailover
	if !splitListsRoutingChanged(base, []config.SplitList{modeChanged, b}) {
		t.Error("解析模式（竞速/串行）变更应清缓存")
	}
}

// 串行故障转移：前一台成功就不再查后一台（上游 QPS 不随 DNS 条数放大）
func TestQueryFailoverSerialSemantics(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)

	okResp := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		}}
		return m
	}

	first, second := "udp://10.0.0.1:53", "udp://10.0.0.2:53"

	t.Run("第一台成功则不查第二台", func(t *testing.T) {
		var firstCalls, secondCalls int32
		qo := NewSimpleModernOptimizer(logger, 2*time.Second)
		t.Cleanup(qo.Close)
		qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
			if server == first {
				atomic.AddInt32(&firstCalls, 1)
				time.Sleep(150 * time.Millisecond) // 慢但成功
				return okResp(), nil
			}
			atomic.AddInt32(&secondCalls, 1)
			return okResp(), nil
		}

		res := qo.QueryFailover(req, []string{first, second})
		if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Server != first {
			t.Fatalf("应使用第一台的响应: %+v", res.SuccessResult)
		}
		if n := atomic.LoadInt32(&firstCalls); n != 1 {
			t.Errorf("第一台应被查询 1 次，实际 %d 次", n)
		}
		if n := atomic.LoadInt32(&secondCalls); n != 0 {
			t.Errorf("第一台成功时不应查询第二台，实际查询 %d 次", n)
		}
	})

	t.Run("第一台失败才用第二台", func(t *testing.T) {
		var firstCalls, secondCalls int32
		qo := NewSimpleModernOptimizer(logger, 2*time.Second)
		t.Cleanup(qo.Close)
		qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
			if server == first {
				atomic.AddInt32(&firstCalls, 1)
				return nil, errors.New("mock query failed")
			}
			atomic.AddInt32(&secondCalls, 1)
			return okResp(), nil
		}

		res := qo.QueryFailover(req, []string{first, second})
		if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Server != second {
			t.Fatalf("第一台失败后应使用第二台的响应: %+v", res.SuccessResult)
		}
		if n := atomic.LoadInt32(&firstCalls); n != 1 {
			t.Errorf("第一台应被查询 1 次，实际 %d 次", n)
		}
		if n := atomic.LoadInt32(&secondCalls); n != 1 {
			t.Errorf("第二台应被查询 1 次，实际 %d 次", n)
		}
	})
}

// A/AAAA 路径：分流列表 DNS 全部不可达时，应回退 BackupDNS 而不是直接 SERVFAIL
func TestProcessQueryFallsBackToBackupDNS(t *testing.T) {
	backup := startFakeUpstream(t) // 兜底解析器

	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	cfg := config.DefaultConfig()
	cfg.Timeout = 1 * time.Second
	cfg.Upstream = []string{"udp://127.0.0.1:1"}
	cfg.BackupDNS = "udp://" + backup.addr
	cfg.SplitLists = []config.SplitList{{
		Name: "线路", Enabled: true,
		DNS:        []string{"udp://127.0.0.1:1"}, // 不可达
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,example.com"),
		Refresh:    time.Hour,
	}}

	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	optimizer := NewSimpleModernOptimizer(logger, cfg.Timeout)
	udpPool := NewUDPConnPool()
	t.Cleanup(func() {
		cm.Close()
		optimizer.Close()
		udpPool.Close()
	})

	h := &RefactoredHandler{
		config:         cfg,
		Logger:         logger,
		cacheManager:   cm,
		queryOptimizer: optimizer,
		udpConnPool:    udpPool,
	}
	mh := NewMatcherHandler(cfg, logger, h)
	h.matcherHandler = mh
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}

	h.processQuery(nopWriter{}, ecsQuery(1232, false), "a.example.com", dns.TypeA, "-")

	got := backup.lastRequest(t)
	if got == nil || len(got.Question) == 0 || got.Question[0].Name != "a.example.com." {
		t.Fatalf("BackupDNS 应收到原始查询，实际 %v", got)
	}
}

// startNegativeUpstream 启动一个对任何查询都返回 NXDOMAIN（含 SOA）的假上游
func startNegativeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	u := &fakeUpstream{addr: pc.LocalAddr().String()}
	u.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		u.mu.Lock()
		u.got = r
		u.mu.Unlock()

		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeNameError
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		}}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = u.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.srv.Shutdown() })
	return u
}

// capWriter 捕获处理器写回客户端的响应
type capWriter struct {
	nopWriter
	mu  sync.Mutex
	msg *dns.Msg
}

func (w *capWriter) WriteMsg(m *dns.Msg) error {
	w.mu.Lock()
	w.msg = m
	w.mu.Unlock()
	return nil
}

func (w *capWriter) get() *dns.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.msg
}

// NXDOMAIN 是终态有效答案（RFC 2308），不能被当成查询失败
func TestQueryTreatsNXDOMAINAsValidResult(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("nx.example.com.", dns.TypeA)

	negResp := func() *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Rcode = dns.RcodeNameError
		return m
	}

	t.Run("单台上游", func(t *testing.T) {
		qo := NewSimpleModernOptimizer(logger, 2*time.Second)
		t.Cleanup(qo.Close)
		qo.udpQueryFunc = func(_ *dns.Msg, _ string) (*dns.Msg, error) { return negResp(), nil }

		res := qo.Query(req, []string{"udp://10.0.0.1:53"})
		if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Response == nil {
			t.Fatalf("NXDOMAIN 应作为有效结果返回: %+v", res)
		}
		if res.SuccessResult.Response.Rcode != dns.RcodeNameError {
			t.Errorf("rcode 应为 NXDOMAIN，实际 %s", dns.RcodeToString[res.SuccessResult.Response.Rcode])
		}
	})

	t.Run("串行模式", func(t *testing.T) {
		var secondCalls int32
		qo := NewSimpleModernOptimizer(logger, 2*time.Second)
		t.Cleanup(qo.Close)
		qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
			if server != "udp://10.0.0.1:53" {
				atomic.AddInt32(&secondCalls, 1)
			}
			return negResp(), nil
		}

		res := qo.QueryFailover(req, []string{"udp://10.0.0.1:53", "udp://10.0.0.2:53"})
		if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Response.Rcode != dns.RcodeNameError {
			t.Fatalf("串行模式应把 NXDOMAIN 作为终态返回: %+v", res.SuccessResult)
		}
		if n := atomic.LoadInt32(&secondCalls); n != 0 {
			t.Errorf("NXDOMAIN 已是终态，不应再查下一台，实际 %d 次", n)
		}
	})
}

// 竞速模式下收到 NXDOMAIN 应立即收尾，不等慢台上游超时
func TestQueryRaceReturnsNXDOMAINWithoutWaiting(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("nx.example.com.", dns.TypeA)

	fast, slow := "udp://10.0.0.2:53", "udp://10.0.0.1:53"
	qo := NewSimpleModernOptimizer(logger, 2*time.Second)
	t.Cleanup(qo.Close)
	qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
		if server == slow {
			time.Sleep(1500 * time.Millisecond) // 慢台：收尾若等它，耗时必然超过 1.5s
			return nil, errors.New("mock timeout")
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Rcode = dns.RcodeNameError
		return m, nil
	}

	start := time.Now()
	res := qo.Query(req, []string{slow, fast})
	elapsed := time.Since(start)

	if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Response.Rcode != dns.RcodeNameError {
		t.Fatalf("应返回 NXDOMAIN: %+v", res.SuccessResult)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("收到 NXDOMAIN 后应立即返回，实际耗时 %v", elapsed)
	}
}

// 竞速模式下收到 NOERROR 空应答（NODATA）也应立即收尾，不等慢台上游超时。
// 回归：海外权威对不存在的子域常返回 NODATA，旧逻辑既不满足“有 Answer”也不是 NXDOMAIN，
// 会一直挂到 modern_timeout（线上曾把境外域名查询拖满 3s）。
func TestQueryRaceReturnsNODATAWithoutWaiting(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	req := new(dns.Msg)
	req.SetQuestion("nodata.example.com.", dns.TypeAAAA)

	fast, slow := "udp://10.0.0.2:53", "udp://10.0.0.1:53"
	qo := NewSimpleModernOptimizer(logger, 2*time.Second)
	t.Cleanup(qo.Close)
	qo.udpQueryFunc = func(_ *dns.Msg, server string) (*dns.Msg, error) {
		if server == slow {
			time.Sleep(1500 * time.Millisecond) // 慢台：收尾若等它，耗时必然超过 1.5s
			return nil, errors.New("mock timeout")
		}
		m := new(dns.Msg)
		m.SetReply(req) // Rcode=NOERROR 且无 Answer，即 NODATA
		return m, nil
	}

	start := time.Now()
	res := qo.Query(req, []string{slow, fast})
	elapsed := time.Since(start)

	if !res.HasSuccess || res.SuccessResult == nil || res.SuccessResult.Response == nil {
		t.Fatalf("NODATA 应作为终态结果返回: %+v", res)
	}
	if res.SuccessResult.Response.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode 应为 NOERROR，实际 %s", dns.RcodeToString[res.SuccessResult.Response.Rcode])
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("收到 NODATA 后应立即返回，实际耗时 %v", elapsed)
	}
}

// A/AAAA 路径：上游返回 NXDOMAIN 时原样返回，不得回退 BackupDNS（否则会被劫持成垃圾IP）
func TestProcessQueryNXDOMAINDoesNotFallbackToBackup(t *testing.T) {
	neg := startNegativeUpstream(t)
	backup := startFakeUpstream(t)

	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	cfg := config.DefaultConfig()
	cfg.Timeout = 1 * time.Second
	cfg.Upstream = []string{"udp://" + neg.addr}
	cfg.BackupDNS = "udp://" + backup.addr
	cfg.SplitLists = []config.SplitList{{
		Name: "线路", Enabled: true,
		DNS:        []string{"udp://" + neg.addr},
		DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,example.com"),
		Refresh:    time.Hour,
	}}

	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	optimizer := NewSimpleModernOptimizer(logger, cfg.Timeout)
	udpPool := NewUDPConnPool()
	t.Cleanup(func() {
		cm.Close()
		optimizer.Close()
		udpPool.Close()
	})

	h := &RefactoredHandler{
		config:         cfg,
		Logger:         logger,
		cacheManager:   cm,
		queryOptimizer: optimizer,
		udpConnPool:    udpPool,
	}
	mh := NewMatcherHandler(cfg, logger, h)
	h.matcherHandler = mh
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}

	w := &capWriter{}
	h.processQuery(w, ecsQuery(1232, false), "a.example.com", dns.TypeA, "-")

	got := w.get()
	if got == nil {
		t.Fatal("客户端应收到响应")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("应原样返回 NXDOMAIN，实际 %s", dns.RcodeToString[got.Rcode])
	}

	backup.mu.Lock()
	backupGot := backup.got
	backup.mu.Unlock()
	if backupGot != nil {
		t.Error("NXDOMAIN 是终态答案，不应回退 BackupDNS")
	}
}
