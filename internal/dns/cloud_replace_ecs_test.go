package dns

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// newReplaceECSTestHandler 构造只走「替换域名 DNS 解析」路径的最小 CloudHandler，
// proxy 记录每一次发往上游的请求，便于断言第二跳的 ECS 语义。
func newReplaceECSTestHandler(t *testing.T, replaceDomain string, proxy func(*dns.Msg, []string) (*dns.Msg, error)) *CloudHandler {
	t.Helper()
	chdirTemp(t)

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = replaceDomain
	cfg.ReplaceCacheTime = 0
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	return NewCloudHandler(cfg, logger, cm, nil, proxy, func(dns.ResponseWriter, *dns.Msg, *dns.Msg) {})
}

// answerA 返回一条指向 ip 的 A 应答
func answerA(req *dns.Msg, ip string) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(req)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	}}
	return r
}

// 云替换的替换域名回源必须带上分流列表的预设 ECS，并剥离客户端自带 ECS
// —— 否则替换域名会按代理出口位置解析，返回与客户端线路不匹配的 IP。
func TestReplaceDomainQueryInjectsSplitListECS(t *testing.T) {
	var got *dns.Msg
	ch := newReplaceECSTestHandler(t, "cf.example.com", func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		got = req.Copy()
		return answerA(req, "104.16.1.1"), nil
	})

	// 客户端自带 203.0.113.0/24，且通告了 4096/UDP 与 DO 位
	clientReq := ecsQuery(4096, true, clientECS("203.0.113.0", 24))
	route := SplitDecision{
		Matched: true,
		ECS:     config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeTelecom, Subnet: "1.2.3.4"},
	}

	if _, _, err := ch.ResolveReplaceIPs(clientReq.Id, "cloud.example.com", dns.TypeA,
		int(CloudTypeCloudflare), ReplaceConfig{CFDomain: "cf.example.com"}, clientReq,
		ReplaceContext{Scope: string(config.ISPGroupTelecom), Route: route}); err != nil {
		t.Fatalf("替换域名解析失败: %v", err)
	}

	if got == nil {
		t.Fatal("替换域名未发起上游查询")
	}
	subnet := findECS(got)
	if subnet == nil {
		t.Fatal("替换域名回源缺少 ECS：替换结果会按代理出口位置解析")
	}
	if subnet.Family != 1 || subnet.SourceNetmask != 24 || subnet.Address.String() != "1.2.3.0" {
		t.Errorf("ECS 应为列表预设 1.2.3.0/24，实际 family=%d mask=%d addr=%s",
			subnet.Family, subnet.SourceNetmask, subnet.Address)
	}
	// 客户端的 EDNS 属性要保留，避免上游截断/DNSSEC 行为变化
	if opt := got.IsEdns0(); opt == nil || opt.UDPSize() != 4096 || !opt.Do() {
		t.Errorf("客户端 UDP payload size 与 DO 位应被继承: %v", opt)
	}
}

// 命中分流列表但未开启 ECS 时：替换域名回源同样不携带 ECS（“不打开不传”）
func TestReplaceDomainQueryStripsClientECSWhenDisabled(t *testing.T) {
	var got *dns.Msg
	ch := newReplaceECSTestHandler(t, "cf.example.com", func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		got = req.Copy()
		return answerA(req, "104.16.1.1"), nil
	})

	clientReq := ecsQuery(1232, false, clientECS("203.0.113.0", 24))
	route := SplitDecision{Matched: true} // ECS 未开启

	if _, _, err := ch.ResolveReplaceIPs(clientReq.Id, "cloud.example.com", dns.TypeA,
		int(CloudTypeCloudflare), ReplaceConfig{CFDomain: "cf.example.com"}, clientReq,
		ReplaceContext{Scope: "-", Route: route}); err != nil {
		t.Fatalf("替换域名解析失败: %v", err)
	}
	if findECS(got) != nil {
		t.Error("ECS 未开启时替换域名回源不应携带 ECS")
	}
}

// 未命中任何分流列表时：替换域名回源应透传客户端自带 ECS（与主查询一致）
func TestReplaceDomainQueryPassesClientECSWhenNotMatched(t *testing.T) {
	var got *dns.Msg
	ch := newReplaceECSTestHandler(t, "cf.example.com", func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		got = req.Copy()
		return answerA(req, "104.16.1.1"), nil
	})

	clientReq := ecsQuery(1232, false, clientECS("203.0.113.0", 24))

	if _, _, err := ch.ResolveReplaceIPs(clientReq.Id, "cloud.example.com", dns.TypeA,
		int(CloudTypeCloudflare), ReplaceConfig{CFDomain: "cf.example.com"}, clientReq,
		ReplaceContext{Scope: "-"}); err != nil {
		t.Fatalf("替换域名解析失败: %v", err)
	}
	subnet := findECS(got)
	if subnet == nil {
		t.Fatal("未命中分流列表时应透传客户端自带 ECS")
	}
	if subnet.Address.String() != "203.0.113.0" || subnet.SourceNetmask != 24 {
		t.Errorf("应透传客户端 ECS 203.0.113.0/24，实际 %s/%d", subnet.Address, subnet.SourceNetmask)
	}
}

// ECS 生效时替换域名缓存必须按线路隔离：不同线路各自回源，互不串味；
// 同一线路重复查询命中缓存，不放大上游请求。
func TestReplaceDomainCacheScopedByLine(t *testing.T) {
	calls := 0
	ch := newReplaceECSTestHandler(t, "cf.example.com", func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		calls++
		// 按 ECS 返回不同 IP，模拟 CDN 按线路调度
		ip := "104.16.1.1"
		if s := findECS(req); s != nil && s.Address.String() == "2.2.2.0" {
			ip = "104.16.9.9"
		}
		return answerA(req, ip), nil
	})

	resolve := func(scope string, subnet string) string {
		clientReq := ecsQuery(1232, false, clientECS(subnet, 24))
		route := SplitDecision{
			Matched: true,
			ECS:     config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeTelecom, Subnet: subnet},
		}
		v4, _, err := ch.ResolveReplaceIPs(clientReq.Id, "cloud.example.com", dns.TypeA,
			int(CloudTypeCloudflare), ReplaceConfig{CFDomain: "cf.example.com"}, clientReq,
			ReplaceContext{Scope: scope, Route: route})
		if err != nil || len(v4) == 0 {
			t.Fatalf("线路 %s 解析失败: v4=%v err=%v", scope, v4, err)
		}
		return v4[0].A.String()
	}

	if ip := resolve(string(config.ISPGroupTelecom), "1.2.3.4"); ip != "104.16.1.1" {
		t.Fatalf("电信线路应拿到 104.16.1.1，实际 %s", ip)
	}
	if calls != 1 {
		t.Fatalf("首次查询应回源 1 次，实际 %d 次", calls)
	}

	// 同线路重复查询：命中缓存
	resolve(string(config.ISPGroupTelecom), "1.2.3.4")
	if calls != 1 {
		t.Errorf("同线路重复查询应命中缓存，实际回源 %d 次", calls)
	}

	// 另一条线路：必须各自回源，且拿到本线路的 IP
	if ip := resolve(string(config.ISPGroupUnicom), "2.2.2.4"); ip != "104.16.9.9" {
		t.Errorf("联通线路应拿到 104.16.9.9，实际 %s（缓存串味）", ip)
	}
	if calls != 2 {
		t.Errorf("不同线路应各自回源，实际回源 %d 次", calls)
	}
}

// 替换域名必须走「进来那条线路」自己的上游：移动线路查移动 DNS、电信线路查电信 DNS，
// 各自拿到本线路的替换 IP（客户端经 CDN 进来时，线路由真实客户端 IP 决定，与代理出口无关）。
func TestReplaceDomainQueryUsesLineUpstreams(t *testing.T) {
	type call struct {
		upstream string
		mode     string
	}
	var mu sync.Mutex
	var calls []call

	ch := newReplaceECSTestHandler(t, "cf.example.com", func(*dns.Msg, []string) (*dns.Msg, error) {
		return nil, errors.New("替换域名不应走全局上游")
	})
	ch.queryWithMode = func(req *dns.Msg, upstreams []string, mode string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		calls = append(calls, call{upstream: upstreams[0], mode: mode})
		mu.Unlock()
		// 模拟按线路调度的权威：移动 DNS 返回移动就近 IP，电信 DNS 返回电信就近 IP
		ip := "104.16.1.1"
		if upstreams[0] == "219.141.136.10:53" {
			ip = "104.16.9.9"
		}
		return answerA(req, ip), nil
	}

	resolve := func(scope, upstream, mode string) string {
		v4, _, err := ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare),
			ReplaceConfig{CFDomain: "cf.example.com"}, nil,
			ReplaceContext{Scope: scope, Upstreams: []string{upstream}, DNSMode: mode})
		if err != nil || len(v4) == 0 {
			t.Fatalf("线路 %s 替换域名解析失败: v4=%v err=%v", scope, v4, err)
		}
		return v4[0].A.String()
	}

	cmcc := resolve(string(config.ISPGroupCMCC), "223.5.5.5:53", config.DNSModeFailover)
	telecom := resolve(string(config.ISPGroupTelecom), "219.141.136.10:53", config.DNSModeFailover)

	if cmcc != "104.16.1.1" {
		t.Errorf("移动线路应拿到移动就近替换 IP 104.16.1.1，实际 %s", cmcc)
	}
	if telecom != "104.16.9.9" {
		t.Errorf("电信线路应拿到电信就近替换 IP 104.16.9.9，实际 %s", telecom)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("两条线路应各回源一次，实际 %d 次", len(calls))
	}
	if calls[0].upstream != "223.5.5.5:53" || calls[1].upstream != "219.141.136.10:53" {
		t.Errorf("替换域名应使用各线路自己的上游，实际 %+v", calls)
	}
	for _, c := range calls {
		if c.mode != config.DNSModeFailover {
			t.Errorf("替换域名应沿用主查询的解析模式 failover，实际 %q", c.mode)
		}
	}
}

// 未指定线路上游时回退全局上游（保持老行为，异步刷新等无线路场景依赖此路径）
func TestReplaceDomainQueryFallsBackToGlobalUpstream(t *testing.T) {
	var used []string
	ch := newReplaceECSTestHandler(t, "cf.example.com", func(req *dns.Msg, upstreams []string) (*dns.Msg, error) {
		used = append([]string(nil), upstreams...)
		return answerA(req, "104.16.1.1"), nil
	})

	if _, _, err := ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare),
		ReplaceConfig{CFDomain: "cf.example.com"}, nil, ReplaceContext{Scope: "-"}); err != nil {
		t.Fatalf("替换域名解析失败: %v", err)
	}
	if len(used) == 0 {
		t.Fatal("替换域名未发起上游查询")
	}
	cfgUpstream := ch.getConfig().Upstream
	if len(used) != len(cfgUpstream) || used[0] != cfgUpstream[0] {
		t.Errorf("未指定线路上游时应回退全局上游 %v，实际 %v", cfgUpstream, used)
	}
}

// 同一替换域名在不同线路上解析出不同 IP（geo-DNS）时，替换必须各按本线路走，
// 且替换域名缓存与云响应缓存互不污染——即「一个联通客户端、一个移动客户端，
// 查同一个替换域名拿到不同结果」的场景。
func TestCloudReplacementPerLineSameReplaceDomain(t *testing.T) {
	chdirTemp(t)

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceCacheTime = 0
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	// 替换域名按 ECS 返回不同线路的就近 IP
	calls := 0
	proxy := func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		calls++
		ip := "104.16.1.1" // 移动线路的就近 IP
		if s := findECS(req); s != nil && s.Address.String() == "2.2.2.0" {
			ip = "104.16.9.9" // 联通线路的就近 IP
		}
		return answerA(req, ip), nil
	}

	var written *dns.Msg
	ch := NewCloudHandler(cfg, logger, cm, nil, proxy,
		func(_ dns.ResponseWriter, _ *dns.Msg, resp *dns.Msg) { written = resp.Copy() })

	// 上游原始应答：真实 CF IP，待替换
	originalResp := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("cloud.example.com.", dns.TypeA)
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "cloud.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("172.64.0.1"),
		}}
		return r
	}

	replaceFor := func(scope, ecsSubnet string) string {
		req := ecsQuery(1232, false, clientECS("203.0.113.0", 24))
		req.Question[0].Name = "cloud.example.com."
		route := SplitDecision{
			Matched: true,
			ECS:     config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeTelecom, Subnet: ecsSubnet},
		}
		if _, err := ch.HandleCloudReplacement(nopWriter{}, req, "cloud.example.com", dns.TypeA,
			int(CloudTypeCloudflare), originalResp(), "",
			ReplaceConfig{CFDomain: "cf.example.com"},
			ReplaceContext{Scope: scope, Route: route}); err != nil {
			t.Fatalf("线路 %s 替换失败: %v", scope, err)
		}
		if written == nil || len(written.Answer) == 0 {
			t.Fatalf("线路 %s 未写出替换结果", scope)
		}
		a, ok := written.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("线路 %s 应答首条不是 A 记录: %v", scope, written.Answer[0])
		}
		return a.A.String()
	}

	if ip := replaceFor(string(config.ISPGroupCMCC), "1.2.3.4"); ip != "104.16.1.1" {
		t.Errorf("移动客户端应替换为移动就近 IP 104.16.1.1，实际 %s", ip)
	}
	if ip := replaceFor(string(config.ISPGroupUnicom), "2.2.2.4"); ip != "104.16.9.9" {
		t.Errorf("联通客户端应替换为联通就近 IP 104.16.9.9，实际 %s", ip)
	}
	// 回头再查移动：必须仍拿到移动的 IP（替换域名缓存按线路隔离，未被联通覆盖）
	if ip := replaceFor(string(config.ISPGroupCMCC), "1.2.3.4"); ip != "104.16.1.1" {
		t.Errorf("移动线路重复查询应仍为 104.16.1.1，实际 %s（缓存串味）", ip)
	}
	if calls != 2 {
		t.Errorf("两条线路各回源一次即可（共 2 次），实际 %d 次", calls)
	}
}
