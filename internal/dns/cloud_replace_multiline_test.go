package dns

import (
	"net"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// 登记多替换域名后，全局替换域名与各分组覆写域名都应跳过云检测自检（含去点/trim/空值）
func TestSetReplaceDomainsAll(t *testing.T) {
	logger := utils.NewEnhancedLogger("error", "test", false)
	cd := NewCloudDetector(logger, nil)
	cd.SetReplaceDomainsAll([]string{"cf.example.com.", " cm.aws.example ", "", "   "})

	for _, d := range []string{"cf.example.com", "cf.example.com.", "cm.aws.example"} {
		if !cd.IsReplaceDomain(d) {
			t.Errorf("%q 应被识别为替换域名", d)
		}
	}
	for _, d := range []string{"other.example.com", "cm.example.com"} {
		if cd.IsReplaceDomain(d) {
			t.Errorf("%q 不应被识别为替换域名", d)
		}
	}

	// 兼容旧接口：单独设置的兜底替换域名同样生效
	cd.SetReplaceDomains("global.cf.example", "global.aws.example")
	if !cd.IsReplaceDomain("global.cf.example") || !cd.IsReplaceDomain("global.aws.example") {
		t.Error("SetReplaceDomains 设置的域名也应被识别为替换域名")
	}
}

// 接口客户端按 (url,count) 多实例创建并复用；配置移除覆写后清理不再使用的客户端
func TestWarmReplaceAPIsMultiLine(t *testing.T) {
	chdirTemp(t)
	globalURL, _ := newReplaceAPIServer(t, "104.16.1.1:443#g 1ms 1MB/s\n")
	cmURL, _ := newReplaceAPIServer(t, "104.24.64.153:443#cm 1ms 1MB/s\n")

	cfg := config.DefaultConfig()
	cfg.ReplaceCFAPI = globalURL
	cfg.ReplaceAPICount = 1
	cfg.ISPGroups = []config.ISPGroup{{
		ISP: config.ISPGroupCMCC, Enabled: true, FallbackDNS: []string{"udp://223.5.5.5:53"},
		CloudReplace: config.CloudReplacePolicy{Override: true, CFAPI: cmURL, APICount: 2},
	}}
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	ch := NewCloudHandler(cfg, logger, cm, nil, nil, func(dns.ResponseWriter, *dns.Msg, *dns.Msg) {})

	global := ch.apiClientFor(globalURL, 1)
	cmClient := ch.apiClientFor(cmURL, 2)
	if global == nil || cmClient == nil || global == cmClient {
		t.Fatalf("不同 (url,count) 应拿到不同客户端: global=%p cm=%p", global, cmClient)
	}
	if again := ch.apiClientFor(cmURL, 2); again != cmClient {
		t.Error("相同 (url,count) 应复用同一客户端")
	}
	if other := ch.apiClientFor(cmURL, 3); other == cmClient {
		t.Error("count 不同应视为不同客户端")
	}

	// 移除覆写后：分组接口客户端被清理，全局客户端保留
	next := *cfg
	next.ISPGroups = nil
	ch.WarmReplaceAPIs(&next)

	ch.apiMu.RLock()
	_, staleKept := ch.apiClients[replaceAPIKey(cmURL, 2)]
	_, globalKept := ch.apiClients[replaceAPIKey(globalURL, 1)]
	ch.apiMu.RUnlock()
	if staleKept {
		t.Error("覆写移除后应清理不再使用的接口客户端")
	}
	if !globalKept {
		t.Error("全局接口客户端应保留")
	}
}

// 有效替换目标决定取哪个接口：全局线路用全局接口，覆写线路用分组接口
func TestResolveReplaceIPsUsesPerGroupAPI(t *testing.T) {
	chdirTemp(t)
	globalURL, _ := newReplaceAPIServer(t, "104.16.1.1:443#g 1ms 1MB/s\n")
	cmURL, _ := newReplaceAPIServer(t, "104.24.64.153:443#cm 1ms 1MB/s\n")

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceCFAPI = globalURL
	cfg.ReplaceAPICount = 1
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)
	ch := NewCloudHandler(cfg, logger, cm, nil, nil, func(dns.ResponseWriter, *dns.Msg, *dns.Msg) {})

	v4, _, err := ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare),
		ReplaceConfig{CFDomain: "cf.example.com", CFAPI: globalURL, APICount: 1})
	if err != nil || len(v4) != 1 || v4[0].A.String() != "104.16.1.1" {
		t.Fatalf("全局线路应取全局接口 IP，实际 v4=%v err=%v", v4, err)
	}

	v4, _, err = ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare),
		ReplaceConfig{CFDomain: "cm.cf.example", CFAPI: cmURL, APICount: 1})
	if err != nil || len(v4) != 1 || v4[0].A.String() != "104.24.64.153" {
		t.Fatalf("覆写线路应取分组接口 IP，实际 v4=%v err=%v", v4, err)
	}
}

// 云替换响应缓存按 scope 隔离：不同线路互不串味，未写入的 scope 不命中
func TestCloudResponseCacheScopeIsolation(t *testing.T) {
	chdirTemp(t)
	cfg := config.DefaultConfig()
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	const domain = "cloud.example.com"
	mk := func(ip string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		}}
		return m
	}

	cm.SetCloudResponseScoped(string(config.ISPGroupCMCC), domain, dns.TypeA, mk("1.1.1.1"), int(CloudTypeCloudflare), time.Minute)
	cm.SetCloudResponseScoped(string(config.ISPGroupTelecom), domain, dns.TypeA, mk("2.2.2.2"), int(CloudTypeCloudflare), time.Minute)

	gotCM, okCM, _ := cm.GetCloudResponseScoped(string(config.ISPGroupCMCC), domain, dns.TypeA)
	gotTC, okTC, _ := cm.GetCloudResponseScoped(string(config.ISPGroupTelecom), domain, dns.TypeA)
	if !okCM || !okTC {
		t.Fatalf("两个 scope 都应命中缓存: cm=%v tc=%v", okCM, okTC)
	}
	if len(gotCM.Answer) != 1 || len(gotTC.Answer) != 1 {
		t.Fatalf("缓存应答记录数异常: cm=%v tc=%v", gotCM.Answer, gotTC.Answer)
	}
	if gotCM.Answer[0].(*dns.A).A.String() != "1.1.1.1" || gotTC.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("不同 scope 缓存应互相隔离: cm=%v tc=%v", gotCM.Answer, gotTC.Answer)
	}
	if _, ok, _ := cm.GetCloudResponseScoped(string(config.ISPGroupUnicom), domain, dns.TypeA); ok {
		t.Error("未写入的 scope 不应命中缓存")
	}
}

// 分组路由变更检测必须覆盖云替换覆写（改覆写目标需清缓存，避免旧线路缓存串味）
func TestClientGroupsRoutingChangedIncludesCloudReplace(t *testing.T) {
	base := config.DefaultConfig()
	base.ISPGroups = []config.ISPGroup{{
		ISP: config.ISPGroupCMCC, Enabled: true, FallbackDNS: []string{"udp://223.5.5.5:53"},
		CloudReplace: config.CloudReplacePolicy{Override: true, CFDomain: "cm.cf.example"},
	}}

	same := *base
	same.ISPGroups = append([]config.ISPGroup(nil), base.ISPGroups...)
	if clientGroupsRoutingChanged(base, &same) {
		t.Error("无变化不应判定为路由变更")
	}

	changed := *base
	changed.ISPGroups = append([]config.ISPGroup(nil), base.ISPGroups...)
	changed.ISPGroups[0].CloudReplace = config.CloudReplacePolicy{Override: true, CFDomain: "cm2.cf.example"}
	if !clientGroupsRoutingChanged(base, &changed) {
		t.Error("云替换覆写目标变更应判定为路由变更（需清缓存）")
	}

	toggled := *base
	toggled.ISPGroups = append([]config.ISPGroup(nil), base.ISPGroups...)
	toggled.ISPGroups[0].CloudReplace = config.CloudReplacePolicy{}
	if !clientGroupsRoutingChanged(base, &toggled) {
		t.Error("覆写开关变更应判定为路由变更")
	}
}
