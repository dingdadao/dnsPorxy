package dns

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// chdirTemp 把工作目录切到临时目录（logger/缓存构造会写 ./logs），测试结束还原
func chdirTemp(t *testing.T) {
	t.Helper()
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })
}

// 接口文本解析：取首个字段中 "#" 之前、去掉端口号的 IPv4，按需截断并去重
func TestParseReplaceAPIIPs(t *testing.T) {
	body := "104.24.64.153:443#联通CF_LAX 184.45ms 14.78MB/s\n" +
		"104.18.23.247:443#联通CF_LAX 188.32ms 13.02MB/s\n" +
		"104.16.53.117:443#联通CF_LAX 187.84ms 12.99MB/s\n" +
		"104.24.64.153:443#重复 190ms 1MB/s\n" +
		"\n" +
		"2606:4700::1:443#IPv6忽略 1ms 1MB/s\n" +
		"not-an-ip:443#无效 1ms 1MB/s\n"

	for _, c := range []struct {
		name  string
		limit int
		want  []string
	}{
		{"默认取第一条", 0, []string{"104.24.64.153"}},
		{"取前两条", 2, []string{"104.24.64.153", "104.18.23.247"}},
		{"去重后取三条", 5, []string{"104.24.64.153", "104.18.23.247", "104.16.53.117"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := parseReplaceAPIIPs(body, c.limit)
			if len(got) != len(c.want) {
				t.Fatalf("解析出 %d 个 IP，期望 %d 个：%v", len(got), len(c.want), got)
			}
			for i, want := range c.want {
				if got[i].String() != want {
					t.Errorf("第 %d 个 IP = %s，期望 %s", i, got[i], want)
				}
			}
		})
	}

	if got := parseReplaceAPIIPs("", 1); got != nil {
		t.Errorf("空响应应解析不出 IP，实际 %v", got)
	}
}

// newReplaceAPIServer 启动固定返回 body 的假接口，并返回累计请求数读取函数
func newReplaceAPIServer(t *testing.T, body string) (string, func() int) {
	t.Helper()
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}
}

// 缓存有效期内不再请求接口
func TestReplaceAPIClientUsesCache(t *testing.T) {
	chdirTemp(t)
	url, hits := newReplaceAPIServer(t, "104.24.64.153:443#a 1ms 1MB/s\n104.18.23.247:443#b 2ms 2MB/s\n")
	c := NewReplaceAPIClient(url, 1, time.Minute, utils.NewEnhancedLogger("error", "test", false))

	ips, err := c.IPs()
	if err != nil {
		t.Fatalf("首次取数失败: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "104.24.64.153" {
		t.Fatalf("应取第一条 104.24.64.153，实际 %v", ips)
	}

	if _, err := c.IPs(); err != nil {
		t.Fatalf("二次取数失败: %v", err)
	}
	if n := hits(); n != 1 {
		t.Errorf("缓存有效期内不应重复请求接口，实际请求 %d 次", n)
	}
}

// 缓存过期：先返回旧值，后台异步刷新（查询路径不被 HTTP 阻塞）
func TestReplaceAPIClientPrefetchesWhenStale(t *testing.T) {
	chdirTemp(t)
	url, hits := newReplaceAPIServer(t, "104.24.64.153:443#a 1ms 1MB/s\n")
	c := NewReplaceAPIClient(url, 1, 20*time.Millisecond, utils.NewEnhancedLogger("error", "test", false))

	if _, err := c.IPs(); err != nil {
		t.Fatalf("首次取数失败: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // 让缓存过期
	ips, err := c.IPs()
	if err != nil {
		t.Fatalf("过期后取数应返回旧值而非报错: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("过期后仍应返回旧值，实际 %v", ips)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hits() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := hits(); n < 2 {
		t.Errorf("过期后应触发后台刷新，实际仅请求 %d 次", n)
	}
}

// 接口取数失败且无缓存时返回错误
func TestReplaceAPIClientFetchFailure(t *testing.T) {
	chdirTemp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := NewReplaceAPIClient(srv.URL, 1, time.Minute, utils.NewEnhancedLogger("error", "test", false))
	if _, err := c.IPs(); err == nil {
		t.Fatal("接口非 200 时应返回错误")
	}
}

// CF 配置接口后，替换 IP 直接来自接口，不再解析替换域名
func TestResolveReplaceIPsFromAPI(t *testing.T) {
	chdirTemp(t)
	url, _ := newReplaceAPIServer(t, "104.24.64.153:443#a 1ms 1MB/s\n104.18.23.247:443#b 2ms 2MB/s\n")

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceCFAPI = url
	cfg.ReplaceAPICount = 2
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	// 替换域名解析被禁用：一旦走了 DNS 路径即失败，确保结果来自接口
	proxy := func(*dns.Msg, []string) (*dns.Msg, error) {
		return nil, errors.New("不应走替换域名解析")
	}
	ch := NewCloudHandler(cfg, logger, cm, nil, proxy, func(dns.ResponseWriter, *dns.Msg, *dns.Msg) {})

	rc := ReplaceConfig{CFDomain: cfg.ReplaceCFDomain, CFAPI: cfg.ReplaceCFAPI, APICount: cfg.ReplaceAPICount}

	v4, v6, err := ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare), rc)
	if err != nil {
		t.Fatalf("A 查询失败: %v", err)
	}
	if len(v4) != 2 || v4[0].A.String() != "104.24.64.153" || v4[1].A.String() != "104.18.23.247" {
		t.Fatalf("应按配置取接口前两条，实际 %v", v4)
	}
	if len(v6) != 0 {
		t.Errorf("接口不提供 IPv6，实际 %v", v6)
	}

	// 接口只有 IPv4：AAAA 查询不返回替换 IP，交由上层按无 v6 替换处理
	v4, v6, err = ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeAAAA, int(CloudTypeCloudflare), rc)
	if err != nil {
		t.Fatalf("AAAA 查询失败: %v", err)
	}
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("AAAA 查询不应返回替换 IP，实际 v4=%v v6=%v", v4, v6)
	}
}

// 接口不可用时回退替换域名解析（保持云替换可用）
func TestResolveReplaceIPsFallsBackToDomainWhenAPIFails(t *testing.T) {
	chdirTemp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cfg := config.DefaultConfig()
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceCFAPI = srv.URL
	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	t.Cleanup(cm.Close)

	proxy := func(req *dns.Msg, _ []string) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(req)
		r.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("104.16.1.1"),
		}}
		return r, nil
	}
	ch := NewCloudHandler(cfg, logger, cm, nil, proxy, func(dns.ResponseWriter, *dns.Msg, *dns.Msg) {})

	v4, _, err := ch.ResolveReplaceIPs(0, "cloud.example.com", dns.TypeA, int(CloudTypeCloudflare),
		ReplaceConfig{CFDomain: cfg.ReplaceCFDomain, CFAPI: cfg.ReplaceCFAPI, APICount: cfg.ReplaceAPICount})
	if err != nil {
		t.Fatalf("接口失败应回退替换域名解析，实际报错: %v", err)
	}
	if len(v4) != 1 || v4[0].A.String() != "104.16.1.1" {
		t.Fatalf("应回退到替换域名的 A 记录，实际 %v", v4)
	}
}
