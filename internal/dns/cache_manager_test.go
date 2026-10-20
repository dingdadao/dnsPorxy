package dns

import (
	"net"
	"os"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// newTestCacheManager 构造测试用缓存管理器
// logger构造会写./logs目录，chdir到临时目录避免污染仓库
func newTestCacheManager(t *testing.T) *CacheManager {
	t.Helper()
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	logger := utils.NewEnhancedLogger("error", "test", false)
	return NewCacheManager(config.DefaultConfig(), logger)
}

// TestCacheManagerCloseSafety 关闭安全性回归：
// 重复Close、关闭后提交任务都不得panic。
// 旧实现 Close() 中 close(cm.asyncChan) 会导致 worker 从已关闭channel读到nil任务，
// 在 processAsyncTask 空指针崩溃；对已关闭channel提交任务同样panic。
func TestCacheManagerCloseSafety(t *testing.T) {
	cm := newTestCacheManager(t)

	cm.Close()
	cm.Close() // 重复关闭必须安全

	cm.submitAsyncRefresh("close-test.example.com", dns.TypeA, time.Now().Add(time.Minute), 0)
	cm.submitOnDemandRefresh("close-test2.example.com", dns.TypeA)
}

// negRespWithSOA 构造含 SOA（Authority 段）的 NXDOMAIN 响应，用于验证负缓存
func negRespWithSOA(qname string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}}
	return m
}

// TestCacheManagerNegativeCaching 非成功响应的缓存策略（对齐 AdGuard Home / RFC 2308）
func TestCacheManagerNegativeCaching(t *testing.T) {
	cm := newTestCacheManager(t)

	// 1) 无 SOA 的 NXDOMAIN：不缓存
	req := new(dns.Msg)
	req.SetQuestion("nx-nosoa.example.com.", dns.TypeA)
	bare := new(dns.Msg)
	bare.SetRcode(req, dns.RcodeNameError)
	cm.SetScoped("-", "nx-nosoa.example.com", dns.TypeA, bare, false)
	if _, hit, _, _ := cm.cache.Get("-", "nx-nosoa.example.com", dns.TypeA); hit {
		t.Fatalf("无 SOA 的 NXDOMAIN 不应缓存")
	}

	// 2) 含 SOA 的 NXDOMAIN：负缓存（两个入口都要生效）
	cm.SetScoped("-", "nx.example.com", dns.TypeA, negRespWithSOA("nx.example.com."), false)
	if _, hit, _, _ := cm.cache.Get("-", "nx.example.com", dns.TypeA); !hit {
		t.Fatalf("含 SOA 的 NXDOMAIN 应被负缓存")
	}
	cm.SetWithTTLScoped("-", "nx2.example.com", dns.TypeA, negRespWithSOA("nx2.example.com."), false, time.Minute)
	if _, hit, _, _ := cm.cache.Get("-", "nx2.example.com", dns.TypeA); !hit {
		t.Fatalf("SetWithTTLScoped 同样应负缓存含 SOA 的 NXDOMAIN")
	}

	// 3) SERVFAIL：短缓存 15s（对齐 AGH，上限下调为 15s）
	sreq := new(dns.Msg)
	sreq.SetQuestion("fail.example.com.", dns.TypeA)
	sf := new(dns.Msg)
	sf.SetRcode(sreq, dns.RcodeServerFailure)
	sf.Ns = negRespWithSOA("fail.example.com.").Ns
	cm.SetScoped("-", "fail.example.com", dns.TypeA, sf, false)
	if _, hit, _, _ := cm.cache.Get("-", "fail.example.com", dns.TypeA); !hit {
		t.Fatalf("SERVFAIL 应被短缓存")
	}
	if e := entryOf(cm.cache, "-", "fail.example.com", dns.TypeA); e == nil {
		t.Fatalf("SERVFAIL 条目应存在")
	} else if d := time.Until(e.ExpireAt); d <= 0 || d > servFailCacheTTL+2*time.Second {
		t.Fatalf("SERVFAIL 缓存时长应约为 15s, got %v", d)
	}
}

// TestCacheManagerCachesSuccessResponse 成功响应仍应正常写入缓存（回归）
func TestCacheManagerCachesSuccessResponse(t *testing.T) {
	cm := newTestCacheManager(t)

	req := new(dns.Msg)
	req.SetQuestion("ok.example.com.", dns.TypeA)
	ok := new(dns.Msg)
	ok.SetReply(req)
	ok.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ok.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	}}

	cm.SetScoped("-", "ok.example.com", dns.TypeA, ok, false)
	if _, hit, _, _ := cm.cache.Get("-", "ok.example.com", dns.TypeA); !hit {
		t.Fatalf("成功响应应被缓存")
	}
}
