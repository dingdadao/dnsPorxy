package dns

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// simUpstream 模拟上游 DNS：
//   - cloud.example.com A → 真实 CF IP（172.64.5.5，用于触发云检测）
//   - cf.example.com  A → 按请求携带的 ECS 返回不同线路的「优选 IP」
//
// 这样就复现了真实场景：同一个替换域名在不同线路上解析出不同结果。
type simUpstream struct {
	addr string
	srv  *dns.Server

	mu          sync.Mutex
	ecsOnCloud  []string // cloud.example.com 收到的 ECS
	ecsOnRepl   []string // cf.example.com 收到的 ECS
	replaceHits int
}

func startSimUpstream(t *testing.T) *simUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	u := &simUpstream{addr: pc.LocalAddr().String()}
	u.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)

		name := ""
		if len(r.Question) > 0 {
			name = dns.Fqdn(r.Question[0].Name)
		}
		ecs := findSubnet(r)
		ecsDesc := "none"
		if ecs != nil {
			ecsDesc = fmt.Sprintf("%s/%d", ecs.Address.String(), ecs.SourceNetmask)
		}

		switch name {
		case "cloud.example.com.":
			u.mu.Lock()
			u.ecsOnCloud = append(u.ecsOnCloud, ecsDesc)
			u.mu.Unlock()
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("172.64.5.5"), // Cloudflare 网段
			}}
		case "cf.example.com.":
			u.mu.Lock()
			u.ecsOnRepl = append(u.ecsOnRepl, ecsDesc)
			u.replaceHits++
			u.mu.Unlock()
			ip := "9.9.9.9" // 未带 ECS 时的兜底（不该被两条线路拿到）
			if ecs != nil {
				switch ecs.Address.String() {
				case "1.2.3.0":
					ip = "104.16.1.1" // 电信线路就近
				case "2.2.2.0":
					ip = "104.16.9.9" // 联通线路就近
				}
			}
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			}}
		default:
			resp.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = u.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.srv.Shutdown() })
	return u
}

func (u *simUpstream) stats() (cloudECS, replECS []string, hits int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.ecsOnCloud...), append([]string(nil), u.ecsOnRepl...), u.replaceHits
}

// captureWriter 复用 ip_prefer_test.go 中的定义（捕获最终写给客户端的响应）

// 端到端模拟：电信客户端与联通客户端查询同一个云域名，替换域名按各自 ECS 解析，
// 两条线路拿到各自就近的替换 IP，且缓存互不污染。
func TestSimulateTwoLinesCloudReplacement(t *testing.T) {
	up := startSimUpstream(t)

	// 云网段文件：只放 CF 段，让 172.64.5.5 被识别为 Cloudflare
	netFile := filepath.Join(t.TempDir(), "cf_v4.txt")
	if err := os.WriteFile(netFile, []byte("172.64.0.0/13\n"), 0o644); err != nil {
		t.Fatalf("写入网段文件失败: %v", err)
	}

	chdirTemp(t) // 组件会写 ./logs

	cfg := config.DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.ModernTimeout = 2 * time.Second
	cfg.Upstream = []string{"udp://" + up.addr}
	cfg.BackupDNS = ""
	cfg.EnableCloudflareCheck = true
	cfg.EnableAWSCheck = false
	cfg.ReplaceCFDomain = "cf.example.com"
	cfg.ReplaceAWSDomain = ""
	cfg.ReplaceCFAPI = ""
	cfg.ReplaceCacheTime = 0
	cfg.CloudflareNetFile = netFile
	cfg.CloudflareNetFile6 = ""
	cfg.AWSNetFile = ""
	cfg.SourceEnabled = false
	cfg.SplitLists = nil
	// 两条线路：各自兜底上游 + 各自的 ECS
	cfg.ISPGroups = []config.ISPGroup{
		{
			ISP: config.ISPGroupTelecom, Enabled: true,
			FallbackDNS: []string{"udp://" + up.addr},
			ECS:         config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeTelecom, Subnet: "1.2.3.4"},
		},
		{
			ISP: config.ISPGroupUnicom, Enabled: true,
			FallbackDNS: []string{"udp://" + up.addr},
			ECS:         config.ECSPolicy{Enabled: true, ISPType: config.ECSTypeUnicom, Subnet: "2.2.2.4"},
		},
	}
	cfg.CustomGroups = nil

	logger := utils.NewEnhancedLogger("error", "test", false)
	h, err := NewRefactoredHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("构建处理器失败: %v", err)
	}
	t.Cleanup(h.Close)

	if err := h.cloudDetector.LoadNetworkRanges(netFile, "", ""); err != nil {
		t.Fatalf("加载云网段失败: %v", err)
	}

	query := func(scope string) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("cloud.example.com.", dns.TypeA)
		w := &captureWriter{}
		h.processQuery(w, req, "cloud.example.com", dns.TypeA, scope)
		if w.msg == nil {
			t.Fatalf("线路 %s 未写出响应", scope)
		}
		return w.msg
	}
	ipOf := func(m *dns.Msg) string {
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				return a.A.String()
			}
		}
		return ""
	}

	// 1. 电信客户端
	tel := query(string(config.ISPGroupTelecom))
	if got := ipOf(tel); got != "104.16.1.1" {
		t.Errorf("电信客户端应替换为 104.16.1.1，实际 %s（应答 %v）", got, tel.Answer)
	}

	// 2. 联通客户端（同一云域名、同一替换域名）
	uni := query(string(config.ISPGroupUnicom))
	if got := ipOf(uni); got != "104.16.9.9" {
		t.Errorf("联通客户端应替换为 104.16.9.9，实际 %s（应答 %v）", got, uni.Answer)
	}

	// 3. 电信客户端再来一次：命中本线路云响应缓存，不能被联通覆盖
	tel2 := query(string(config.ISPGroupTelecom))
	if got := ipOf(tel2); got != "104.16.1.1" {
		t.Errorf("电信客户端重复查询应仍为 104.16.1.1，实际 %s（缓存串味）", got)
	}

	// 4. 上游视角：主查询与替换域名都带上了各线路 ECS，且替换域名每线路只回源一次
	cloudECS, replECS, hits := up.stats()
	t.Logf("主查询收到 ECS: %v", cloudECS)
	t.Logf("替换域名收到 ECS: %v（回源 %d 次）", replECS, hits)

	wantCloud := map[string]bool{"1.2.3.0/24": true, "2.2.2.0/24": true}
	for _, e := range cloudECS {
		delete(wantCloud, e)
	}
	if len(wantCloud) != 0 {
		t.Errorf("主查询应分别携带两条线路的 ECS，缺少 %v（实际 %v）", wantCloud, cloudECS)
	}
	if len(replECS) != 2 || replECS[0] != "1.2.3.0/24" || replECS[1] != "2.2.2.0/24" {
		t.Errorf("替换域名应按线路各回源一次并携带对应 ECS，实际 %v", replECS)
	}
	if hits != 2 {
		t.Errorf("替换域名应只回源 2 次（每线路一次），实际 %d 次", hits)
	}
}
