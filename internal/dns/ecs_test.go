package dns

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

func netipMustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("解析前缀 %q 失败: %v", s, err)
	}
	return p
}

// findECS 取出报文 OPT 中的 ECS option
func findECS(m *dns.Msg) *dns.EDNS0_SUBNET {
	if m == nil {
		return nil
	}
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if s, ok := o.(*dns.EDNS0_SUBNET); ok {
			return s
		}
	}
	return nil
}

// ecsQuery 构造测试请求：size=0 表示不带 OPT
func ecsQuery(size uint16, do bool, extras ...dns.EDNS0) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	if size == 0 {
		return m
	}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(size)
	if do {
		opt.SetDo()
	}
	opt.Option = extras
	m.Extra = append(m.Extra, opt)
	return m
}

// clientECS 构造客户端自带的 ECS option
func clientECS(ip string, mask uint8) *dns.EDNS0_SUBNET {
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: mask,
		Address:       net.ParseIP(ip),
	}
}

func TestApplyECS(t *testing.T) {
	injectV4 := netipMustPrefix(t, "1.2.3.0/24")

	nsid := func() *dns.EDNS0_NSID { return &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "aabb"} }

	cases := []struct {
		name        string
		msg         *dns.Msg
		inject      *netip.Prefix
		wantOpt     bool
		wantUDPSize uint16
		wantDO      bool
		wantMask    uint8  // 期望 ECS 的 SourceNetmask，0 表示不应有 ECS
		wantAddr    string // 期望 ECS 的地址
	}{
		{"无OPT且不注入", ecsQuery(0, false), nil, false, 0, false, 0, ""},
		{"无OPT且注入", ecsQuery(0, false), &injectV4, true, ecsDefaultUDPSize, false, 24, "1.2.3.0"},
		{"有OPT带ECS且不注入", ecsQuery(4096, true, clientECS("203.0.113.0", 24)), nil, true, 4096, true, 0, ""},
		{"有OPT带ECS且注入", ecsQuery(1232, false, clientECS("203.0.113.0", 24)), &injectV4, true, 1232, false, 24, "1.2.3.0"},
		{"有OPT无ECS且不注入", ecsQuery(512, true), nil, true, 512, true, 0, ""},
		{"有OPT无ECS且注入", ecsQuery(512, true), &injectV4, true, 512, true, 24, "1.2.3.0"},
		{"其余option保留", ecsQuery(4096, false, nsid()), &injectV4, true, 4096, false, 24, "1.2.3.0"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			applyECS(c.msg, c.inject)

			opt := c.msg.IsEdns0()
			if !c.wantOpt {
				if opt != nil {
					t.Fatalf("不应存在 OPT，实际 %v", opt)
				}
				return
			}
			if opt == nil {
				t.Fatal("应保留/新建 OPT")
			}
			if opt.UDPSize() != c.wantUDPSize {
				t.Errorf("UDP payload size 应为 %d，实际 %d", c.wantUDPSize, opt.UDPSize())
			}
			if opt.Do() != c.wantDO {
				t.Errorf("DO 位应为 %v，实际 %v", c.wantDO, opt.Do())
			}

			subnet := findECS(c.msg)
			if c.wantMask == 0 {
				if subnet != nil {
					t.Errorf("不应注入/保留 ECS，实际 %v", subnet)
				}
			} else {
				if subnet == nil {
					t.Fatal("应注入 ECS")
				}
				if subnet.Family != 1 || subnet.SourceNetmask != c.wantMask {
					t.Errorf("ECS 应为 family=1 mask=%d，实际 family=%d mask=%d", c.wantMask, subnet.Family, subnet.SourceNetmask)
				}
				if subnet.Address.String() != c.wantAddr {
					t.Errorf("ECS 地址应为 %s，实际 %s", c.wantAddr, subnet.Address)
				}
			}

			// 其余 option（NSID）不能被误删
			if c.name == "其余option保留" && len(opt.Option) != 2 {
				t.Errorf("应保留 NSID 与 ECS 共2个 option，实际 %d 个", len(opt.Option))
			}
		})
	}
}

// 注入的 ECS 必须真的出现在打包后的报文中（等价于抓包断言）
func TestApplyECSWireFormat(t *testing.T) {
	inject := netipMustPrefix(t, "1.2.3.0/24")
	req := ecsQuery(4096, true, clientECS("203.0.113.0", 24))
	applyECS(req, &inject)

	wire, err := req.Pack()
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	got := new(dns.Msg)
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("解包失败: %v", err)
	}

	subnet := findECS(got)
	if subnet == nil {
		t.Fatal("打包后的报文缺少 ECS")
	}
	if subnet.Family != 1 || subnet.SourceNetmask != 24 || subnet.Address.String() != "1.2.3.0" {
		t.Errorf("ECS 取值不符: family=%d mask=%d addr=%s", subnet.Family, subnet.SourceNetmask, subnet.Address)
	}
	opt := got.IsEdns0()
	if opt == nil || opt.UDPSize() != 4096 || !opt.Do() {
		t.Errorf("客户端 OPT 属性丢失: %v", opt)
	}
}

// 未命中分流列表时不做任何 ECS 干预（原样透传，含客户端自带 ECS）
func TestApplySplitECSNotMatched(t *testing.T) {
	req := ecsQuery(1232, false, clientECS("203.0.113.0", 24))
	got := applySplitECS(req, SplitDecision{})
	if got != req {
		t.Error("未命中分流列表时应原样返回原请求")
	}
	if findECS(got) == nil {
		t.Error("未命中分流列表时应透传客户端自带 ECS")
	}
}

// 命中分流列表且未开启 ECS 时：剥离客户端 ECS，且不污染原请求（req 会被缓存与 single-flight 复用）
func TestApplySplitECSStripsClientECSOnCopy(t *testing.T) {
	req := ecsQuery(1232, false, clientECS("203.0.113.0", 24))
	got := applySplitECS(req, SplitDecision{Matched: true})
	if got == req {
		t.Fatal("应返回副本，避免并发污染原请求")
	}
	if findECS(got) != nil {
		t.Error("副本应已剥离客户端 ECS")
	}
	if findECS(req) == nil {
		t.Error("原请求不应被修改")
	}
	if opt := got.IsEdns0(); opt == nil || opt.UDPSize() != 1232 {
		t.Errorf("副本应保留客户端 UDP payload size: %v", opt)
	}
}

// fakeUpstream 记录收到的请求并返回一条 A 记录
type fakeUpstream struct {
	addr string
	srv  *dns.Server
	mu   sync.Mutex
	got  *dns.Msg
}

func startFakeUpstream(t *testing.T) *fakeUpstream {
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
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		}}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = u.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.srv.Shutdown() })
	return u
}

func (u *fakeUpstream) lastRequest(t *testing.T) *dns.Msg {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.got == nil {
		t.Fatal("上游未收到任何请求")
	}
	return u.got
}

// newSplitListTestHandler 构造仅含分流列表所需组件的最小处理器（上游为本地假服务器）
func newSplitListTestHandler(t *testing.T, upstreamAddr string, ecs config.ECSPolicy) (*RefactoredHandler, *MatcherHandler) {
	t.Helper()

	// 组件构造会写 ./logs，切到临时目录避免污染仓库
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	ruleFile := filepath.Join(t.TempDir(), "split.yaml")
	if err := os.WriteFile(ruleFile, []byte("payload:\n  - DOMAIN-SUFFIX,test.example.com\n"), 0o644); err != nil {
		t.Fatalf("写入规则文件失败: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.Upstream = []string{"udp://" + upstreamAddr} // 全局上游（本用例不应走到这里）
	cfg.SplitLists = []config.SplitList{{
		Name:       "线路测试",
		Enabled:    true,
		DNS:        []string{upstreamAddr}, // 传统优化器直接使用 host:port
		DomainFile: ruleFile,
		Refresh:    time.Hour,
		ECS:        ecs,
	}}

	logger := utils.NewEnhancedLogger("error", "test", false)
	cm := NewCacheManager(cfg, logger)
	optimizer := NewFastQueryOptimizer(logger, nil, cfg.Timeout)
	t.Cleanup(func() {
		cm.Close()
		optimizer.Close()
	})

	h := &RefactoredHandler{
		config:         cfg,
		Logger:         logger,
		cacheManager:   cm,
		queryOptimizer: optimizer,
	}
	mh := NewMatcherHandler(cfg, logger, h)
	h.matcherHandler = mh
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}
	return h, mh
}

// 查询路径：命中分流列表且开启 ECS 时，发往上游的报文应带本地 ECS，并剥离客户端自带 ECS
func TestProcessQueryInjectsSplitListECS(t *testing.T) {
	up := startFakeUpstream(t)
	h, _ := newSplitListTestHandler(t, up.addr, config.ECSPolicy{
		Enabled: true, ISPType: config.ECSTypeTelecom, Subnet: "1.2.3.4",
	})

	req := ecsQuery(4096, true, clientECS("203.0.113.0", 24))
	h.processQuery(nopWriter{}, req, "a.test.example.com", dns.TypeA, "-")

	got := up.lastRequest(t)
	subnet := findECS(got)
	if subnet == nil {
		t.Fatal("上游报文缺少 ECS")
	}
	if subnet.Family != 1 || subnet.SourceNetmask != 24 || subnet.Address.String() != "1.2.3.0" {
		t.Errorf("ECS 应被替换为本地配置: family=%d mask=%d addr=%s", subnet.Family, subnet.SourceNetmask, subnet.Address)
	}
	if opt := got.IsEdns0(); opt == nil || opt.UDPSize() != 4096 || !opt.Do() {
		t.Errorf("客户端通告的 UDP payload size 与 DO 位应保留: %v", opt)
	}
}

// 查询路径：命中分流列表但 ECS 未开启时，客户端自带 ECS 应被剥离（“不打开不传”）
func TestProcessQueryStripsClientECSWhenDisabled(t *testing.T) {
	up := startFakeUpstream(t)
	h, _ := newSplitListTestHandler(t, up.addr, config.ECSPolicy{})

	req := ecsQuery(1232, false, clientECS("203.0.113.0", 24))
	h.processQuery(nopWriter{}, req, "a.test.example.com", dns.TypeA, "-")

	if findECS(up.lastRequest(t)) != nil {
		t.Error("ECS 未开启时上游报文不应带 ECS")
	}
}

// 异步刷新是第二条查询链路：自建请求同样要带上列表 ECS，否则会静默覆盖带 ECS 的缓存
func TestRefreshRecordInjectsSplitListECS(t *testing.T) {
	up := startFakeUpstream(t)
	h, mh := newSplitListTestHandler(t, up.addr, config.ECSPolicy{
		Enabled: true, ISPType: config.ECSTypeMobile, Subnet: "240e:1:2::/32",
	})

	rh := NewRefreshHandler(h.config, h.Logger, h.cacheManager, NewCloudDetector(h.Logger, nil),
		h.queryOptimizer, mh, h.proxyQuery, nil)

	if err := rh.RefreshDNSRecord("a.test.example.com", dns.TypeA); err != nil {
		t.Fatalf("异步刷新失败: %v", err)
	}

	subnet := findECS(up.lastRequest(t))
	if subnet == nil {
		t.Fatal("异步刷新发往上游的报文缺少 ECS")
	}
	if subnet.Family != 2 || subnet.SourceNetmask != 32 || subnet.Address.String() != "240e:1::" {
		t.Errorf("ECS 取值不符: family=%d mask=%d addr=%s", subnet.Family, subnet.SourceNetmask, subnet.Address)
	}
}
