package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// wireCaptureWriter 捕获写出的字节，用于对比新旧两条响应出口
type wireCaptureWriter struct {
	network string
	msg     []byte // WriteMsg 打包后的字节
	raw     []byte // Write 直写的字节
}

func (c *wireCaptureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (c *wireCaptureWriter) RemoteAddr() net.Addr {
	if c.network == "tcp" {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *wireCaptureWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	c.msg = b
	return nil
}
func (c *wireCaptureWriter) Write(b []byte) (int, error) {
	c.raw = append([]byte(nil), b...)
	return len(b), nil
}
func (c *wireCaptureWriter) Close() error        { return nil }
func (c *wireCaptureWriter) TsigStatus() error   { return nil }
func (c *wireCaptureWriter) TsigTimersOnly(bool) {}
func (c *wireCaptureWriter) Hijack()             {}

// writeBytes 返回实际写入的字节（WriteMsg 或 Write）
func (c *wireCaptureWriter) writeBytes() []byte {
	if c.raw != nil {
		return c.raw
	}
	return c.msg
}

// wireTestResponse 构造带 CNAME + 多 A + AAAA + 非OPT额外记录、且上游 AD=1 的响应
func wireTestResponse(qname string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.AuthenticatedData = true // 上游 AD=1，出口必须清零

	target := "cf.example.net."
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target},
		&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(1, 2, 3, 4)},
		&dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IPv4(5, 6, 7, 8)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2400:cb00::1")},
	}
	// 非 OPT 的额外记录必须保留（OPT 由出口按请求回带）
	resp.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "extra.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(9, 9, 9, 9)},
	}
	return resp
}

// newWireTestCache 建缓存并写入一条被测响应，返回缓存与缓存键
func newWireTestCache(t *testing.T, qname string) (*OptimizedDNSCache, string) {
	t.Helper()
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	c := NewOptimizedDNSCache(4096, time.Minute)
	c.Set("-", domain, dns.TypeA, wireTestResponse(qname), false)
	return c, domain
}

// ageStoredAt 把条目的存储时间往前拨，构造稳定的 TTL 递减场景
func ageStoredAt(c *OptimizedDNSCache, scope, domain string, qtype uint16, age time.Duration) {
	key := c.key(scope, domain, qtype)
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if e, ok := shard.store[key]; ok {
		e.StoredAt = time.Now().Add(-age)
	}
}

// TestBuildWireScanMeta 校验预打包与扫描出的补丁元信息
func TestBuildWireScanMeta(t *testing.T) {
	qname := "Example.COM."
	data, meta := buildWire(wireTestResponse(qname))
	if !meta.ok {
		t.Fatalf("buildWire 应成功，meta.ok=false")
	}
	if data == nil {
		t.Fatalf("buildWire 应返回字节")
	}
	if meta.qnameOff != 12 {
		t.Errorf("qnameOff = %d, want 12", meta.qnameOff)
	}
	if want := len(qname) + 1; meta.qnameLen != want {
		t.Errorf("qnameLen = %d, want %d", meta.qnameLen, want)
	}
	// Answer(4) 无 OPT；Extra 中的非OPT记录保留
	if got, want := len(meta.ttls), 5; got != want {
		t.Errorf("ttls 数量 = %d, want %d", got, want)
	}
	if ar := binary.BigEndian.Uint16(data[10:12]); ar != 1 {
		t.Errorf("ARCOUNT = %d, want 1（OPT 应被剥离，仅保留额外A记录）", ar)
	}
	// Question 段 NAME 必须是可原地覆盖的完整 wire 编码
	gotName, end, err := dns.UnpackDomainName(data, meta.qnameOff)
	if err != nil || gotName != qname || end-meta.qnameOff != meta.qnameLen {
		t.Errorf("wire 中 Question 名 = (%q, %d), want (%q, %d)", gotName, end-meta.qnameOff, qname, meta.qnameLen)
	}
}

// TestBuildWireRejectsUnsupported 多问题响应不适合快路径，应判定为不支持
func TestBuildWireRejectsUnsupported(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	if data, meta := buildWire(m); meta.ok || data != nil {
		t.Fatalf("多问题响应应被拒绝，got ok=%v data=%v", meta.ok, data != nil)
	}

	if meta := scanWire([]byte{0, 1, 2}); meta.ok {
		t.Fatalf("过短报文应被拒绝")
	}
}

// TestScanWireRejectsCompressedQuestion Question 段带压缩指针时不可原地改写
func TestScanWireRejectsCompressedQuestion(t *testing.T) {
	m := new(dns.Msg)
	m.Response = true
	m.Question = []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	m.Compress = false
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// 手工把 Question NAME 首字节改成压缩指针（0xC00C）
	b[12] = 0xC0
	b[13] = 0x0C
	if meta := scanWire(b); meta.ok {
		t.Fatalf("Question 段压缩指针应被拒绝")
	}
}

// sectionFingerprint 段落指纹：域名大小写不敏感，其余字段严格一致
func sectionFingerprint(rrs []dns.RR) string {
	parts := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		parts = append(parts, strings.ToLower(rr.String()))
	}
	return strings.Join(parts, "\n")
}

// msgsEquivalent 比较两条报文的语义等价性，返回空串表示等价
func msgsEquivalent(a, b *dns.Msg) string {
	if a == nil || b == nil {
		if a != b {
			return "一方为 nil"
		}
		return ""
	}
	if a.MsgHdr != b.MsgHdr {
		return fmt.Sprintf("头部不一致: %+v != %+v", a.MsgHdr, b.MsgHdr)
	}
	if len(a.Question) != len(b.Question) {
		return fmt.Sprintf("Question 数不一致: %d != %d", len(a.Question), len(b.Question))
	}
	for i := range a.Question {
		qa, qb := a.Question[i], b.Question[i]
		if !strings.EqualFold(qa.Name, qb.Name) || qa.Qtype != qb.Qtype || qa.Qclass != qb.Qclass {
			return fmt.Sprintf("Question[%d] 不一致: %v != %v", i, qa, qb)
		}
	}
	pairs := []struct {
		label string
		x, y  []dns.RR
	}{
		{"Answer", a.Answer, b.Answer},
		{"Ns", a.Ns, b.Ns},
		{"Extra", a.Extra, b.Extra},
	}
	for _, p := range pairs {
		if len(p.x) != len(p.y) {
			return fmt.Sprintf("%s 数不一致: %d != %d", p.label, len(p.x), len(p.y))
		}
		if sectionFingerprint(p.x) != sectionFingerprint(p.y) {
			return fmt.Sprintf("%s 内容不一致:\n%s\n!=\n%s", p.label, sectionFingerprint(p.x), sectionFingerprint(p.y))
		}
	}
	oa, ob := a.IsEdns0(), b.IsEdns0()
	if (oa == nil) != (ob == nil) {
		return "EDNS OPT 存在性不一致"
	}
	if oa != nil && (oa.UDPSize() != ob.UDPSize() || oa.Do() != ob.Do()) {
		return fmt.Sprintf("OPT 不一致: (size %d, do %v) != (size %d, do %v)", oa.UDPSize(), oa.Do(), ob.UDPSize(), ob.Do())
	}
	return ""
}

// TestWireFastPathMatchesLegacy 快路径应与旧「Get 深拷贝 + 统一出口」保持语义一致。
// TCP 上旧路径不做 Truncate，字节应完全一致；UDP 上旧路径的 Truncate 会关闭压缩，
// 因此只要求语义一致且快路径不更大（压缩后就地改写）。
func TestWireFastPathMatchesLegacy(t *testing.T) {
	const qname = "Example.COM."

	cases := []struct {
		name       string
		network    string
		reqEDNS    bool
		udpSize    uint16
		do         bool
		wantDirect bool // 是否应命中直写快路径
	}{
		{name: "TCP无EDNS", network: "tcp", wantDirect: true},
		{name: "TCP带EDNS", network: "tcp", reqEDNS: true, udpSize: 1232, do: true, wantDirect: true},
		{name: "UDP无EDNS", network: "udp", wantDirect: true},
		{name: "UDP带EDNS4096", network: "udp", reqEDNS: true, udpSize: 4096, wantDirect: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cache, domain := newWireTestCache(t, qname)
			ageStoredAt(cache, "-", domain, dns.TypeA, 3500*time.Millisecond)

			s, ok := cache.GetServe("-", domain, dns.TypeA)
			if !ok {
				t.Fatalf("GetServe 应命中")
			}

			req := new(dns.Msg)
			req.SetQuestion(qname, dns.TypeA)
			req.Id = 0xBEEF
			if c.reqEDNS {
				req.SetEdns0(c.udpSize, c.do)
			}

			h := &RefactoredHandler{}

			// 旧路径参考：Get 深拷贝（含 TTL 递减）+ 统一响应出口
			refResp, hit, _, _ := cache.Get("-", domain, dns.TypeA)
			if !hit {
				t.Fatalf("旧路径应命中")
			}
			legacy := &wireCaptureWriter{network: c.network}
			h.writeResponse(legacy, req, refResp)

			// 新路径：优先直写预打包字节
			got := &wireCaptureWriter{network: c.network}
			h.serveCacheHit(got, req, s)

			direct := got.raw != nil
			if direct != c.wantDirect {
				t.Errorf("是否命中直写快路径 = %v, want %v", direct, c.wantDirect)
			}

			var want, now dns.Msg
			if err := want.Unpack(legacy.writeBytes()); err != nil {
				t.Fatalf("Unpack legacy: %v", err)
			}
			if err := now.Unpack(got.writeBytes()); err != nil {
				t.Fatalf("Unpack new: %v", err)
			}
			if diff := msgsEquivalent(&want, &now); diff != "" {
				t.Errorf("新旧报文语义不一致: %s\nlegacy(%d) = %x\nnew(%d)    = %x",
					diff, len(legacy.writeBytes()), legacy.writeBytes(),
					len(got.writeBytes()), got.writeBytes())
			}
			if c.network == "tcp" && !bytes.Equal(legacy.writeBytes(), got.writeBytes()) {
				t.Errorf("TCP 上字节应完全一致\nlegacy(%d) = %x\nnew(%d)    = %x",
					len(legacy.writeBytes()), legacy.writeBytes(),
					len(got.writeBytes()), got.writeBytes())
			}
			if len(got.writeBytes()) > len(legacy.writeBytes()) {
				t.Errorf("快路径响应不应更大: new=%d legacy=%d", len(got.writeBytes()), len(legacy.writeBytes()))
			}

			// 校验关键字段：ID、AD清零、TTL递减、EDNS回带
			out := got.writeBytes()
			if id := binary.BigEndian.Uint16(out[0:2]); id != req.Id {
				t.Errorf("响应 ID = %#x, want %#x", id, req.Id)
			}
			if out[3]&0x20 != 0 {
				t.Errorf("AD 位应为 0")
			}
			if len(now.Answer) != 4 {
				t.Fatalf("Answer 数 = %d, want 4", len(now.Answer))
			}
			if gotTTL := now.Answer[1].Header().Ttl; gotTTL != 297 {
				t.Errorf("TTL 递减错误：= %d, want 297", gotTTL)
			}
			if gotTTL := now.Answer[3].Header().Ttl; gotTTL != 57 {
				t.Errorf("TTL 递减错误：= %d, want 57", gotTTL)
			}
			if o := now.IsEdns0(); c.reqEDNS {
				if o == nil {
					t.Errorf("应回带 EDNS OPT")
				} else if o.UDPSize() != c.udpSize || o.Do() != c.do {
					t.Errorf("OPT = (size %d, do %v), want (%d, %v)", o.UDPSize(), o.Do(), c.udpSize, c.do)
				}
			} else if o != nil {
				t.Errorf("无 EDNS 请求不应回带 OPT")
			}
			if len(now.Extra) == 0 {
				t.Errorf("非OPT额外记录应被保留")
			}
		})
	}
}

// TestWireFastPathPreservesClientCase 客户端QNAME大小写不同时，题面必须按客户端原样回写
func TestWireFastPathPreservesClientCase(t *testing.T) {
	const stored = "Example.COM."
	const client = "eXAMPLE.cOm."

	cache, domain := newWireTestCache(t, stored)
	s, ok := cache.GetServe("-", domain, dns.TypeA)
	if !ok {
		t.Fatalf("GetServe 应命中")
	}

	req := new(dns.Msg)
	req.SetQuestion(client, dns.TypeA)

	h := &RefactoredHandler{}
	w := &wireCaptureWriter{network: "tcp"}
	h.serveCacheHit(w, req, s)

	if w.raw == nil {
		t.Fatalf("应命中直写快路径")
	}
	var decoded dns.Msg
	if err := decoded.Unpack(w.raw); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if decoded.Question[0].Name != client {
		t.Errorf("Question = %q, want %q（保留客户端大小写）", decoded.Question[0].Name, client)
	}
	// 答案仍需可解析且内容一致（大小写不敏感）
	if len(decoded.Answer) != 4 {
		t.Fatalf("Answer 数 = %d, want 4", len(decoded.Answer))
	}
	if !strings.EqualFold(decoded.Answer[0].Header().Name, stored) {
		t.Errorf("CNAME owner = %q, want %q", decoded.Answer[0].Header().Name, stored)
	}
}

// TestServeCacheHitFallsBackOnTruncation UDP 超出通告报文大小时必须回退旧路径截断
func TestServeCacheHitFallsBackOnTruncation(t *testing.T) {
	qname := "big.example.com."
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := 0; i < 40; i++ {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(10, 0, byte(i), 1),
		})
	}

	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, resp, false)

	s, ok := cache.GetServe("-", domain, dns.TypeA)
	if !ok {
		t.Fatalf("GetServe 应命中")
	}

	req2 := new(dns.Msg)
	req2.SetQuestion(qname, dns.TypeA)
	req2.Id = 0x1111

	h := &RefactoredHandler{}
	got := &wireCaptureWriter{network: "udp"}
	h.serveCacheHit(got, req2, s)

	if got.raw != nil {
		t.Fatalf("超长响应不应走直写快路径（需回退以按 UDP 截断）")
	}

	refResp, hit, _, _ := cache.Get("-", domain, dns.TypeA)
	if !hit {
		t.Fatalf("旧路径应命中")
	}
	legacy := &wireCaptureWriter{network: "udp"}
	h.writeResponse(legacy, req2, refResp)
	if !bytes.Equal(legacy.writeBytes(), got.writeBytes()) {
		t.Errorf("回退路径与旧路径字节不一致")
	}

	var decoded dns.Msg
	if err := decoded.Unpack(got.writeBytes()); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !decoded.Truncated {
		t.Errorf("超长响应应置 TC=1")
	}
}

// TestGetServeRejections 云条目/过期/无预打包字节时必须回退旧路径
func TestGetServeRejections(t *testing.T) {
	domain := "cloud.example.com"

	t.Run("云条目", func(t *testing.T) {
		c := NewOptimizedDNSCache(4096, time.Minute)
		c.Set("-", domain, dns.TypeA, nil, true, int(CloudTypeCloudflare))
		if _, ok := c.GetServe("-", domain, dns.TypeA); ok {
			t.Errorf("云标记条目不应走快路径")
		}
	})

	t.Run("过期", func(t *testing.T) {
		c, d := newWireTestCache(t, domain+".")
		key := c.key("-", d, dns.TypeA)
		shard := c.getShard(key)
		shard.mu.Lock()
		shard.store[key].ExpireAt = time.Now().Add(-time.Second)
		shard.mu.Unlock()
		if _, ok := c.GetServe("-", d, dns.TypeA); ok {
			t.Errorf("过期条目应回退旧路径（含陈旧TTL调整与按需刷新）")
		}
	})

	t.Run("无预打包字节", func(t *testing.T) {
		c, d := newWireTestCache(t, domain+".")
		key := c.key("-", d, dns.TypeA)
		shard := c.getShard(key)
		shard.mu.Lock()
		shard.store[key].wire = nil
		shard.store[key].wmeta = wireMeta{}
		shard.mu.Unlock()
		if _, ok := c.GetServe("-", d, dns.TypeA); ok {
			t.Errorf("无预打包字节应回退旧路径")
		}
	})
}

// TestWriteResponseWireRejectsBadQuestion QNAME 编码长度不匹配时应回退
func TestWriteResponseWireRejectsBadQuestion(t *testing.T) {
	cache, domain := newWireTestCache(t, "Example.COM.")
	s, ok := cache.GetServe("-", domain, dns.TypeA)
	if !ok {
		t.Fatalf("GetServe 应命中")
	}

	req := new(dns.Msg)
	req.SetQuestion("other-longer-name.example.org.", dns.TypeA)

	h := &RefactoredHandler{}
	w := &wireCaptureWriter{network: "tcp"}
	if h.writeResponseWire(w, req, s) {
		t.Fatalf("QNAME 长度不匹配时应返回 false")
	}
	if w.raw != nil || w.msg != nil {
		t.Fatalf("拒绝时不应写出任何字节")
	}
}

// TestWirePooledBufferNotShared 复用的缓冲不得把上一条响应的内容泄漏到后续响应
func TestWirePooledBufferNotShared(t *testing.T) {
	cache, domain := newWireTestCache(t, "Example.COM.")
	s, ok := cache.GetServe("-", domain, dns.TypeA)
	if !ok {
		t.Fatalf("GetServe 应命中")
	}

	h := &RefactoredHandler{}
	var first []byte
	for i := 0; i < 3; i++ {
		req := new(dns.Msg)
		req.SetQuestion("Example.COM.", dns.TypeA)
		req.Id = uint16(0x100 + i)
		w := &wireCaptureWriter{network: "tcp"}
		h.serveCacheHit(w, req, s)
		if i == 0 {
			first = append([]byte(nil), w.writeBytes()...)
			continue
		}
		// 仅 ID 不同，其余字节必须完全一致
		if len(w.writeBytes()) != len(first) {
			t.Fatalf("第 %d 次长度 = %d, want %d", i, len(w.writeBytes()), len(first))
		}
		for j := 2; j < len(first); j++ {
			if w.writeBytes()[j] != first[j] {
				t.Fatalf("第 %d 次字节 %d 不一致：%x != %x", i, j, w.writeBytes()[j], first[j])
			}
		}
	}
}

// entryOf 取出条目快照（仅用于测试断言）
func entryOf(c *OptimizedDNSCache, scope, domain string, qtype uint16) *CacheEntry {
	key := c.key(scope, domain, qtype)
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	return shard.store[key]
}

// TestNormalEntryKeepsNoObjectTree 普通条目应只保留预打包字节，不再持有 dns.Msg 对象树
func TestNormalEntryKeepsNoObjectTree(t *testing.T) {
	cache, domain := newWireTestCache(t, "Example.COM.")
	e := entryOf(cache, "-", domain, dns.TypeA)
	if e == nil {
		t.Fatalf("条目应存在")
	}
	if e.Response != nil {
		t.Errorf("普通条目不应保留对象树，got %+v", e.Response)
	}
	if len(e.wire) == 0 || !e.wmeta.ok {
		t.Fatalf("普通条目应保留可用的预打包字节")
	}
	if e.rcode != dns.RcodeSuccess || e.answerCount != 4 || e.ipv4Count != 2 || e.ipv6Count != 1 {
		t.Errorf("预计算字段不符: rcode=%d answerCount=%d v4=%d v6=%d",
			e.rcode, e.answerCount, e.ipv4Count, e.ipv6Count)
	}
	if e.answers == "" {
		t.Errorf("answersSummary 应预计算")
	}

	// 旧路径 Get 仍需能从字节重建出等价响应
	resp, hit, _, _ := cache.Get("-", domain, dns.TypeA)
	if !hit || resp == nil || len(resp.Answer) != 4 {
		t.Fatalf("Get 应从预打包字节重建响应，hit=%v answers=%d", hit, len(resp.Answer))
	}
}

// TestExpiredFromWireReturnsStale 过期成功响应在宽限内必须仍能返回陈旧内容（TTL 调整为 5s）
func TestExpiredFromWireReturnsStale(t *testing.T) {
	cache, domain := newWireTestCache(t, "Example.COM.")
	cache.SetStaleTTL(time.Hour) // 开启过期宽限（serve-stale）
	key := cache.key("-", domain, dns.TypeA)
	shard := cache.getShard(key)
	shard.mu.Lock()
	shard.store[key].ExpireAt = time.Now().Add(-time.Second)
	shard.mu.Unlock()

	resp, hit, _, _ := cache.Get("-", domain, dns.TypeA)
	if !hit || resp == nil {
		t.Fatalf("过期成功响应应返回陈旧内容，hit=%v", hit)
	}
	if got := resp.Answer[1].Header().Ttl; got != 5 {
		t.Errorf("过期响应 TTL = %d, want 5", got)
	}
}

// TestExpiredNXDOMAINFromWireIsMiss NXDOMAIN 过期后应返回未命中并删除条目
func TestExpiredNXDOMAINFromWireIsMiss(t *testing.T) {
	domain := "nx.example.com."
	req := new(dns.Msg)
	req.SetQuestion(domain, dns.TypeA)
	neg := new(dns.Msg)
	neg.SetRcode(req, dns.RcodeNameError)

	c := NewOptimizedDNSCache(4096, time.Minute)
	c.Set("-", "nx.example.com", dns.TypeA, neg, false)
	key := c.key("-", "nx.example.com", dns.TypeA)
	shard := c.getShard(key)
	shard.mu.Lock()
	shard.store[key].ExpireAt = time.Now().Add(-time.Second)
	shard.mu.Unlock()

	if _, hit, _, _ := c.Get("-", "nx.example.com", dns.TypeA); hit {
		t.Fatalf("过期 NXDOMAIN 应返回未命中")
	}
	if e := entryOf(c, "-", "nx.example.com", dns.TypeA); e != nil {
		t.Errorf("过期 NXDOMAIN 条目应被删除")
	}
}

// expireEntryAt 把条目过期时间设为指定时刻，用于构造「已过期」场景
func expireEntryAt(c *OptimizedDNSCache, scope, domain string, qtype uint16, at time.Time) {
	key := c.key(scope, domain, qtype)
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if e, ok := shard.store[key]; ok {
		e.ExpireAt = at
	}
}

// TestStaleWithinGraceReturnsOldValue 过期但仍在宽限内：应返回旧值（TTL 压到 5s），且条目保留
func TestStaleWithinGraceReturnsOldValue(t *testing.T) {
	c := NewOptimizedDNSCache(4096, time.Minute)
	c.SetStaleTTL(time.Hour)
	domain := "stale.example.com"
	c.Set("-", domain, dns.TypeA, wireTestResponse("stale.example.com."), false)
	expireEntryAt(c, "-", domain, dns.TypeA, time.Now().Add(-10*time.Second)) // 过期 10s，仍在 1h 宽限内

	resp, hit, _, _ := c.Get("-", domain, dns.TypeA)
	if !hit || resp == nil {
		t.Fatalf("宽限内应命中旧值: hit=%v resp=%v", hit, resp != nil)
	}
	for _, rr := range resp.Answer {
		if rr.Header().Ttl != 5 {
			t.Errorf("陈旧响应 Answer TTL 应压到 5s, got %d (%s)", rr.Header().Ttl, rr.Header().Name)
		}
	}
	if entryOf(c, "-", domain, dns.TypeA) == nil {
		t.Errorf("宽限内条目不应被删除")
	}
}

// TestStaleBeyondGraceIsMissAndDeleted 超出宽限：应返回未命中并删除条目（由本次请求同步回源）
func TestStaleBeyondGraceIsMissAndDeleted(t *testing.T) {
	c := NewOptimizedDNSCache(4096, time.Minute)
	c.SetStaleTTL(5 * time.Minute)
	domain := "stale2.example.com"
	c.Set("-", domain, dns.TypeA, wireTestResponse("stale2.example.com."), false)
	expireEntryAt(c, "-", domain, dns.TypeA, time.Now().Add(-10*time.Minute)) // 过期 10m，超出 5m 宽限

	if _, hit, _, _ := c.Get("-", domain, dns.TypeA); hit {
		t.Fatalf("超出宽限应返回未命中")
	}
	if entryOf(c, "-", domain, dns.TypeA) != nil {
		t.Errorf("超出宽限的条目应被删除")
	}
}

// TestStaleDisabledExpiredIsMiss stale_ttl=0 禁用 serve-stale：过期即未命中并删除
func TestStaleDisabledExpiredIsMiss(t *testing.T) {
	c := NewOptimizedDNSCache(4096, time.Minute) // 未调用 SetStaleTTL，默认 0=禁用
	domain := "stale3.example.com"
	c.Set("-", domain, dns.TypeA, wireTestResponse("stale3.example.com."), false)
	expireEntryAt(c, "-", domain, dns.TypeA, time.Now().Add(-time.Second))

	if _, hit, _, _ := c.Get("-", domain, dns.TypeA); hit {
		t.Fatalf("禁用宽限时过期应返回未命中")
	}
	if entryOf(c, "-", domain, dns.TypeA) != nil {
		t.Errorf("禁用宽限时过期条目应被删除")
	}
}

// TestStaleWithinGraceViaFlight 单飞行路径的宽限内陈旧返回与 Get 一致
func TestStaleWithinGraceViaFlight(t *testing.T) {
	c := NewOptimizedDNSCache(4096, time.Minute)
	c.SetStaleTTL(time.Hour)
	domain := "stale4.example.com"
	c.Set("-", domain, dns.TypeA, wireTestResponse("stale4.example.com."), false)
	expireEntryAt(c, "-", domain, dns.TypeA, time.Now().Add(-10*time.Second))

	resp, hit, _, _ := c.GetWithFlight("-", domain, dns.TypeA)
	if !hit || resp == nil {
		t.Fatalf("单飞行宽限内应命中旧值: hit=%v resp=%v", hit, resp != nil)
	}
}

// TestUnscannableResponseFallsBackToObjectTree 不可预打包的响应应保留对象树兜底，缓存语义不变
func TestUnscannableResponseFallsBackToObjectTree(t *testing.T) {
	c := NewOptimizedDNSCache(4096, time.Minute)
	m := new(dns.Msg)
	m.Response = true
	m.Question = []dns.Question{
		{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	}}
	c.Set("-", "a.example.com", dns.TypeA, m, false)

	e := entryOf(c, "-", "a.example.com", dns.TypeA)
	if e == nil {
		t.Fatalf("条目应存在")
	}
	if e.Response == nil || len(e.wire) != 0 {
		t.Fatalf("不可预打包时应保留对象树兜底: Response=%v wire=%d", e.Response != nil, len(e.wire))
	}
	if _, ok := c.GetServe("-", "a.example.com", dns.TypeA); ok {
		t.Errorf("无预打包字节的条目不应走快路径")
	}
	resp, hit, _, _ := c.Get("-", "a.example.com", dns.TypeA)
	if !hit || resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("兜底条目 Get 应仍可命中，hit=%v", hit)
	}
}

// 内存测量保活对象：用包级变量保证在两次统计之间始终可达，避免被 GC 提前回收
var (
	memTestResponses []*dns.Msg
	memTestTrees     []*dns.Msg
	memTestOldWires  [][]byte
	memTestNewWires  [][]byte
)

// liveHeap 多次强制 GC 后读取稳定存活堆大小，避免单次 GC 残留垃圾干扰测量
func liveHeap() uint64 {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestRetainedMemoryPerEntry 对比每条约保留内容的内存占用：
//
//	上一版：dns.Msg 对象树 与 预打包字节 各留一份
//	本  版：只保留预打包字节（外加少量预计算字段）
//
// 缓存键、分片 map、条目结构等容器开销两者一致，不在对比内。
func TestRetainedMemoryPerEntry(t *testing.T) {
	const n = 10000
	memTestResponses = make([]*dns.Msg, n)
	for i := range memTestResponses {
		memTestResponses[i] = benchResponse("m" + strconv.Itoa(i) + ".example.com.")
	}

	retained := func(setup func()) uint64 {
		before := liveHeap()
		setup()
		after := liveHeap()
		return after - before
	}

	// 本版：只保留预打包字节（临时副本测完即回收）
	newBytes := retained(func() {
		memTestNewWires = make([][]byte, n)
		for i, r := range memTestResponses {
			memTestNewWires[i], _ = buildWire(r.Copy())
		}
	})

	// 上一版：对象树与预打包字节各留一份
	oldBytes := retained(func() {
		memTestTrees = make([]*dns.Msg, n)
		memTestOldWires = make([][]byte, n)
		for i, r := range memTestResponses {
			c := r.Copy()
			memTestTrees[i] = c
			memTestOldWires[i], _ = buildWire(c)
		}
	})

	oldPer, newPer := float64(oldBytes)/n, float64(newBytes)/n
	t.Logf("上一版（对象树+wire）: %d bytes (%d 条) ≈ %.0f B/条", oldBytes, n, oldPer)
	t.Logf("本  版（仅 wire）    : %d bytes (%d 条) ≈ %.0f B/条", newBytes, n, newPer)
	t.Logf("每条节省 ≈ %.0f B（%.0f%%）", oldPer-newPer, (1-newPer/oldPer)*100)

	// 释放保活对象，避免影响同包其他测试的内存表现
	memTestResponses, memTestTrees, memTestOldWires, memTestNewWires = nil, nil, nil, nil

	if newPer >= oldPer {
		t.Errorf("新方案每条内存应下降，old=%.0f new=%.0f", oldPer, newPer)
	}
}
