package dns

import (
	"errors"
	"net"
	"os"
	"testing"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// nopWriter 仅用于让 respond 出口拿到非 nil 的 ResponseWriter
type nopWriter struct{}

func (nopWriter) LocalAddr() net.Addr       { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (nopWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (nopWriter) WriteMsg(*dns.Msg) error   { return nil }
func (nopWriter) Write([]byte) (int, error) { return 0, nil }
func (nopWriter) Close() error              { return nil }
func (nopWriter) TsigStatus() error         { return nil }
func (nopWriter) TsigTimersOnly(bool)       {}
func (nopWriter) Hijack()                   {}

// 云IP替换不可用时应降级返回上游原始应答，而不是让整条请求 SERVFAIL
func TestCloudReplacementFallback(t *testing.T) {
	cases := []struct {
		name          string
		replaceDomain string
		proxy         func(*dns.Msg, []string) (*dns.Msg, error)
	}{
		{"替换域名查询报错", "cf.example.com", func(*dns.Msg, []string) (*dns.Msg, error) {
			return nil, errors.New("boom")
		}},
		{"替换域名无应答", "cf.example.com", func(*dns.Msg, []string) (*dns.Msg, error) {
			return nil, nil
		}},
		{"替换域名返回空应答", "cf.example.com", func(req *dns.Msg, _ []string) (*dns.Msg, error) {
			r := new(dns.Msg)
			r.SetReply(req)
			return r, nil
		}},
		{"未配置替换域名", "", func(*dns.Msg, []string) (*dns.Msg, error) {
			return nil, errors.New("不应被调用")
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// logger与缓存管理器构造会写./logs目录，chdir到临时目录避免污染仓库
			origWd, _ := os.Getwd()
			if err := os.Chdir(t.TempDir()); err != nil {
				t.Fatalf("chdir失败: %v", err)
			}
			t.Cleanup(func() { os.Chdir(origWd) })

			cfg := config.DefaultConfig()
			cfg.ReplaceCFDomain = c.replaceDomain
			cfg.ReplaceCacheTime = 0
			logger := utils.NewEnhancedLogger("error", "test", false)
			cm := NewCacheManager(cfg, logger)

			var written *dns.Msg
			ch := NewCloudHandler(cfg, logger, cm, nil, c.proxy,
				func(_ dns.ResponseWriter, _ *dns.Msg, resp *dns.Msg) { written = resp })

			req := new(dns.Msg)
			req.SetQuestion("cloud.example.com.", dns.TypeA)

			original := new(dns.Msg)
			original.SetReply(req)
			original.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "cloud.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("104.16.1.1"),
			}}

			if _, err := ch.HandleCloudReplacement(nopWriter{}, req, "cloud.example.com", dns.TypeA,
				int(CloudTypeCloudflare), original, "", "-", ReplaceConfig{CFDomain: cfg.ReplaceCFDomain}); err != nil {
				t.Fatalf("HandleCloudReplacement 返回错误: %v", err)
			}
			if written == nil {
				t.Fatal("未写出任何响应")
			}
			if written.Rcode != dns.RcodeSuccess {
				t.Errorf("应降级返回原始应答(NOERROR)，实际 rcode=%s", dns.RcodeToString[written.Rcode])
			}
			if len(written.Answer) != 1 {
				t.Fatalf("应保留原始应答记录，实际 %d 条", len(written.Answer))
			}
			a, ok := written.Answer[0].(*dns.A)
			if !ok || a.A.String() != "104.16.1.1" {
				t.Errorf("应返回原始 CF IP 104.16.1.1，实际 %v", written.Answer[0])
			}
		})
	}
}
