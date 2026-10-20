package dns

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// newInboundTestHandler 构造一个指向本地假上游的处理器与证书存储
// 假上游对任意请求返回 A 10.0.0.1（见 ecs_test.go 的 startFakeUpstream）
func newInboundTestHandler(t *testing.T) (*RefactoredHandler, *CertStore) {
	t.Helper()

	// 组件构造会写 ./logs，切到临时目录避免污染仓库
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	upstream := startFakeUpstream(t).addr
	logger := utils.NewEnhancedLogger("error", "test", false)

	cfg := &config.Config{
		ListenPort:            5353, // 仅用于通过配置校验，本用例不启动明文监听
		Upstream:              []string{"udp://" + upstream},
		Timeout:               2 * time.Second,
		ModernTimeout:         2 * time.Second,
		BackupDNS:             "",
		Cache:                 config.CacheConfig{MaxItems: 100, TTL: time.Minute, MaxAsyncWorkers: 1},
		QueryLog:              config.QueryLogConfig{Enabled: false},
		EnableCloudflareCheck: false,
		EnableAWSCheck:        false,
		SplitLists:            []config.SplitList{},
		LogLevel:              "error",
		ClientIPSources:       []string{"static", "header", "socket"},
		ClientIPHeaders:       []string{"x-forwarded-for"},
		TrustedProxies:        []string{"127.0.0.1/32", "::1/128"},
	}
	if err := config.ValidateConfig(cfg); err != nil {
		t.Fatalf("配置校验失败: %v", err)
	}

	handler, err := NewRefactoredHandler(cfg, logger, nil)
	if err != nil {
		t.Fatalf("创建处理器失败: %v", err)
	}
	t.Cleanup(handler.Close)

	certPEM, keyPEM := generateCert(t, []string{"localhost"})
	cs := NewCertStore(t.TempDir(), "test", logger)
	if _, err := cs.AddCert("test", certPEM, keyPEM, CertSourceUpload); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}
	return handler, cs
}

// packAQuery 构造 example.com A 查询的 wire 报文
func packAQuery(t *testing.T) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("打包查询失败: %v", err)
	}
	return wire
}

// assertUpstreamAnswer 校验响应含假上游返回的 A 10.0.0.1
func assertUpstreamAnswer(t *testing.T, wire []byte) {
	t.Helper()
	resp := new(dns.Msg)
	if err := resp.Unpack(wire); err != nil {
		t.Fatalf("解包响应失败: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("响应码 %s，期望 NOERROR", dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "10.0.0.1" {
			return
		}
	}
	t.Fatalf("响应中未找到 A 10.0.0.1: %v", resp.Answer)
}

// TestDoHServerEndToEnd 端到端验证 DoH（HTTP over TLS + RFC 8484 POST）
func TestDoHServerEndToEnd(t *testing.T) {
	handler, cs := newInboundTestHandler(t)
	logger := utils.NewEnhancedLogger("error", "test", false)

	srv := NewDoHServer("127.0.0.1:0", "/dns-query", "", cs, handler, logger)
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 DoH 失败: %v", err)
	}
	defer srv.Stop()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	url := "https://" + srv.Addr() + "/dns-query"
	httpResp, err := client.Post(url, dohMediaType, bytes.NewReader(packAQuery(t)))
	if err != nil {
		t.Fatalf("DoH 请求失败: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("DoH 状态码 %d，期望 200", httpResp.StatusCode)
	}
	body, _ := io.ReadAll(httpResp.Body)
	assertUpstreamAnswer(t, body)
}

// TestDoH3ServerEndToEnd 端到端验证 DoH3（HTTP/3 over QUIC）
func TestDoH3ServerEndToEnd(t *testing.T) {
	handler, cs := newInboundTestHandler(t)
	logger := utils.NewEnhancedLogger("error", "test", false)

	srv := NewDoH3Server("127.0.0.1:0", "/dns-query", cs, handler, logger)
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 DoH3 失败: %v", err)
	}
	defer srv.Stop()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{},
	}
	defer rt.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: rt}

	url := "https://" + srv.Addr() + "/dns-query"
	httpResp, err := client.Post(url, dohMediaType, bytes.NewReader(packAQuery(t)))
	if err != nil {
		t.Fatalf("DoH3 请求失败: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("DoH3 状态码 %d，期望 200", httpResp.StatusCode)
	}
	body, _ := io.ReadAll(httpResp.Body)
	assertUpstreamAnswer(t, body)
}

// TestDoH3AddrReleased 验证停止后 UDP 端口被正确释放（无 socket 泄漏）
func TestDoH3AddrReleased(t *testing.T) {
	handler, cs := newInboundTestHandler(t)
	logger := utils.NewEnhancedLogger("error", "test", false)

	srv := NewDoH3Server("127.0.0.1:0", "/dns-query", cs, handler, logger)
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 DoH3 失败: %v", err)
	}
	addr := srv.Addr()
	srv.Stop()

	// 停止后应能重新占用同一 UDP 地址
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("DoH3 停止后 UDP 地址未释放: %v", err)
	}
	_ = pc.Close()
}

// TestDoTServerEndToEnd 端到端验证 DoT（TLS over TCP）
func TestDoTServerEndToEnd(t *testing.T) {
	handler, cs := newInboundTestHandler(t)
	logger := utils.NewEnhancedLogger("error", "test", false)

	srv := NewDoTServer("127.0.0.1:0", cs, handler, logger)
	// Start 非阻塞：同步完成端口绑定后于后台 goroutine 提供服务
	if err := srv.Start(); err != nil {
		t.Fatalf("启动 DoT 失败: %v", err)
	}
	defer srv.Stop()

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("DoT 未在预期时间内监听")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DoT TLS 连接失败: %v", err)
	}
	defer conn.Close()

	dnsConn := &dns.Conn{Conn: conn}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if err := dnsConn.WriteMsg(m); err != nil {
		t.Fatalf("DoT 写入失败: %v", err)
	}
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("DoT 读取失败: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoT 响应码 %s", dns.RcodeToString[resp.Rcode])
	}
	found := false
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "10.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DoT 响应中未找到 A 10.0.0.1: %v", resp.Answer)
	}
}
