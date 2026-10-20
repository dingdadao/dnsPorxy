package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/dns"
	"dnsPorxy/internal/utils"
)

// generateTestCert 生成测试用自签证书
func generateTestCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.example.com"},
		DNSNames:     []string{"dns.example.com", "*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// newCertTestServer 构造带有真实证书存储的测试服务器
func newCertTestServer(t *testing.T) *Server {
	t.Helper()
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	store, err := config.OpenStore("test.db")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	logger := utils.NewEnhancedLogger("error", "test", false)
	certStore := dns.NewCertStore(t.TempDir(), "", logger)

	return NewServer(store, logger,
		func() *dns.RefactoredHandler { return nil },
		func() *dns.CertStore { return certStore },
		nil, nil)
}

// certReq 发起请求并返回记录器
func certReq(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, req)
	return rec
}

// 管理端页面应包含新增的入站服务 / 客户端分流 / 证书托管入口
func TestIndexPageHasNewSections(t *testing.T) {
	s := newCertTestServer(t)
	rec := certReq(s, "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d，期望200", rec.Code)
	}
	body := rec.Body.String()
	for _, marker := range []string{
		`id:"inbound"`, `id:"clients"`, `入站加密服务`, `客户端 IP 分流`,
		`item("certs","证书托管")`, `renderCerts`, `cert-upload`, `cert-deploy-url`,
		`enable_doh3`, `doh3_quic_keepalive`,
		`listPlaceholder`, `cgMatchValid`,
		// 新版客户端分组：运营商固定分组 + 自定义分组 + 运营商识别开关
		`source_enabled`, `source_update_hours`, `isp_groups`, `custom_groups`,
		`ispGroupEditorHTML`, `customGroupEditorHTML`, `normalizeISPGroups`, `ISP_GROUP_DEFS`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("页面缺少标记 %q", marker)
		}
	}
}

// 客户端分组的错误位键名必须与 validateClientGroups 产出的键名一致（同为 cg<i>.<field>），
// 否则校验会「弹提示但不标红」——这类漂移曾真实发生过。
// Webhook Token 是热生效字段（每次请求都重新 LoadConfig，实测 PUT 后 restart_required=false），
// 管理页不应把它与 cert_store_dir / cert_default 一起标成「改动需重启」，否则会误导用户去重启进程
func TestWebhookTokenIsHotReloadableInUI(t *testing.T) {
	s := newCertTestServer(t)
	body := certReq(s, "GET", "/", "").Body.String()

	if !strings.Contains(body, "?token=") {
		t.Error("Webhook Token 帮助文案应说明令牌以 ?token= 查询参数传入")
	}
	if strings.Contains(body, "证书与 Webhook（改动需重启）") {
		t.Error("webhook_token 为热生效字段，卡片标题不应笼统声明「改动需重启」")
	}
}

// 客户端分组的错误位键名必须与 validateClientGroups 产出的键名一致
// （同为 <kind><i>.<field>，kind ∈ {isp, custom}），否则校验会「弹提示但不标红」。
// 同时确认键名带 kind 前缀——无前缀的 <i>.<field> 会与分流列表的错误键名冲突（单页视图同时渲染两者）。
func TestClientGroupErrorKeysArePrefixed(t *testing.T) {
	s := newCertTestServer(t)
	body := certReq(s, "GET", "/", "").Body.String()

	if !strings.Contains(body, `data-cg-err="${kind}${i}.`) {
		t.Error("分组字段错误位应使用 <kind><i>.<field> 前缀键名")
	}
	if !strings.Contains(body, `data-cg-err="custom${i}.name"`) {
		t.Error("自定义分组名称错误位应带 custom 前缀")
	}
	// 反例：无前缀的 ${i}.<field> 会与分流列表的错误键名冲突（单页视图同时渲染两者）
	if strings.Contains(body, `data-cg-err="${i}.`) {
		t.Error("发现未加 kind 前缀的分组错误位，会与分流列表错误键名冲突")
	}
	// 错误消费端也必须读取带前缀的键
	if !strings.Contains(body, `function cgErrKey(el)`) ||
		!strings.Contains(body, "errors[cgErrKey(inp)]") {
		t.Error("showErrors 应按 <kind><idx>.<field> 读取分组字段错误")
	}
}

// 上传 → 列表 → 删除 的完整链路
func TestCertUploadListDelete(t *testing.T) {
	s := newCertTestServer(t)
	certPEM, keyPEM := generateTestCert(t)

	body, _ := json.Marshal(map[string]string{"name": "dns.example.com", "cert": certPEM, "key": keyPEM})
	rec := certReq(s, "POST", "/api/certs", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传状态码 %d，期望200，body=%s", rec.Code, rec.Body.String())
	}

	// 列表可见
	rec = certReq(s, "GET", "/api/certs", "")
	var listResp struct {
		Certs []struct {
			Name    string   `json:"name"`
			Domains []string `json:"domains"`
		} `json:"certs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("解析列表失败: %v", err)
	}
	if len(listResp.Certs) != 1 || listResp.Certs[0].Name != "dns.example.com" {
		t.Fatalf("列表内容错误: %s", rec.Body.String())
	}

	// 删除
	rec = certReq(s, "DELETE", "/api/certs/dns.example.com", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("删除状态码 %d，期望200", rec.Code)
	}

	// 删除后列表为空
	rec = certReq(s, "GET", "/api/certs", "")
	if !strings.Contains(rec.Body.String(), `"certs":[]`) {
		t.Fatalf("删除后列表应为空: %s", rec.Body.String())
	}
}

// 非法证书（cert/key 不匹配）应被拒
func TestCertUploadInvalidRejected(t *testing.T) {
	s := newCertTestServer(t)
	certPEM, _ := generateTestCert(t)
	_, otherKey := generateTestCert(t)

	body, _ := json.Marshal(map[string]string{"name": "bad", "cert": certPEM, "key": otherKey})
	rec := certReq(s, "POST", "/api/certs", string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不配对证书状态码 %d，期望400", rec.Code)
	}
}

// webhook 部署：错 token → 401；正确 token → success；重复推送幂等
func TestCertWebhookDeploy(t *testing.T) {
	s := newCertTestServer(t)

	// 设置 webhook token
	cfg, err := s.store.LoadConfig()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	cfg.WebhookToken = "secret-token-123"
	if err := s.store.SaveConfig(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	certPEM, keyPEM := generateTestCert(t)
	deployBody, _ := json.Marshal(map[string]string{
		"domain": "dns.example.com",
		"crt":    certPEM,
		"key":    keyPEM,
	})

	// 错 token
	rec := certReq(s, "POST", "/api/certs/deploy?token=wrong", string(deployBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错 token 状态码 %d，期望401", rec.Code)
	}

	// 正确 token
	rec = certReq(s, "POST", "/api/certs/deploy?token=secret-token-123", string(deployBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook 状态码 %d，期望200，body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Fatalf("webhook 响应缺少 success: %s", rec.Body.String())
	}

	// 重复推送（同指纹）应幂等成功
	rec = certReq(s, "POST", "/api/certs/deploy?token=secret-token-123", string(deployBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Fatalf("重复推送应幂等成功: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 数据库中只应有一条
	records, err := s.store.ListCerts()
	if err != nil {
		t.Fatalf("查询证书失败: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("证书条数 %d，期望1", len(records))
	}
}
