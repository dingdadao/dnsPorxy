package dns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dnsPorxy/internal/utils"
)

func generateCert(t *testing.T, domains []string) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestCertStoreAddAndSNI(t *testing.T) {
	dir := t.TempDir()
	logger := utils.NewEnhancedLogger("error", "test", false)
	store := NewCertStore(dir, "default", logger)

	certPEM, keyPEM := generateCert(t, []string{"example.com", "*.example.com"})

	rec, err := store.AddCert("default", certPEM, keyPEM, CertSourceUpload)
	if err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}
	if len(rec.Domains) != 2 {
		t.Fatalf("域名数量不对: %v", rec.Domains)
	}

	// 精确匹配
	c, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("SNI 精确匹配失败: %v", err)
	}
	if c == nil {
		t.Fatal("未返回证书")
	}

	// 泛域名匹配
	c, err = store.GetCertificate(&tls.ClientHelloInfo{ServerName: "www.example.com"})
	if err != nil {
		t.Fatalf("SNI 泛域名匹配失败: %v", err)
	}
	if c == nil {
		t.Fatal("未返回证书")
	}

	// 未命中应回退默认
	c, err = store.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.com"})
	if err != nil {
		t.Fatalf("回退失败: %v", err)
	}
	if c == nil {
		t.Fatal("未返回默认证书")
	}
}

func TestCertStoreDelete(t *testing.T) {
	dir := t.TempDir()
	logger := utils.NewEnhancedLogger("error", "test", false)
	store := NewCertStore(dir, "", logger)

	certPEM, keyPEM := generateCert(t, []string{"a.com"})
	if _, err := store.AddCert("a", certPEM, keyPEM, CertSourceUpload); err != nil {
		t.Fatalf("添加失败: %v", err)
	}

	if err := store.DeleteCert("a"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if len(store.Records()) != 0 {
		t.Fatalf("删除后仍有记录: %d", len(store.Records()))
	}

	if _, err := os.Stat(filepath.Join(dir, "a.crt")); !os.IsNotExist(err) {
		t.Fatal("删除后证书文件仍存在")
	}
	if _, err := os.Stat(filepath.Join(dir, "a.key")); !os.IsNotExist(err) {
		t.Fatal("删除后私钥文件仍存在")
	}
}

func TestCertStoreScanDir(t *testing.T) {
	dir := t.TempDir()
	logger := utils.NewEnhancedLogger("error", "test", false)
	store := NewCertStore(dir, "", logger)

	certPEM, keyPEM := generateCert(t, []string{"scan.example.com"})
	if err := os.WriteFile(filepath.Join(dir, "scan.crt"), certPEM, 0o600); err != nil {
		t.Fatalf("写证书失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("写私钥失败: %v", err)
	}

	records, err := store.ScanDir()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("扫描到 %d 条记录", len(records))
	}
	if records[0].Source != CertSourceSSH {
		t.Fatalf("来源不对: %v", records[0].Source)
	}
}

func TestCertStoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	logger := utils.NewEnhancedLogger("error", "test", false)
	store := NewCertStore(dir, "", logger)

	certPEM, keyPEM := generateCert(t, []string{"id.example.com"})
	rec1, err := store.AddCert("id", certPEM, keyPEM, CertSourceUpload)
	if err != nil {
		t.Fatalf("第一次添加失败: %v", err)
	}
	rec2, err := store.AddCert("id2", certPEM, keyPEM, CertSourceWebhook)
	if err != nil {
		t.Fatalf("第二次添加失败: %v", err)
	}
	if rec1.Fingerprint != rec2.Fingerprint {
		t.Fatal("同指纹应幂等")
	}
	if len(store.Records()) != 1 {
		t.Fatalf("幂等后应有 1 条，实际 %d", len(store.Records()))
	}
}
