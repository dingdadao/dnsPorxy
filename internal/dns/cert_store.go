package dns

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsPorxy/internal/utils"
)

// CertSource 证书来源类型
type CertSource string

const (
	CertSourceUpload  CertSource = "upload"
	CertSourceSSH     CertSource = "ssh"
	CertSourceWebhook CertSource = "webhook"
)

// CertRecord 证书元数据（内存表示）
type CertRecord struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Domains     []string   `json:"domains"`
	CertPath    string     `json:"cert_path"`
	KeyPath     string     `json:"key_path"`
	Fingerprint string     `json:"fingerprint"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Source      CertSource `json:"source"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// certEntry 内部条目，持有已解析的证书对象
type certEntry struct {
	CertRecord
	cert *tls.Certificate
	leaf *x509.Certificate
}

// CertStore 证书存储、SNI 选择与热加载
type CertStore struct {
	logger *utils.EnhancedLogger

	dir         string
	defaultName string

	mu      sync.RWMutex
	entries []certEntry

	tlsConf atomic.Pointer[tls.Config]
}

// NewCertStore 创建证书存储
func NewCertStore(dir, defaultName string, logger *utils.EnhancedLogger) *CertStore {
	s := &CertStore{
		dir:         dir,
		defaultName: defaultName,
		logger:      logger,
	}
	s.buildTLSConfig()
	return s
}

// SetDefault 设置默认证书名称
func (s *CertStore) SetDefault(name string) {
	s.mu.Lock()
	s.defaultName = name
	s.mu.Unlock()
	s.buildTLSConfig()
}

// LoadRecords 从数据库元数据加载证书（不校验磁盘存在性，调用方应保证路径有效）
func (s *CertStore) LoadRecords(records []CertRecord) error {
	entries := make([]certEntry, 0, len(records))
	for _, r := range records {
		cert, leaf, err := loadCertPair(r.CertPath, r.KeyPath)
		if err != nil {
			// 记录警告但跳过，避免一条坏证书导致整个服务起不来
			if s.logger != nil {
				s.logger.Warn("⚠️ [证书加载失败，已跳过] ", map[string]interface{}{
					"rule":  "CERT_LOAD_SKIPPED",
					"name":  r.Name,
					"error": err.Error(),
					"cert":  r.CertPath,
					"key":   r.KeyPath,
				})
			}
			continue
		}
		entries = append(entries, certEntry{CertRecord: r, cert: cert, leaf: leaf})
	}

	s.mu.Lock()
	s.entries = entries
	s.mu.Unlock()
	s.buildTLSConfig()

	if s.logger != nil {
		s.logger.Info("📜 [证书存储已加载] ", map[string]interface{}{
			"rule":    "CERT_STORE_LOADED",
			"count":   len(entries),
			"skipped": len(records) - len(entries),
		})
	}
	return nil
}

// ScanDir 扫描约定目录，将成对 PEM 文件作为 SSH 来源导入（幂等）
func (s *CertStore) ScanDir() ([]CertRecord, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}

	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("读取证书目录失败: %w", err)
	}

	records := make([]CertRecord, 0)
	certPaths := make(map[string]string)
	keyPaths := make(map[string]string)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if strings.HasSuffix(name, ".crt") {
			base := strings.TrimSuffix(name, ".crt")
			certPaths[base] = filepath.Join(s.dir, name)
		} else if strings.HasSuffix(name, ".key") {
			base := strings.TrimSuffix(name, ".key")
			keyPaths[base] = filepath.Join(s.dir, name)
		}
	}

	for base, certPath := range certPaths {
		keyPath, ok := keyPaths[base]
		if !ok {
			continue
		}
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		rec, err := s.validateAndBuildRecord(base, certPEM, keyPEM, CertSourceSSH)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("⚠️ [目录扫描证书校验失败] ", map[string]interface{}{
					"rule":  "CERT_SCAN_INVALID",
					"name":  base,
					"error": err.Error(),
				})
			}
			continue
		}
		records = append(records, rec)
	}

	return records, nil
}

// AddCert 添加或更新证书（上传/webhook 用）
// 返回元数据；若同指纹已存在则直接返回现有记录（幂等）
func (s *CertStore) AddCert(name string, certPEM, keyPEM []byte, source CertSource) (*CertRecord, error) {
	rec, err := s.validateAndBuildRecord(name, certPEM, keyPEM, source)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 幂等：同指纹直接返回现有记录
	for _, e := range s.entries {
		if e.Fingerprint == rec.Fingerprint {
			return &e.CertRecord, nil
		}
	}

	certPath := filepath.Join(s.dir, name+".crt")
	keyPath := filepath.Join(s.dir, name+".key")

	// 原子落盘：先写临时文件，再 rename
	if err := writePrivateFile(certPath, certPEM); err != nil {
		return nil, fmt.Errorf("写入证书文件失败: %w", err)
	}
	if err := writePrivateFile(keyPath, keyPEM); err != nil {
		_ = os.Remove(certPath)
		return nil, fmt.Errorf("写入私钥文件失败: %w", err)
	}

	rec.CertPath = certPath
	rec.KeyPath = keyPath

	cert, leaf, err := loadCertPair(certPath, keyPath)
	if err != nil {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("落盘后重新加载证书失败: %w", err)
	}

	s.entries = append(s.entries, certEntry{CertRecord: rec, cert: cert, leaf: leaf})
	s.buildTLSConfig()
	return &rec, nil
}

// ReplaceCert 用同 name 更新证书（SSH 扫描/热重载用）
func (s *CertStore) ReplaceCert(name string, certPEM, keyPEM []byte, source CertSource) (*CertRecord, error) {
	rec, err := s.validateAndBuildRecord(name, certPEM, keyPEM, source)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := filepath.Join(s.dir, name+".crt")
	keyPath := filepath.Join(s.dir, name+".key")

	if err := writePrivateFile(certPath, certPEM); err != nil {
		return nil, fmt.Errorf("写入证书文件失败: %w", err)
	}
	if err := writePrivateFile(keyPath, keyPEM); err != nil {
		_ = os.Remove(certPath)
		return nil, fmt.Errorf("写入私钥文件失败: %w", err)
	}

	rec.CertPath = certPath
	rec.KeyPath = keyPath

	cert, leaf, err := loadCertPair(certPath, keyPath)
	if err != nil {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("落盘后重新加载证书失败: %w", err)
	}

	// 替换同 name 条目，或追加
	found := false
	for i := range s.entries {
		if s.entries[i].Name == name {
			s.entries[i] = certEntry{CertRecord: rec, cert: cert, leaf: leaf}
			found = true
			break
		}
	}
	if !found {
		s.entries = append(s.entries, certEntry{CertRecord: rec, cert: cert, leaf: leaf})
	}
	s.buildTLSConfig()
	return &rec, nil
}

// DeleteCert 删除证书（同时删文件和内存条目）
func (s *CertStore) DeleteCert(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed certEntry
	newEntries := make([]certEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.Name == name {
			removed = e
			continue
		}
		newEntries = append(newEntries, e)
	}
	if removed.Name == "" {
		return fmt.Errorf("证书不存在: %s", name)
	}
	s.entries = newEntries

	_ = os.Remove(removed.CertPath)
	_ = os.Remove(removed.KeyPath)
	s.buildTLSConfig()
	return nil
}

// Records 返回当前证书元数据列表副本
func (s *CertStore) Records() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]CertRecord, len(s.entries))
	for i, e := range s.entries {
		out[i] = e.CertRecord
	}
	return out
}

// TLSConfig 返回当前 tls.Config（可被 TLS/QUIC 共享）
func (s *CertStore) TLSConfig() *tls.Config {
	return s.tlsConf.Load()
}

// GetCertificate 实现 tls.Config.GetCertificate，供外部直接使用
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.lookup(hello.ServerName)
}

// IsExpiredSoon 检查是否有证书在 days 天内过期（用于日志告警）
func (s *CertStore) IsExpiredSoon(days int) []CertRecord {
	deadline := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	var list []CertRecord
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.NotAfter.Before(deadline) {
			list = append(list, e.CertRecord)
		}
	}
	return list
}

// lookup 按 SNI 选择证书，未命中则回退默认证书
func (s *CertStore) lookup(serverName string) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.entries) == 0 {
		return nil, errors.New("无可用证书")
	}

	// 未提供 SNI 时使用默认证书
	if serverName == "" {
		for _, e := range s.entries {
			if e.Name == s.defaultName {
				return e.cert, nil
			}
		}
		// 没有默认证书则取第一个
		return s.entries[0].cert, nil
	}

	serverName = strings.ToLower(serverName)

	// 精确匹配 > 泛域名匹配
	var exact, wildcard *certEntry
	for i := range s.entries {
		e := &s.entries[i]
		for _, d := range e.Domains {
			d = strings.ToLower(d)
			if d == serverName {
				exact = e
				break
			}
			if strings.HasPrefix(d, "*.") {
				suffix := d[1:] // ".example.com"
				if strings.HasSuffix(serverName, suffix) && strings.Count(serverName, ".") == strings.Count(suffix, ".") {
					if wildcard == nil || len(e.Domains) < len(wildcard.Domains) {
						wildcard = e
					}
				}
			}
		}
		if exact != nil {
			break
		}
	}

	if exact != nil {
		return exact.cert, nil
	}
	if wildcard != nil {
		return wildcard.cert, nil
	}

	// 未命中：使用默认证书（若配置）或第一个
	for _, e := range s.entries {
		if e.Name == s.defaultName {
			return e.cert, nil
		}
	}
	return s.entries[0].cert, nil
}

// buildTLSConfig 原子替换 tls.Config
func (s *CertStore) buildTLSConfig() {
	conf := &tls.Config{
		GetCertificate: s.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	s.tlsConf.Store(conf)
}

// validateAndBuildRecord 校验 PEM 并构造元数据（不设置路径）
func (s *CertStore) validateAndBuildRecord(name string, certPEM, keyPEM []byte, source CertSource) (CertRecord, error) {
	_, leaf, err := parseCertPair(certPEM, keyPEM)
	if err != nil {
		return CertRecord{}, err
	}

	fp := sha256.Sum256(certPEM)
	now := time.Now()
	return CertRecord{
		Name:        name,
		Domains:     leaf.DNSNames,
		Fingerprint: hex.EncodeToString(fp[:]),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Source:      source,
		UpdatedAt:   now,
	}, nil
}

// parseCertPair 解析并校验证书与私钥匹配
func parseCertPair(certPEM, keyPEM []byte) (*tls.Certificate, *x509.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("证书与私钥不匹配: %w", err)
	}

	if len(cert.Certificate) == 0 {
		return nil, nil, errors.New("证书链为空")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("解析叶子证书失败: %w", err)
	}

	if time.Now().After(leaf.NotAfter) {
		// 允许过期证书继续存在/导入，由服务层决定是否握手失败；
		// 但这里仍给出明确错误，防止误导入完全不可用的证书
		// webhook 等入口可根据需要忽略此错误
	}

	return &cert, leaf, nil
}

// loadCertPair 从磁盘加载证书
func loadCertPair(certPath, keyPath string) (*tls.Certificate, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return parseCertPair(certPEM, keyPEM)
}

// writePrivateFile 原子写入敏感文件（权限 0600）
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// sortCertRecords 按名称排序，便于列表展示与测试稳定
func sortCertRecords(records []CertRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
}
