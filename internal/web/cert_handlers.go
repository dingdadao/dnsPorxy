package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/dns"
)

const maxCertBodyBytes = 4 << 20 // 4 MB

// certRecordJSON 证书列表/上传返回的统一结构
type certRecordJSON struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Domains       []string  `json:"domains"`
	Fingerprint   string    `json:"fingerprint"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Source        string    `json:"source"`
	UpdatedAt     time.Time `json:"updated_at"`
	RemainingDays int       `json:"remaining_days"`
}

func toCertRecordJSON(r dns.CertRecord) certRecordJSON {
	remaining := int(time.Until(r.NotAfter).Hours() / 24)
	if remaining < 0 {
		remaining = 0
	}
	return certRecordJSON{
		ID:            r.ID,
		Name:          r.Name,
		Domains:       r.Domains,
		Fingerprint:   r.Fingerprint,
		NotBefore:     r.NotBefore,
		NotAfter:      r.NotAfter,
		Source:        string(r.Source),
		UpdatedAt:     r.UpdatedAt,
		RemainingDays: remaining,
	}
}

// handleListCerts GET /api/certs
func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	cs := s.getCertStore()
	if cs == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"certs": []certRecordJSON{}, "default": ""})
		return
	}
	records := cs.Records()
	out := make([]certRecordJSON, len(records))
	for i, rec := range records {
		out[i] = toCertRecordJSON(rec)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certs": out})
}

// handleUploadCert POST /api/certs
// 支持 multipart/form-data（name, cert, key）或 JSON（name, cert, key）
func (s *Server) handleUploadCert(w http.ResponseWriter, r *http.Request) {
	cs := s.certStoreOrError(w)
	if cs == nil {
		return
	}

	name, certPEM, keyPEM, err := s.parseCertUpload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	rec, err := cs.AddCert(name, certPEM, keyPEM, dns.CertSourceUpload)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("证书校验失败: %w", err))
		return
	}

	if err := s.persistCertRecord(*rec); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.logger.Info("📜 [证书上传成功] ", map[string]interface{}{
		"rule":   "CERT_UPLOADED",
		"name":   rec.Name,
		"fp":     rec.Fingerprint,
		"source": "upload",
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "cert": toCertRecordJSON(*rec)})
}

// handleDeleteCert DELETE /api/certs/{name}
func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	cs := s.certStoreOrError(w)
	if cs == nil {
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("证书名称不能为空"))
		return
	}

	if err := cs.DeleteCert(name); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := s.store.DeleteCert(name); err != nil {
		s.logger.Warn("⚠️ [删除证书数据库记录失败] ", map[string]interface{}{
			"rule":  "CERT_DB_DELETE_FAILED",
			"name":  name,
			"error": err.Error(),
		})
	}

	s.logger.Info("📜 [证书已删除] ", map[string]interface{}{
		"rule": "CERT_DELETED",
		"name": name,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// handleReloadCerts POST /api/certs/reload
// 重新扫描约定目录并热加载（SSH 路径用）
func (s *Server) handleReloadCerts(w http.ResponseWriter, r *http.Request) {
	cs := s.certStoreOrError(w)
	if cs == nil {
		return
	}

	scanned, err := cs.ScanDir()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	persisted := 0
	for _, rec := range scanned {
		cfgRec := certRecordToConfig(rec)
		if err := s.store.AddOrReplaceCert(&cfgRec); err != nil {
			s.logger.Warn("⚠️ [重扫证书持久化失败] ", map[string]interface{}{
				"rule":  "CERT_RELOAD_PERSIST_FAILED",
				"name":  rec.Name,
				"error": err.Error(),
			})
			continue
		}
		persisted++
	}

	s.logger.Info("📜 [证书目录已重扫] ", map[string]interface{}{
		"rule":      "CERTS_RELOADED",
		"scanned":   len(scanned),
		"persisted": persisted,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "scanned": len(scanned), "persisted": persisted})
}

// handleCertDeployConfig GET /api/certs/deploy-config
// 返回 webhook URL 与字段映射模板
func (s *Server) handleCertDeployConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	host := r.Host
	if r.URL.Host != "" {
		host = r.URL.Host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	webhookURL := fmt.Sprintf("%s://%s/api/certs/deploy?token=%s", scheme, host, cfg.WebhookToken)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"url":          webhookURL,
		"method":       "POST",
		"content_type": "application/json",
		"field_mapping": map[string]string{
			"domain": "name（可用域名作为证书名）",
			"crt":    "证书 PEM 文本（或 base64）",
			"key":    "私钥 PEM 文本（或 base64）",
			"ic":     "中间证书 PEM 文本（可选，会拼接到 crt 后）",
		},
		"success_mark": "status",
	})
}

// handleCertDeploy POST /api/certs/deploy
// certd 等外部平台通过 webhook 部署证书
func (s *Server) handleCertDeploy(w http.ResponseWriter, r *http.Request) {
	// token 鉴权
	cfg, err := s.store.LoadConfig()
	if err != nil {
		writeDeployError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}
	if cfg.WebhookToken == "" {
		writeDeployError(w, http.StatusForbidden, "未配置 webhook_token")
		return
	}
	if r.URL.Query().Get("token") != cfg.WebhookToken {
		writeDeployError(w, http.StatusUnauthorized, "无效的 token")
		return
	}

	cs := s.getCertStore()
	if cs == nil {
		writeDeployError(w, http.StatusServiceUnavailable, "证书存储未就绪")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxCertBodyBytes))
	if err != nil {
		writeDeployError(w, http.StatusBadRequest, "读取请求体失败")
		return
	}

	var req certDeployRequest
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		if err := json.Unmarshal(body, &req); err != nil {
			writeDeployError(w, http.StatusBadRequest, "JSON 解析失败")
			return
		}
	} else {
		// 默认也尝试 JSON（兼容 form-data 中 json 字段）
		_ = json.Unmarshal(body, &req)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Domain)
	}
	if name == "" {
		writeDeployError(w, http.StatusBadRequest, "缺少 name 或 domain 字段")
		return
	}

	certPEM, err := decodeCertField(req.Crt)
	if err != nil {
		writeDeployError(w, http.StatusBadRequest, fmt.Sprintf("crt 字段解码失败: %v", err))
		return
	}
	keyPEM, err := decodeCertField(req.Key)
	if err != nil {
		writeDeployError(w, http.StatusBadRequest, fmt.Sprintf("key 字段解码失败: %v", err))
		return
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		writeDeployError(w, http.StatusBadRequest, "crt/key 字段不能为空")
		return
	}

	// 中间证书可选，拼接到 cert 之后
	if req.Ic != "" {
		icPEM, err := decodeCertField(req.Ic)
		if err != nil {
			writeDeployError(w, http.StatusBadRequest, fmt.Sprintf("ic 字段解码失败: %v", err))
			return
		}
		certPEM = append(certPEM, '\n')
		certPEM = append(certPEM, icPEM...)
	}

	rec, err := cs.AddCert(name, certPEM, keyPEM, dns.CertSourceWebhook)
	if err != nil {
		writeDeployError(w, http.StatusBadRequest, fmt.Sprintf("证书校验失败: %v", err))
		return
	}

	if err := s.persistCertRecord(*rec); err != nil {
		writeDeployError(w, http.StatusInternalServerError, "证书持久化失败")
		return
	}

	s.logger.Info("📜 [Webhook 证书部署成功] ", map[string]interface{}{
		"rule":   "CERT_WEBHOOK_DEPLOYED",
		"name":   rec.Name,
		"fp":     rec.Fingerprint,
		"source": "webhook",
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"cert":   toCertRecordJSON(*rec),
	})
}

// certDeployRequest webhook 部署请求结构
type certDeployRequest struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Crt    string `json:"crt"`
	Key    string `json:"key"`
	Ic     string `json:"ic"`
}

// certStoreOrError 返回证书存储，未就绪时写错误并返回 nil
func (s *Server) certStoreOrError(w http.ResponseWriter) *dns.CertStore {
	cs := s.getCertStore()
	if cs == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("证书存储未就绪"))
		return nil
	}
	return cs
}

// persistCertRecord 将 dns.CertRecord 持久化到 SQLite
func (s *Server) persistCertRecord(rec dns.CertRecord) error {
	cfgRec := certRecordToConfig(rec)
	return s.store.AddOrReplaceCert(&cfgRec)
}

// certRecordToConfig 将 dns.CertRecord 转换为 config.CertRecord
func certRecordToConfig(r dns.CertRecord) config.CertRecord {
	return config.CertRecord{
		ID:          r.ID,
		Name:        r.Name,
		Domains:     r.Domains,
		CertPath:    r.CertPath,
		KeyPath:     r.KeyPath,
		Fingerprint: r.Fingerprint,
		NotBefore:   r.NotBefore,
		NotAfter:    r.NotAfter,
		Source:      string(r.Source),
		UpdatedAt:   r.UpdatedAt,
	}
}

// parseCertUpload 解析上传请求，返回 name/certPEM/keyPEM
func (s *Server) parseCertUpload(r *http.Request) (string, []byte, []byte, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxCertBodyBytes); err != nil {
			return "", nil, nil, fmt.Errorf("解析 multipart 失败: %w", err)
		}
		name := strings.TrimSpace(r.FormValue("name"))
		certB64 := r.FormValue("cert")
		keyB64 := r.FormValue("key")
		certPEM, err := decodeCertField(certB64)
		if err != nil {
			return "", nil, nil, fmt.Errorf("cert 字段解码失败: %w", err)
		}
		keyPEM, err := decodeCertField(keyB64)
		if err != nil {
			return "", nil, nil, fmt.Errorf("key 字段解码失败: %w", err)
		}
		return name, certPEM, keyPEM, nil
	}

	// JSON 或 form-urlencoded
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCertBodyBytes))
	if err != nil {
		return "", nil, nil, fmt.Errorf("读取请求体失败: %w", err)
	}

	var req struct {
		Name string `json:"name"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", nil, nil, fmt.Errorf("解析 JSON 失败: %w", err)
	}

	certPEM, err := decodeCertField(req.Cert)
	if err != nil {
		return "", nil, nil, fmt.Errorf("cert 字段解码失败: %w", err)
	}
	keyPEM, err := decodeCertField(req.Key)
	if err != nil {
		return "", nil, nil, fmt.Errorf("key 字段解码失败: %w", err)
	}
	return strings.TrimSpace(req.Name), certPEM, keyPEM, nil
}

// decodeCertField 解码证书/私钥字段：支持裸 PEM 或 base64
func decodeCertField(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	// 裸 PEM
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	// base64 编码的 PEM
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		// 尝试 URL safe base64
		b, err = base64.URLEncoding.DecodeString(v)
		if err != nil {
			// 再次尝试 raw url
			b, err = base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("不是有效的 PEM 或 base64")
			}
		}
	}
	return b, nil
}

// writeDeployError 以 certd 友好格式返回错误
func writeDeployError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"status":  "error",
		"message": message,
	})
}
