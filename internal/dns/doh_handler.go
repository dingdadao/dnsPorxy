package dns

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"

	"github.com/miekg/dns"
)

const (
	dohMediaType = "application/dns-message"
	maxDoHBody   = 65535
)

// dohHandler 处理 RFC 8484 DoH 查询的 HTTP handler（供 DoH/DoH3 复用）
type dohHandler struct {
	path    string
	altSvc  string
	proto   string // 接入协议标记：DoH 或 DoH3
	handler *RefactoredHandler
}

func newDoHHandler(path, altSvc, proto string, handler *RefactoredHandler) *dohHandler {
	if path == "" {
		path = "/dns-query"
	}
	return &dohHandler{path: path, altSvc: altSvc, proto: proto, handler: handler}
}

// ServeHTTP 实现 http.Handler
func (h *dohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 方法校验
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var body []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		body, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dohMediaType {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDoHBody)
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
	}

	if len(body) == 0 {
		http.Error(w, "empty DNS message", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}

	// 解析客户端 IP 并包装 ResponseWriter（保留来源名，供日志区分经代理/直连）
	clientIP, clientSrc := h.handler.ResolveClientIPFromRequest(r)
	dw := newDoHResponseWriter(w, r, clientIP, clientSrc, h.proto)

	// 设置 Alt-Svc 头（引导客户端使用 DoH3）
	// 必须在 ServeDNS 写入响应头之前设置，否则头信息已被发出，设置无效
	if h.altSvc != "" {
		w.Header().Set("Alt-Svc", h.altSvc)
	}

	// 调用 DNS handler
	h.handler.ServeDNS(dw, msg)
}

// dohResponseWriter 把 http.ResponseWriter 适配为 dns.ResponseWriter
type dohResponseWriter struct {
	w          http.ResponseWriter
	req        *http.Request
	remoteAddr string
	clientIP   netip.Addr
	info       clientInfo
	proto      string // 接入协议标记：DoH 或 DoH3
	written    bool
}

func newDoHResponseWriter(w http.ResponseWriter, req *http.Request, clientIP netip.Addr, source, proto string) *dohResponseWriter {
	info := clientInfo{ip: clientIP, source: source}
	if !clientIP.IsValid() {
		info = clientInfo{ip: parseAddr(req.RemoteAddr), source: "socket"}
	}
	return &dohResponseWriter{
		w:          w,
		req:        req,
		remoteAddr: req.RemoteAddr,
		clientIP:   clientIP,
		info:       info,
		proto:      proto,
	}
}

func (d *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	if d.written {
		return nil
	}
	data, err := m.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", dohMediaType)
	d.w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minTTL(m)))
	d.w.WriteHeader(http.StatusOK)
	_, err = d.w.Write(data)
	if err == nil {
		d.written = true
	}
	return err
}

// Write 处理「缓存命中走 wire 快路径」的直接字节写出。
// 这条路径不经过 WriteMsg，必须在这里补上 RFC 8484 §4.2.1 要求的响应头，
// 否则严格的 DoH 客户端会因缺少 Content-Type（Go 会嗅探成 application/octet-stream）而拒绝响应。
func (d *dohResponseWriter) Write(p []byte) (int, error) {
	if !d.written {
		if d.w.Header().Get("Content-Type") == "" {
			d.w.Header().Set("Content-Type", dohMediaType)
		}
		if d.w.Header().Get("Cache-Control") == "" {
			if m := new(dns.Msg); m.Unpack(p) == nil {
				d.w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minTTL(m)))
			}
		}
		d.w.WriteHeader(http.StatusOK)
		d.written = true
	}
	return d.w.Write(p)
}

func (d *dohResponseWriter) Close() error        { return nil }
func (d *dohResponseWriter) TsigStatus() error   { return nil }
func (d *dohResponseWriter) TsigTimersOnly(bool) {}
func (d *dohResponseWriter) Hijack() {
	// DoH 基于 HTTP 短连接，不支持 Hijack
}

func (d *dohResponseWriter) RemoteAddr() net.Addr {
	return &tcpAddr{d.remoteAddr}
}

func (d *dohResponseWriter) LocalAddr() net.Addr {
	return &tcpAddr{d.req.Host}
}

// clientInfo 返回携带的客户端信息，供 ResolveClientIP 优先读取
func (d *dohResponseWriter) clientInfo() clientInfo {
	return d.info
}

// protocol 返回接入协议标记（DoH 或 DoH3），供解析日志记录
func (d *dohResponseWriter) protocol() string {
	return d.proto
}

// tcpAddr 是 net.Addr 的最小实现
type tcpAddr struct {
	s string
}

func (a *tcpAddr) Network() string { return "tcp" }
func (a *tcpAddr) String() string  { return a.s }

// minTTL 返回响应中最小 TTL，用于 Cache-Control
func minTTL(m *dns.Msg) int {
	if m == nil {
		return 0
	}
	minT := 86400
	for _, rr := range m.Answer {
		if int(rr.Header().Ttl) < minT {
			minT = int(rr.Header().Ttl)
		}
	}
	if minT == 86400 {
		minT = 0
	}
	return minT
}
