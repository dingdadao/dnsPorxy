package dns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"dnsPorxy/internal/querylog"
	"dnsPorxy/internal/utils"
)

// DoHServer DNS over HTTPS 入站服务器（HTTP/1.1 + HTTP/2）
type DoHServer struct {
	addr      string
	path      string
	altSvc    string
	certStore *CertStore
	handler   *RefactoredHandler
	logger    *utils.EnhancedLogger

	server  *http.Server
	ln      net.Listener
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewDoHServer 创建 DoH 服务器
func NewDoHServer(addr, path, altSvc string, certStore *CertStore, handler *RefactoredHandler, logger *utils.EnhancedLogger) *DoHServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &DoHServer{
		addr:      addr,
		path:      path,
		altSvc:    altSvc,
		certStore: certStore,
		handler:   handler,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start 启动 DoH 服务（HTTP/1.1 + HTTP/2）
func (s *DoHServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("DoH server already running")
	}

	mux := http.NewServeMux()
	handler := newDoHHandler(s.path, s.altSvc, querylog.ProtoDoH, s.handler)
	mux.Handle("GET "+s.path, handler)
	mux.Handle("POST "+s.path, handler)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("监听 DoH 端口失败: %w", err)
	}
	s.ln = ln
	s.running = true
	s.mu.Unlock()

	s.logger.Info("🚀 [DoH 服务器启动] ", map[string]interface{}{
		"rule": "DOH_SERVER_START",
		"addr": s.addr,
		"path": s.path,
	})

	go func() {
		var err error
		if s.certStore != nil {
			s.server.TLSConfig = s.certStore.TLSConfig()
			err = s.server.ServeTLS(s.ln, "", "")
		} else {
			err = s.server.Serve(s.ln)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("❌ [DoH 服务器运行失败] ", map[string]interface{}{
				"rule":  "DOH_SERVER_FAILED",
				"error": err.Error(),
			})
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	return nil
}

// Stop 停止 DoH 服务
func (s *DoHServer) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.logger.Info("🔄 [停止 DoH 服务器] ", map[string]interface{}{
		"rule": "DOH_SERVER_STOP",
	})
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}

	time.Sleep(200 * time.Millisecond)
	s.cancel()
	s.logger.Info("✅ [DoH 服务器已停止] ", map[string]interface{}{
		"rule": "DOH_SERVER_STOPPED",
	})
}

// IsRunning 返回运行状态
func (s *DoHServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Addr 返回实际监听的 TCP 地址（未启动时为空）
func (s *DoHServer) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}
