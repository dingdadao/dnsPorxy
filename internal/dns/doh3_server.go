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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DoH3Server DNS over HTTPS/3 入站服务器（QUIC/HTTP3）
type DoH3Server struct {
	addr      string
	path      string
	certStore *CertStore
	handler   *RefactoredHandler
	logger    *utils.EnhancedLogger

	server  *http3.Server
	conn    net.PacketConn
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewDoH3Server 创建 DoH3 服务器
func NewDoH3Server(addr, path string, certStore *CertStore, handler *RefactoredHandler, logger *utils.EnhancedLogger) *DoH3Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &DoH3Server{
		addr:      addr,
		path:      path,
		certStore: certStore,
		handler:   handler,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start 启动 DoH3 服务（QUIC/HTTP3）
func (s *DoH3Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("DoH3 server already running")
	}

	conf := s.certStore.TLSConfig()
	if conf == nil {
		s.mu.Unlock()
		return fmt.Errorf("TLS 配置未就绪")
	}

	// 监听 UDP 端口；QUIC 目前仅支持 UDP
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("监听 DoH3 端口失败: %w", err)
	}
	s.conn = conn

	handler := newDoHHandler(s.path, "", querylog.ProtoDoH3, s.handler)
	s.server = &http3.Server{
		Addr:      s.addr,
		Handler:   handler,
		TLSConfig: conf,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  3 * time.Minute,
			KeepAlivePeriod: 30 * time.Second,
		},
		IdleTimeout: 3 * time.Minute,
	}

	s.running = true
	s.mu.Unlock()

	s.logger.Info("🚀 [DoH3 服务器启动] ", map[string]interface{}{
		"rule": "DOH3_SERVER_START",
		"addr": s.addr,
		"path": s.path,
	})

	go func() {
		// Serve 在 s.server.Close/Shutdown 时返回，不会关闭外部传入的 PacketConn
		err := s.server.Serve(conn)
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("❌ [DoH3 服务器运行失败] ", map[string]interface{}{
				"rule":  "DOH3_SERVER_FAILED",
				"error": err.Error(),
			})
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	return nil
}

// Stop 停止 DoH3 服务
func (s *DoH3Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.logger.Info("🔄 [停止 DoH3 服务器] ", map[string]interface{}{
		"rule": "DOH3_SERVER_STOP",
	})
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}

	time.Sleep(200 * time.Millisecond)
	s.cancel()
	s.logger.Info("✅ [DoH3 服务器已停止] ", map[string]interface{}{
		"rule": "DOH3_SERVER_STOPPED",
	})
}

// IsRunning 返回运行状态
func (s *DoH3Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Addr 返回实际监听的 UDP 地址（未启动时为空）
func (s *DoH3Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn == nil {
		return ""
	}
	return s.conn.LocalAddr().String()
}
