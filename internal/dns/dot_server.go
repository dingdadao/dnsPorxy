package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"dnsPorxy/internal/querylog"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// DoTServer DNS over TLS 入站服务器
type DoTServer struct {
	addr      string
	certStore *CertStore
	handler   *RefactoredHandler
	logger    *utils.EnhancedLogger

	server  *dns.Server
	ln      net.Listener
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewDoTServer 创建 DoT 服务器
func NewDoTServer(addr string, certStore *CertStore, handler *RefactoredHandler, logger *utils.EnhancedLogger) *DoTServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &DoTServer{
		addr:      addr,
		certStore: certStore,
		handler:   handler,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start 监听并启动 DoT 服务（非阻塞：同步完成端口绑定后于后台 goroutine 提供服务）
func (s *DoTServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("DoT server already running")
	}

	conf := s.certStore.TLSConfig()
	if conf == nil {
		s.mu.Unlock()
		return fmt.Errorf("TLS 配置未就绪")
	}

	ln, err := tls.Listen("tcp", s.addr, conf)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("监听 DoT 端口失败: %w", err)
	}
	s.ln = ln

	s.server = &dns.Server{
		Listener: ln,
		Handler:  protocolTagHandler{proto: querylog.ProtoDoT, next: s.handler},
		Net:      "tcp-tls",
	}

	s.running = true
	s.mu.Unlock()

	s.logger.Info("🚀 [DoT 服务器启动] ", map[string]interface{}{
		"rule": "DOT_SERVER_START",
		"addr": s.addr,
	})

	// 后台提供 TLS 服务；ShutdownContext 会使 ActivateAndServe 正常返回
	go func() {
		err := s.server.ActivateAndServe()
		s.mu.Lock()
		wasStopping := !s.running
		s.running = false
		s.mu.Unlock()
		if err != nil && !wasStopping {
			s.logger.Error("❌ [DoT 服务器运行失败] ", map[string]interface{}{
				"rule":  "DOT_SERVER_FAILED",
				"error": err.Error(),
			})
		}
	}()

	return nil
}

// Stop 停止 DoT 服务
func (s *DoTServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}

	s.logger.Info("🔄 [停止 DoT 服务器] ", map[string]interface{}{
		"rule": "DOT_SERVER_STOP",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.server != nil {
		_ = s.server.ShutdownContext(ctx)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}

	time.Sleep(200 * time.Millisecond)
	s.cancel()
	s.logger.Info("✅ [DoT 服务器已停止] ", map[string]interface{}{
		"rule": "DOT_SERVER_STOPPED",
	})
}

// IsRunning 返回运行状态
func (s *DoTServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Addr 返回实际监听的 TCP 地址（未启动时为空）
func (s *DoTServer) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}
