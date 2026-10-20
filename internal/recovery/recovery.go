package recovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/dns"
	"dnsPorxy/internal/querylog"
	"dnsPorxy/internal/utils"
	"dnsPorxy/internal/web"
)

// RecoveryManager panic恢复管理器
type RecoveryManager struct {
	config          *config.Config
	logger          *utils.EnhancedLogger
	store           *config.Store
	webServer       *web.Server
	dnsHandler      *dns.RefactoredHandler
	certStore       *dns.CertStore
	queryLog        *querylog.Store // 进程级解析日志库（独立于 DNS 服务生命周期）
	udpServer       *dns.Server
	tcpServer       *dns.Server
	dotServer       *dns.DoTServer
	dohServer       *dns.DoHServer
	doh3Server      *dns.DoH3Server
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	running         bool
	restartCount    int
	panicCount      int
	lastRestart     time.Time
	restartChan     chan bool // true=管理端手动重启（无需退避等待），false=panic/健康检查触发的恢复重启
	maxRestarts     int
	restartInterval time.Duration
	startTime       time.Time
	startWebAddr    string // 进程启动时绑定的 Web 监听地址（用于判断是否需进程级重启）
}

// NewRecoveryManager 创建新的panic恢复管理器
func NewRecoveryManager(cfg *config.Config, logger *utils.EnhancedLogger, store *config.Store) *RecoveryManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &RecoveryManager{
		config:          cfg,
		logger:          logger,
		store:           store,
		ctx:             ctx,
		cancel:          cancel,
		restartChan:     make(chan bool, 1),
		maxRestarts:     100,             // 最大重启次数
		restartInterval: 5 * time.Second, // 初始重启间隔
		running:         false,
		startTime:       time.Now(), // 初始化startTime
		startWebAddr:    cfg.WebAddr,
	}
}

// Start 启动带panic恢复的服务
func (rm *RecoveryManager) Start() error {
	rm.logger.Info("🔄 [启动恢复管理器] ", map[string]interface{}{
		"rule": "RECOVERY_MANAGER_START",
	})

	// 设置信号处理
	rm.setupSignalHandler()

	// 打开进程级解析日志库（失败仅告警，不影响 DNS 解析）
	rm.startQueryLog()

	// 启动DNS服务
	if err := rm.startDNSService(); err != nil {
		return fmt.Errorf("启动DNS服务失败: %w", err)
	}

	// 启动Web管理端（配置保存在SQLite，管理端独立于DNS服务生命周期）
	rm.startWebServer()

	// 主循环
	rm.mainLoop()

	return nil
}

// GetDNSHandler 获取当前DNS处理器（web层配置热更新/规则重载使用）
func (rm *RecoveryManager) GetDNSHandler() *dns.RefactoredHandler {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.dnsHandler
}

// GetCertStore 获取当前证书存储（web 层证书 API 使用）
func (rm *RecoveryManager) GetCertStore() *dns.CertStore {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.certStore
}

// processRestartDelay 进程级重启前的等待：先让 HTTP 响应写回客户端，再终止自身
const processRestartDelay = 800 * time.Millisecond

// RequestRestart 管理端触发：按配置库中的最新配置重启服务。
// systemd 托管时执行进程级重启，使 Web 监听地址、日志格式等启动期字段一并生效；
// 非 systemd 运行（如本地直接运行）退回进程内重建 DNS 服务，此时 Web 地址变更不会生效。
func (rm *RecoveryManager) RequestRestart() (web.RestartOutcome, error) {
	if rm.store == nil {
		return web.RestartOutcome{}, fmt.Errorf("配置库不可用")
	}
	if rm.GetDNSHandler() == nil {
		return web.RestartOutcome{}, fmt.Errorf("DNS服务未在运行")
	}

	cfg, err := rm.store.LoadConfig()
	if err != nil {
		return web.RestartOutcome{}, fmt.Errorf("加载配置失败: %w", err)
	}
	if err := config.ValidateConfig(cfg); err != nil {
		return web.RestartOutcome{}, fmt.Errorf("配置无效: %w", err)
	}

	rm.mu.Lock()
	rm.config = cfg // 退回进程内重启时 startDNSService 以该配置重建处理器
	webAddrChanged := cfg.WebAddr != rm.startWebAddr
	rm.mu.Unlock()

	out := web.RestartOutcome{
		ProcessRestart: systemdUnitName() != "",
		WebAddrChanged: webAddrChanged,
	}
	if webAddrChanged {
		out.WebAddr = cfg.WebAddr
	}

	rm.logger.Warn("🔄 [管理端请求重启服务] ", map[string]interface{}{
		"rule":             "WEB_RESTART_REQUESTED",
		"process_restart":  out.ProcessRestart,
		"web_addr_changed": webAddrChanged,
	})

	// 进程级重启会终止当前进程，故延迟到 HTTP 响应写回后再执行
	go func() {
		time.Sleep(processRestartDelay)
		if out.ProcessRestart && rm.restartProcess() {
			return
		}
		// 非 systemd 托管或重启命令下发失败：退回进程内重建 DNS 服务
		select {
		case rm.restartChan <- true:
		default:
			// 已有重启在排队：其执行时读取的是最新配置，无需重复入队
		}
	}()
	return out, nil
}

// restartProcess 向 systemd 下发进程级重启（systemctl --no-block restart <unit>）
func (rm *RecoveryManager) restartProcess() bool {
	unit := systemdUnitName()
	if unit == "" {
		return false
	}
	if err := exec.Command("systemctl", "--no-block", "restart", unit).Run(); err != nil {
		rm.logger.Warn("⚠️ [进程级重启下发失败，退回进程内重启] ", map[string]interface{}{
			"rule":  "PROCESS_RESTART_FAILED",
			"unit":  unit,
			"error": err.Error(),
		})
		return false
	}
	rm.logger.Warn("🔄 [已下发进程级重启] ", map[string]interface{}{
		"rule": "PROCESS_RESTART_REQUESTED",
		"unit": unit,
	})
	return true
}

// systemdUnitName 从 /proc/self/cgroup 解析当前服务所属的 systemd 单元名（如 dnsproxy.service）
// 返回空字符串表示当前进程不由 systemd 托管（如 macOS/本地直接运行）
func systemdUnitName() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		_, path, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// cgroup v2 形如 0::/system.slice/dnsproxy.service；v1 形如 1:name=systemd:/system.slice/dnsproxy.service
		if i := strings.LastIndex(path, "/"); i >= 0 {
			if name := path[i+1:]; strings.HasSuffix(name, ".service") {
				return name
			}
		}
	}
	return ""
}

// startQueryLog 打开进程级解析日志库（独立 SQLite，与配置库分离）
func (rm *RecoveryManager) startQueryLog() {
	opt := rm.config.QueryLog
	store, err := querylog.Open(config.DefaultQueryLogPath, rm.logger, querylog.Options{
		Enabled:   opt.Enabled,
		Retention: opt.Retention,
		MaxRows:   opt.MaxRows,
	})
	if err != nil {
		rm.logger.Warn("⚠️ [解析日志库打开失败，将不记录解析日志] ", map[string]interface{}{
			"rule":  "QUERY_LOG_OPEN_FAILED",
			"path":  config.DefaultQueryLogPath,
			"error": err.Error(),
		})
		return
	}
	rm.queryLog = store
	rm.logger.Info("📝 [解析日志库已就绪] ", map[string]interface{}{
		"rule":      "QUERY_LOG_READY",
		"path":      config.DefaultQueryLogPath,
		"enabled":   opt.Enabled,
		"retention": opt.Retention.String(),
		"max_rows":  opt.MaxRows,
	})
}

// startWebServer 启动Web管理端（失败不阻塞DNS服务）
func (rm *RecoveryManager) startWebServer() {
	if rm.store == nil {
		return
	}

	rm.webServer = web.NewServer(rm.store, rm.logger, rm.GetDNSHandler, rm.GetCertStore, rm.RequestRestart, rm.queryLog)
	rm.webServer.SetWebTLS(rm.config.WebTLS)
	httpAddr := rm.config.WebAddr
	if httpAddr == "" {
		httpAddr = config.DefaultWebAddr
	}
	tlsAddr := rm.config.WebTLSAddr
	if tlsAddr == "" {
		tlsAddr = config.DefaultWebTLSAddr
	}
	if err := rm.webServer.Start(httpAddr, tlsAddr); err != nil {
		rm.logger.Warn("⚠️ [Web管理端启动失败] ", map[string]interface{}{
			"rule":  "WEB_SERVER_START_FAILED",
			"addr":  httpAddr,
			"error": err.Error(),
		})
	}
}

// reloadConfig 从配置库重新加载配置并热更新（SIGHUP触发）
func (rm *RecoveryManager) reloadConfig() {
	if rm.store == nil {
		return
	}

	cfg, err := rm.store.LoadConfig()
	if err != nil {
		rm.logger.Error("❌ [配置重载失败] ", map[string]interface{}{
			"rule":  "CONFIG_RELOAD_FAILED",
			"error": err.Error(),
		})
		return
	}

	handler := rm.GetDNSHandler()
	if handler == nil {
		rm.logger.Warn("⚠️ [配置重载跳过] DNS处理器不存在")
		return
	}

	needsRestart := handler.ApplyConfig(cfg)
	rm.logger.Info("🔄 [配置已重载] ", map[string]interface{}{
		"rule":             "CONFIG_RELOADED",
		"restart_required": needsRestart,
	})
}

// mainLoop 主循环
func (rm *RecoveryManager) mainLoop() {
	rm.logger.Info("🔄 [进入主循环] ", map[string]interface{}{
		"rule": "MAIN_LOOP_START",
	})

	for {
		select {
		case <-rm.ctx.Done():
			rm.logger.Info("🛑 [主循环退出] ", map[string]interface{}{
				"rule": "MAIN_LOOP_EXIT",
			})
			return

		case manual := <-rm.restartChan:
			rm.handleRestart(manual)

		case <-time.After(30 * time.Second):
			// 定期健康检查
			rm.healthCheck()
			// 检查上下文是否被取消，避免在长时间运行后无法退出
			if rm.ctx.Err() != nil {
				return
			}
		}
	}
}

// startDNSService 启动DNS服务（带panic恢复）
func (rm *RecoveryManager) startDNSService() error {
	defer func() {
		if r := recover(); r != nil {
			rm.handlePanic(r)
		}
	}()

	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.logger.Info("🚀 [启动DNS服务] ", map[string]interface{}{
		"rule": "DNS_SERVICE_START",
		"port": rm.config.ListenPort,
	})

	// 初始化证书存储（TLS/QUIC 共用）
	certStore, err := rm.loadCertStore()
	if err != nil {
		rm.logger.Warn("⚠️ [证书加载失败，继续启动] ", map[string]interface{}{
			"rule":  "CERT_STORE_LOAD_FAILED",
			"error": err.Error(),
		})
		// 未启用入站加密服务时，证书失败不应阻塞启动
		if rm.config.EnableDoT || rm.config.EnableDoH || rm.config.EnableDoH3 {
			return fmt.Errorf("启用入站加密服务时证书加载失败: %w", err)
		}
	}
	rm.certStore = certStore

	// 创建DNS处理器
	handler, err := dns.NewRefactoredHandler(rm.config, rm.logger, rm.queryLog)
	if err != nil {
		return fmt.Errorf("创建DNS处理器失败: %w", err)
	}
	rm.dnsHandler = handler

	// 从配置库加载本地域名篡改规则
	if rm.store != nil {
		if list, err := rm.store.ListOverrides(); err != nil {
			rm.logger.Warn("⚠️ [域名篡改规则加载失败] ", map[string]interface{}{
				"rule":  "OVERRIDE_LOAD_FAILED",
				"error": err.Error(),
			})
		} else {
			handler.LoadOverrides(list)
		}
	}

	// 创建UDP DNS服务器
	udpServer, err := dns.NewUDPServer(rm.config, handler)
	if err != nil {
		return fmt.Errorf("创建UDP DNS服务器失败: %w", err)
	}

	// 创建TCP DNS服务器
	tcpServer, err := dns.NewTCPServer(rm.config, handler)
	if err != nil {
		return fmt.Errorf("创建TCP DNS服务器失败: %w", err)
	}

	// 创建一个临时的UDP连接来验证端口可用性
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", rm.config.ListenPort))
	if err != nil {
		return fmt.Errorf("解析UDP地址失败: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		rm.logger.Error("❌ [UDP端口检查失败] ", map[string]interface{}{
			"rule":  "PORT_CHECK_FAILED",
			"type":  "UDP",
			"error": err.Error(),
		})
		return fmt.Errorf("UDP端口 %d 已被占用: %w", rm.config.ListenPort, err)
	}
	udpConn.Close()

	// 创建一个临时的TCP连接来验证端口可用性
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", rm.config.ListenPort))
	if err != nil {
		rm.logger.Error("❌ [TCP端口检查失败] ", map[string]interface{}{
			"rule":  "PORT_CHECK_FAILED",
			"type":  "TCP",
			"error": err.Error(),
		})
		return fmt.Errorf("TCP端口 %d 已被占用: %w", rm.config.ListenPort, err)
	}
	tcpListener.Close()

	// 设置服务器实例
	rm.udpServer = udpServer
	rm.tcpServer = tcpServer

	// 在单独的goroutine中启动UDP服务器（带panic恢复）
	go rm.runDNSServer(udpServer, "UDP")

	// 在单独的goroutine中启动TCP服务器（带panic恢复）
	go rm.runDNSServer(tcpServer, "TCP")

	// 启动 DoT 入站服务
	if rm.config.EnableDoT {
		if err := rm.startDoTServer(handler); err != nil {
			return fmt.Errorf("启动DoT服务失败: %w", err)
		}
	}

	// 启动 DoH 入站服务
	if rm.config.EnableDoH {
		if err := rm.startDoHServer(handler); err != nil {
			return fmt.Errorf("启动DoH服务失败: %w", err)
		}
	}

	// 启动 DoH3 入站服务
	if rm.config.EnableDoH3 {
		if err := rm.startDoH3Server(handler); err != nil {
			return fmt.Errorf("启动DoH3服务失败: %w", err)
		}
	}

	rm.running = true
	rm.logger.Info("✅ [DNS服务启动成功] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STARTED",
	})

	return nil
}

// certRecordToDNS 将 config.CertRecord 转换为 dns.CertRecord
func certRecordToDNS(r config.CertRecord) dns.CertRecord {
	return dns.CertRecord{
		ID:          r.ID,
		Name:        r.Name,
		Domains:     r.Domains,
		CertPath:    r.CertPath,
		KeyPath:     r.KeyPath,
		Fingerprint: r.Fingerprint,
		NotBefore:   r.NotBefore,
		NotAfter:    r.NotAfter,
		Source:      dns.CertSource(r.Source),
		UpdatedAt:   r.UpdatedAt,
	}
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

// loadCertStore 从数据库与约定目录加载证书；失败时返回 nil
func (rm *RecoveryManager) loadCertStore() (*dns.CertStore, error) {
	if rm.config.CertStoreDir == "" {
		return nil, fmt.Errorf("证书存储目录未配置")
	}

	certStore := dns.NewCertStore(rm.config.CertStoreDir, rm.config.CertDefault, rm.logger)

	// 1. 从数据库加载已有证书元数据
	if rm.store != nil {
		records, err := rm.store.ListCerts()
		if err != nil {
			return nil, fmt.Errorf("读取数据库证书失败: %w", err)
		}
		dnsRecords := make([]dns.CertRecord, len(records))
		for i, r := range records {
			dnsRecords[i] = certRecordToDNS(r)
		}
		if err := certStore.LoadRecords(dnsRecords); err != nil {
			return nil, fmt.Errorf("加载证书记录失败: %w", err)
		}
	}

	// 2. 扫描目录发现新证书（如 SSH 同步放入的 cert/key），并同步到数据库
	scanned, err := certStore.ScanDir()
	if err != nil {
		return nil, fmt.Errorf("扫描证书目录失败: %w", err)
	}
	if rm.store != nil && len(scanned) > 0 {
		// 以 fingerprint 为键，避免重复写入
		existing, err := rm.store.ListCerts()
		if err != nil {
			return nil, fmt.Errorf("读取已有证书失败: %w", err)
		}
		fpSet := make(map[string]struct{}, len(existing))
		for _, r := range existing {
			fpSet[r.Fingerprint] = struct{}{}
		}
		for _, r := range scanned {
			if _, ok := fpSet[r.Fingerprint]; ok {
				continue
			}
			rec := certRecordToConfig(r)
			if err := rm.store.AddOrReplaceCert(&rec); err != nil {
				rm.logger.Warn("⚠️ [扫描证书持久化失败] ", map[string]interface{}{
					"rule":  "CERT_SCAN_PERSIST_FAILED",
					"name":  r.Name,
					"error": err.Error(),
				})
			}
		}
	}

	return certStore, nil
}

// startDoTServer 启动 DoT 入站服务
func (rm *RecoveryManager) startDoTServer(handler *dns.RefactoredHandler) error {
	if rm.certStore == nil {
		return fmt.Errorf("证书存储未就绪")
	}
	server := dns.NewDoTServer(rm.config.DoTAddr, rm.certStore, handler, rm.logger)
	if err := server.Start(); err != nil {
		return err
	}
	rm.dotServer = server
	return nil
}

// startDoHServer 启动 DoH 入站服务
func (rm *RecoveryManager) startDoHServer(handler *dns.RefactoredHandler) error {
	if rm.certStore == nil {
		return fmt.Errorf("证书存储未就绪")
	}
	server := dns.NewDoHServer(rm.config.DoHAddr, rm.config.DoHPath, rm.config.DoHAltSvc, rm.certStore, handler, rm.logger)
	if err := server.Start(); err != nil {
		return err
	}
	rm.dohServer = server
	return nil
}

// startDoH3Server 启动 DoH3 入站服务
func (rm *RecoveryManager) startDoH3Server(handler *dns.RefactoredHandler) error {
	if rm.certStore == nil {
		return fmt.Errorf("证书存储未就绪")
	}
	server := dns.NewDoH3Server(rm.config.DoH3Addr, rm.config.DoHPath, rm.certStore, handler, rm.logger)
	if err := server.Start(); err != nil {
		return err
	}
	rm.doh3Server = server
	return nil
}

// runDNSServer 运行DNS服务器（带panic恢复）
func (rm *RecoveryManager) runDNSServer(server *dns.Server, serverType string) {
	defer func() {
		if r := recover(); r != nil {
			rm.handlePanic(r)
			// 触发重启
			select {
			case rm.restartChan <- false:
			default:
			}
		}
	}()

	if err := server.Start(); err != nil {
		rm.logger.Error("❌ [DNS服务器运行失败] ", map[string]interface{}{
			"rule":  "DNS_SERVER_FAILED",
			"type":  serverType,
			"error": err.Error(),
		})

		// 检查错误是否是端口被占用
		if strings.Contains(err.Error(), "address already in use") ||
			strings.Contains(err.Error(), "bind: address already in use") {
			rm.logger.Warn("⚠️ [端口已被占用，不触发重启] ", map[string]interface{}{
				"rule": "PORT_ALREADY_IN_USE_NO_RESTART",
				"type": serverType,
			})
			return // 端口被占用时不触发重启
		}

		// 触发重启
		select {
		case rm.restartChan <- false:
		default:
		}
	}
}

// stopDNSService 停止DNS服务
func (rm *RecoveryManager) stopDNSService() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.running {
		return
	}

	rm.logger.Info("🔄 [停止DNS服务] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STOP",
	})

	// 停止 DoH3 入站服务器
	if rm.doh3Server != nil {
		rm.doh3Server.Stop()
		rm.doh3Server = nil
	}

	// 停止 DoH 入站服务器
	if rm.dohServer != nil {
		rm.dohServer.Stop()
		rm.dohServer = nil
	}

	// 停止 DoT 入站服务器
	if rm.dotServer != nil {
		rm.dotServer.Stop()
		rm.dotServer = nil
	}

	// 停止UDP DNS服务器
	if rm.udpServer != nil {
		rm.udpServer.Stop()
		rm.udpServer = nil
	}

	// 停止TCP DNS服务器
	if rm.tcpServer != nil {
		rm.tcpServer.Stop()
		rm.tcpServer = nil
	}

	// 确保服务器完全停止后等待一段时间，避免端口立即被重用
	time.Sleep(100 * time.Millisecond)

	// 关闭DNS处理器
	if rm.dnsHandler != nil {
		rm.dnsHandler.Close()
		rm.dnsHandler = nil
	}

	rm.certStore = nil
	rm.running = false
	rm.logger.Info("✅ [DNS服务已停止] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STOPPED",
	})
}

// handlePanic 处理panic
func (rm *RecoveryManager) handlePanic(r interface{}) {
	rm.panicCount++

	// 获取调用栈
	stack := debug.Stack()

	rm.logger.Error("💥 [检测到Panic] ", map[string]interface{}{
		"rule":        "PANIC_DETECTED",
		"panic_msg":   fmt.Sprintf("%v", r),
		"panic_count": rm.panicCount,
		"stack_trace": string(stack),
	})

	// 记录更详细的运行时信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rm.logger.Debug("💾 运行时内存信息", map[string]interface{}{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         m.NumGC,
		"goroutines":     runtime.NumGoroutine(),
	})

	// 触发重启
	select {
	case rm.restartChan <- false:
	default:
	}
}

// handleRestart 处理重启（manual=true 为管理端主动触发，跳过恢复用的退避等待以缩短中断）
func (rm *RecoveryManager) handleRestart(manual bool) {
	rm.restartCount++
	rm.lastRestart = time.Now()

	rm.logger.Warn("🔄 [开始服务重启] ", map[string]interface{}{
		"rule":          "SERVICE_RESTART",
		"manual":        manual,
		"restart_count": rm.restartCount,
		"panic_count":   rm.panicCount,
	})

	// 检查重启次数限制
	if rm.restartCount > rm.maxRestarts {
		rm.logger.Error("❌ [重启次数超限，服务退出] ", map[string]interface{}{
			"rule":          "RESTART_LIMIT_EXCEEDED",
			"restart_count": rm.restartCount,
			"max_restarts":  rm.maxRestarts,
		})
		rm.cancel()
		return
	}

	// 停止当前服务
	rm.stopDNSService()

	// 额外等待一段时间确保端口完全释放
	time.Sleep(500 * time.Millisecond)

	// 等待一段时间后重启
	wait := rm.restartInterval
	if manual {
		wait = 0 // 手动重启不做退避等待，仅保留上方端口释放的缓冲
	}
	rm.logger.Debug("⏱️ 等待重启间隔", map[string]interface{}{
		"interval": wait.String(),
	})
	time.Sleep(wait)

	// 重新启动服务
	if err := rm.startDNSService(); err != nil {
		rm.logger.Error("❌ [重启DNS服务失败] ", map[string]interface{}{
			"rule":  "RESTART_FAILED",
			"error": err.Error(),
		})

		// 增加重启间隔并再次尝试
		rm.restartInterval = time.Duration(float64(rm.restartInterval) * 1.5)
		if rm.restartInterval > 60*time.Second {
			rm.restartInterval = 60 * time.Second
		}

		time.Sleep(rm.restartInterval)
		select {
		case rm.restartChan <- manual:
		default:
		}
		return
	}

	rm.logger.Info("✅ [服务重启成功] ", map[string]interface{}{
		"rule":          "SERVICE_RESTARTED",
		"restart_count": rm.restartCount,
	})

	// 重置重启间隔
	rm.restartInterval = 5 * time.Second
}

// healthCheck 健康检查
func (rm *RecoveryManager) healthCheck() {
	rm.mu.RLock()
	running := rm.running
	rm.mu.RUnlock()

	if !running {
		rm.logger.Warn("⚠️ [健康检查失败] ", map[string]interface{}{
			"rule":   "HEALTH_CHECK_FAILED",
			"reason": "service_not_running",
		})

		// 触发重启
		select {
		case rm.restartChan <- false:
		default:
		}
		return
	}

	// 检查内存使用情况
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / 1024 / 1024
	if allocMB > 500 { // 如果内存使用超过500MB
		rm.logger.Warn("⚠️ [内存使用过高] ", map[string]interface{}{
			"rule":     "HIGH_MEMORY_USAGE",
			"alloc_mb": allocMB,
		})

		// 强制GC
		runtime.GC()
	}

	// 获取统计信息以显示IP统计
	stats := rm.GetStats()
	cacheInfo, ok := stats["cache"].(map[string]interface{})

	logFields := map[string]interface{}{
		"uptime":        time.Since(rm.startTime).String(),
		"restart_count": rm.restartCount,
		"panic_count":   rm.panicCount,
		"memory_mb":     allocMB,
		"goroutines":    runtime.NumGoroutine(),
	}

	// 添加缓存IP统计信息到日志
	if ok && cacheInfo != nil {
		if ipCounts, exists := cacheInfo["ip_counts"].(map[string]interface{}); exists {
			logFields["cached_a_records"] = ipCounts["A"]
			logFields["cached_aaaa_records"] = ipCounts["AAAA"]
			logFields["total_cached_ips"] = ipCounts["A"]
			if aaaaCount, ok := ipCounts["AAAA"].(int); ok {
				if aCount, ok := ipCounts["A"].(int); ok {
					logFields["total_cached_ips"] = aCount + aaaaCount
				}
			}
		}
		logFields["cache_size"] = cacheInfo["size"]
		logFields["cache_valid_entries"] = cacheInfo["valid_entries"]
	}

	rm.logger.Debug("✅ 健康检查通过", logFields)
}

// setupSignalHandler 设置信号处理
func (rm *RecoveryManager) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // 终止信号
		syscall.SIGQUIT, // 退出信号
		syscall.SIGHUP,  // 挂起信号（重新加载配置）
	)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				rm.handlePanic(r)
			}
		}()

		for {
			select {
			case sig := <-sigChan:
				rm.handleSignal(sig)
			case <-rm.ctx.Done():
				return
			}
		}
	}()
}

// handleSignal 处理系统信号
func (rm *RecoveryManager) handleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGHUP:
		rm.logger.Info("🔄 [接收到SIGHUP信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": "SIGHUP",
			"action": "reload_config",
		})
		rm.reloadConfig()

	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
		rm.logger.Info("📪 [接收到退出信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": sig.String(),
			"action": "graceful_shutdown",
		})
		// 立即开始优雅退出，不等待
		go rm.gracefulShutdown()
	}
}

// gracefulShutdown 优雅退出
func (rm *RecoveryManager) gracefulShutdown() {
	rm.logger.Info("🔄 [开始优雅退出] ", map[string]interface{}{
		"rule": "GRACEFUL_SHUTDOWN_START",
	})

	// 设置优雅关闭超时
	shutdownTimeout := 10 * time.Second
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// 在单独的goroutine中停止服务
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 停止服务
		rm.stopDNSService()
		// 关闭Web管理端
		if rm.webServer != nil {
			webCtx, webCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer webCancel()
			if err := rm.webServer.Shutdown(webCtx); err != nil {
				rm.logger.Warn("⚠️ [Web管理端关闭警告] ", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}
		// 额外等待一段时间确保端口完全释放
		time.Sleep(500 * time.Millisecond)
		// 关闭解析日志库（落库剩余日志）
		if rm.queryLog != nil {
			if err := rm.queryLog.Close(); err != nil {
				rm.logger.Warn("⚠️ [解析日志库关闭警告] ", map[string]interface{}{
					"error": err.Error(),
				})
			}
			rm.queryLog = nil
		}
		// 取消上下文
		rm.cancel()
	}()

	// 等待服务停止或超时
	select {
	case <-done:
		rm.logger.Info("✅ [优雅退出完成] ", map[string]interface{}{
			"rule":          "GRACEFUL_SHUTDOWN_COMPLETE",
			"uptime":        time.Since(rm.startTime).String(),
			"restart_count": rm.restartCount,
			"panic_count":   rm.panicCount,
		})
	case <-shutdownCtx.Done():
		rm.logger.Warn("⚠️ [优雅退出超时，强制退出] ", map[string]interface{}{
			"rule":    "GRACEFUL_SHUTDOWN_TIMEOUT",
			"timeout": shutdownTimeout.String(),
		})
		// 强制退出
		os.Exit(1)
	}
}

// GetStats 获取统计信息
func (rm *RecoveryManager) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := map[string]interface{}{
		"running":         rm.running,
		"restart_count":   rm.restartCount,
		"panic_count":     rm.panicCount,
		"uptime":          time.Since(rm.startTime).String(),
		"memory_alloc_mb": m.Alloc / 1024 / 1024,
		"goroutines":      runtime.NumGoroutine(),
		"max_restarts":    rm.maxRestarts,
	}

	// 如果DNS处理器存在，添加缓存统计信息
	if rm.dnsHandler != nil && rm.dnsHandler.GetCacheManager() != nil {
		// 获取缓存统计信息（不包含详细条目信息以节省资源）
		cacheStats := rm.dnsHandler.GetCacheManager().GetStats(false)
		if cacheStats != nil {
			cacheInfo := map[string]interface{}{
				"size":          cacheStats.Size,
				"max_size":      cacheStats.MaxSize,
				"valid_entries": cacheStats.ValidEntries,
				"expired_count": cacheStats.ExpiredCount,
			}
			// 添加IP统计信息
			if cacheStats.IPCounts != nil {
				cacheInfo["ip_counts"] = cacheStats.IPCounts
			}
			stats["cache"] = cacheInfo

			// 获取热点条目（前10个）
			hotEntries := rm.dnsHandler.GetCacheManager().GetHotEntries(10)
			if len(hotEntries) > 0 {
				hotEntryList := make([]map[string]interface{}, 0, len(hotEntries))
				for _, entry := range hotEntries {
					hotEntryList = append(hotEntryList, map[string]interface{}{
						"domain":      entry.Domain,
						"qtype":       entry.QType,
						"last_access": entry.LastAccess.Format(time.RFC3339),
					})
				}
				stats["hot_entries"] = hotEntryList
			}

			// 获取过期条目（前10个）
			if len(cacheStats.ExpiredEntries) > 0 {
				limit := 10
				if len(cacheStats.ExpiredEntries) < limit {
					limit = len(cacheStats.ExpiredEntries)
				}
				expiredList := make([]string, 0, limit)
				for i := 0; i < limit; i++ {
					expiredList = append(expiredList, cacheStats.ExpiredEntries[i])
				}
				stats["expired_entries"] = expiredList
			}
		}
	}

	if !rm.lastRestart.IsZero() {
		stats["last_restart"] = rm.lastRestart.Format(time.RFC3339)
		stats["time_since_restart"] = time.Since(rm.lastRestart).String()
	}

	return stats
}
