package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/querylog"
	"dnsPorxy/internal/source"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// hasModernProtocols 检查是否包含现代协议或新格式（统一URL scheme）
func hasModernProtocols(upstreams []string) bool {
	for _, upstream := range upstreams {
		if strings.HasPrefix(upstream, "udp://") ||
			strings.HasPrefix(upstream, "tcp://") ||
			strings.HasPrefix(upstream, "https://") ||
			strings.HasPrefix(upstream, "tls://") ||
			strings.HasPrefix(upstream, "h3://") {
			return true
		}
	}
	return false
}

// getProtocolTypes 获取协议类型列表
func getProtocolTypes(upstreams []string) []string {
	protocolSet := make(map[string]bool)
	for _, upstream := range upstreams {
		if strings.HasPrefix(upstream, "udp://") {
			protocolSet["UDP"] = true
		} else if strings.HasPrefix(upstream, "tcp://") {
			protocolSet["TCP"] = true
		} else if strings.HasPrefix(upstream, "https://") {
			protocolSet["DoH"] = true
		} else if strings.HasPrefix(upstream, "tls://") {
			protocolSet["DoT"] = true
		} else if strings.HasPrefix(upstream, "h3://") {
			protocolSet["DoH3"] = true
		} else {
			protocolSet["UDP/TCP"] = true
		}
	}

	var protocols []string
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}
	return protocols
}

// RefactoredHandler 重构后的DNS处理器
type RefactoredHandler struct {
	cfgMu  sync.RWMutex
	config *config.Config
	Logger *utils.EnhancedLogger // 改为公共字段

	// 核心组件
	cacheManager   *CacheManager
	cloudDetector  *CloudDetector
	queryOptimizer interface{} // 可以是 *FastQueryOptimizer 或 *SimpleModernOptimizer
	matcherHandler *MatcherHandler
	cloudHandler   *CloudHandler
	refreshHandler *RefreshHandler
	fileLoader     *FileLoader
	taskScheduler  *TaskScheduler

	// 新增处理器
	cnameProcessor  *CNAMEProcessor
	cloudProcessor  *CloudProcessor
	overrideMatcher *OverrideMatcher // 本地域名篡改匹配器（最高优先级）

	// 入站加密与客户端维度分流
	certStore          *CertStore
	clientGroupMatcher *ClientGroupMatcher

	// 并发 miss 合并：同一 scope+域名+qtype+模式+上游集合的回源只发一次
	upstreamFlight singleflight.Group

	// 运营商段库（按运营商自动分组的数据来源）
	ispDB          *source.DB // nil 表示当前未启用运营商识别
	ispDBDir       string     // 已加载的段库目录，用于识别目录变更
	sourceAutoStop func()     // 段库定时更新停止函数；nil 表示未启用
	sourceAutoKey  string     // 已生效的自动更新参数（baseURL|hours），用于识别参数变更

	// 解析日志（进程级，独立于处理器生命周期，可为 nil 表示不记录）
	queryLog *querylog.Store

	// 连接池
	dotConnPool  *DoTConnPool
	dohConnPool  *DoHConnPool
	doh3ConnPool *DoH3ConnPool
	udpConnPool  *UDPConnPool
	tcpConnPool  *TCPConnPool

	ctx    context.Context
	cancel context.CancelFunc
}

// NewRefactoredHandler 创建新的重构后处理器（qlog 为进程级解析日志库，可为 nil）
func NewRefactoredHandler(cfg *config.Config, logger *utils.EnhancedLogger, qlog *querylog.Store) (*RefactoredHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建核心组件（移除指标系统）
	cloudDetector := NewCloudDetector(logger, nil)

	// 设置替换域名配置
	cloudDetector.SetReplaceDomains(cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)
	cloudDetector.SetReplaceDomainsAll(allReplaceDomains(cfg))

	// 创建连接池
	dotConnPool := NewDoTConnPool()
	dotConnPool.SetBootstrapResolver(cfg.Upstream) // 用 UDP 上游解析 DoT 主机名，不依赖系统 DNS
	dohConnPool := NewDoHConnPool()
	doh3ConnPool := NewDoH3ConnPool()
	udpConnPool := NewUDPConnPool()
	tcpConnPool := NewTCPConnPool()

	// 创建缓存管理器（云检测统一在查询流程中执行，缓存层不做云检测）
	cacheManager := NewCacheManager(cfg, logger)

	// 初始化处理器结构体
	handler := &RefactoredHandler{
		config:        cfg,
		Logger:        logger, // 使用公共字段
		cacheManager:  cacheManager,
		cloudDetector: cloudDetector,
		dotConnPool:   dotConnPool,
		dohConnPool:   dohConnPool,
		doh3ConnPool:  doh3ConnPool,
		udpConnPool:   udpConnPool,
		tcpConnPool:   tcpConnPool,
		queryLog:      qlog,
		ctx:           ctx,
		cancel:        cancel,
	}

	// 根据上游配置选择查询优化器
	var queryOptimizer interface{}
	if hasModernProtocols(cfg.Upstream) {
		// 使用简化的现代查询优化器，传入现代协议超时
		modernOptimizer := NewSimpleModernOptimizer(logger, cfg.Timeout, cfg.ModernTimeout)
		// 设置各种协议的查询函数，使用连接池
		modernOptimizer.udpQueryFunc = handler.getUDPQueryFunc()
		modernOptimizer.tcpQueryFunc = handler.getTCPQueryFunc()
		modernOptimizer.doHQueryFunc = handler.getDoHQueryFunc()
		modernOptimizer.doTQueryFunc = handler.getDoTQueryFunc()
		modernOptimizer.doH3QueryFunc = handler.getDoH3QueryFunc()
		queryOptimizer = modernOptimizer
		logger.Info("🚀 [使用现代DNS查询优化器] ", map[string]interface{}{
			"rule":           "MODERN_OPTIMIZER_SELECTED",
			"protocols":      getProtocolTypes(cfg.Upstream),
			"timeout":        cfg.Timeout.String(),
			"modern_timeout": cfg.ModernTimeout.String(),
		})
	} else {
		// 使用传统查询优化器
		queryOptimizer = NewFastQueryOptimizer(logger, nil, cfg.Timeout)
		logger.Info("🚀 [使用传统 DNS查询优化器] ", map[string]interface{}{
			"rule": "TRADITIONAL_OPTIMIZER_SELECTED",
		})
	}

	// 将查询优化器设置到handler
	handler.queryOptimizer = queryOptimizer

	// 初始化匹配处理器 - 传递完整的handler实例（各列表DNS由buildMatchers按配置注入）
	matcherHandler := NewMatcherHandler(cfg, logger, handler)
	handler.matcherHandler = matcherHandler

	// 初始化云服务处理器（统一响应出口回调，保证EDNS/TC处理一致）
	cloudHandler := NewCloudHandler(cfg, logger, cacheManager, cloudDetector, handler.proxyQuery, handler.writeResponse)
	handler.cloudHandler = cloudHandler

	// 初始化文件加载处理器
	fileLoader := NewFileLoader(cfg, logger, cloudDetector, matcherHandler)
	handler.fileLoader = fileLoader

	// 初始化任务调度器
	taskScheduler := NewTaskScheduler(cfg, logger, fileLoader, cloudDetector)
	handler.taskScheduler = taskScheduler

	// 初始化刷新处理器（云域名刷新时通过该回调重建替换响应，保证与查询路径一致）
	refreshHandler := NewRefreshHandler(cfg, logger, cacheManager, cloudDetector, queryOptimizer, matcherHandler, handler.proxyQuery,
		func(originalResp *dns.Msg, domain string, qtype uint16, cloudType int) *dns.Msg {
			// 异步刷新无法得知客户端线路，统一按全局替换目标重建
			v4, v6, err := cloudHandler.ResolveReplaceIPs(0, domain, qtype, cloudType, handler.effectiveReplaceConfig(ClientDecision{}))
			if err != nil {
				return nil
			}
			if qtype == dns.TypeA && len(v4) == 0 {
				return nil
			}
			if qtype == dns.TypeAAAA && len(v6) == 0 {
				return nil
			}
			return buildCloudResponse(originalResp, qtype, v4, v6)
		})
	handler.refreshHandler = refreshHandler

	// 初始化CNAME处理器
	cnameProcessor := NewCNAMEProcessor(cfg, logger, handler.proxyQuery, cacheManager)
	handler.cnameProcessor = cnameProcessor

	// 初始化云服务处理器
	cloudProcessor := NewCloudProcessor(cfg, logger, handler.proxyQuery)
	handler.cloudProcessor = cloudProcessor

	// 初始化本地域名篡改匹配器（最高优先级）
	handler.overrideMatcher = NewOverrideMatcher(logger)

	// 初始化客户端分组匹配器
	handler.clientGroupMatcher = NewClientGroupMatcher(cfg.ISPGroups, cfg.CustomGroups)

	// 可选：加载运营商段库，为"按运营商自动分组"提供支持。
	// 即使目录为空/首次部署也注入空库（全部落 other），并在配置了更新间隔时触发首次下载。
	// 该逻辑同时被 ApplyConfig 复用，因此"是否启用识别/段库目录/更新间隔"均可热切换。
	handler.syncSourceDB(cfg)

	// 设置缓存回调
	handler.cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 根据开关决定是否加载数据
	if err := handler.fileLoader.LoadSelectiveData(
		cfg.EnableCloudflareCheck || cfg.EnableAWSCheck,
	); err != nil {
		logger.Error("选择性加载数据失败，但继续启动", map[string]interface{}{
			"error": err.Error(),
		})
		// 即使加载失败也继续启动，确保服务可用
	}

	// 启动后台任务
	handler.taskScheduler.StartBackgroundTasks()

	logger.Info("🚀 重构后DNS处理器初始化完成")

	return handler, nil
}

// getConfig 获取当前配置（web保存后热切换）
func (h *RefactoredHandler) getConfig() *config.Config {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.config
}

// LoadOverrides 加载本地域名篡改规则（web变更后全量重建索引）
func (h *RefactoredHandler) LoadOverrides(list []*config.Override) {
	h.overrideMatcher.Reload(list)
}

// overrideMatcherGetter 供web层获取篡改匹配器
func (h *RefactoredHandler) GetOverrideMatcher() *OverrideMatcher {
	return h.overrideMatcher
}

// RefreshSplitList 按索引强制下载并重新加载该分流列表的域名文件，返回加载后的规则条数
// （供 Web 管理端「立即更新」按钮调用；下载或加载失败时保留原有规则）
func (h *RefactoredHandler) RefreshSplitList(i int) (int, error) {
	if h.fileLoader == nil {
		return 0, fmt.Errorf("文件加载器不可用")
	}
	if err := h.fileLoader.ForceDownloadAndReloadSplitList(i); err != nil {
		return 0, err
	}
	if m := h.matcherHandler.MatcherFor(i); m != nil {
		return m.RuleCount(), nil
	}
	return 0, nil
}

// ApplyConfig 热更新配置：立即生效可热切换部分，返回是否需要重启生效
func (h *RefactoredHandler) ApplyConfig(cfg *config.Config) bool {
	old := h.getConfig()

	// 热切换查询路径与各组件持有的配置指针
	h.cfgMu.Lock()
	h.config = cfg
	h.cfgMu.Unlock()

	h.cacheManager.UpdateConfig(cfg)
	h.cloudHandler.UpdateConfig(cfg)
	h.refreshHandler.UpdateConfig(cfg)
	h.cloudProcessor.UpdateConfig(cfg)
	h.cnameProcessor.UpdateConfig(cfg)
	h.cloudDetector.SetReplaceDomains(cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)
	h.cloudDetector.SetReplaceDomainsAll(allReplaceDomains(cfg))
	h.matcherHandler.UpdateConfig(cfg)
	h.clientGroupMatcher.UpdateGroups(cfg.ISPGroups, cfg.CustomGroups)
	sourceChanged := h.syncSourceDB(cfg) // 运营商识别开关/段库目录可热切换
	h.Logger.SetLevel(cfg.LogLevel)
	if h.queryLog != nil {
		h.queryLog.UpdateOptions(querylog.Options{
			Enabled:   cfg.QueryLog.Enabled,
			Retention: cfg.QueryLog.Retention,
			MaxRows:   cfg.QueryLog.MaxRows,
		})
	}
	if modern, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		modern.UpdateTimeouts(cfg.Timeout, cfg.ModernTimeout)
	} else if traditional, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		traditional.UpdateTimeouts(cfg.Timeout)
	}

	// 分流路由（顺序/取反/DNS/ECS/A-AAAA偏好）变更后，缓存里仍是按旧路由取回的结果，必须清空避免串味
	// 替换接口地址/条数变更后同理：缓存里还是旧接口给出的替换 IP
	// 客户端分组变更同理：不同分组可能得到不同上游，旧缓存会串味
	if splitListsRoutingChanged(old.SplitLists, cfg.SplitLists) || old.IPPrefer != cfg.IPPrefer ||
		old.ReplaceCFAPI != cfg.ReplaceCFAPI || old.ReplaceAPICount != cfg.ReplaceAPICount ||
		clientGroupsRoutingChanged(old, cfg) || sourceChanged {
		h.cacheManager.Clear()
		h.Logger.Info("🧹 [分流路由变更，已清空缓存] ", map[string]interface{}{
			"rule":           "SPLIT_ROUTING_CHANGED_CACHE_CLEARED",
			"ip_prefer":      cfg.IPPrefer,
			"replace_cf_api": cfg.ReplaceCFAPI,
		})
	}

	h.Logger.Info("🔥 [配置已热更新] ", map[string]interface{}{
		"rule": "CONFIG_HOT_APPLIED",
	})

	// 以下字段仅启动时生效，变更后需重启
	return old.ListenPort != cfg.ListenPort ||
		old.WebAddr != cfg.WebAddr ||
		old.LogFormat != cfg.LogFormat ||
		old.Cache.MaxItems != cfg.Cache.MaxItems ||
		old.Cache.MaxAsyncWorkers != cfg.Cache.MaxAsyncWorkers ||
		splitListsNeedRestart(old.SplitLists, cfg.SplitLists) ||
		old.CloudflareNetFile != cfg.CloudflareNetFile ||
		old.CloudflareNetFile6 != cfg.CloudflareNetFile6 ||
		old.AWSNetFile != cfg.AWSNetFile ||
		old.NetworkRefreshInterval != cfg.NetworkRefreshInterval ||
		old.EnableDoT != cfg.EnableDoT ||
		old.EnableDoH != cfg.EnableDoH ||
		old.EnableDoH3 != cfg.EnableDoH3 ||
		old.DoTAddr != cfg.DoTAddr ||
		old.DoHAddr != cfg.DoHAddr ||
		old.DoH3Addr != cfg.DoH3Addr ||
		old.DoHPath != cfg.DoHPath ||
		old.DoHAltSvc != cfg.DoHAltSvc ||
		old.CertStoreDir != cfg.CertStoreDir ||
		old.CertDefault != cfg.CertDefault ||
		old.WebTLS != cfg.WebTLS ||
		old.WebTLSAddr != cfg.WebTLSAddr
}

// allReplaceDomains 汇总全部替换域名（全局 + 各分组覆写），供云检测跳过替换域名自检
func allReplaceDomains(cfg *config.Config) []string {
	out := make([]string, 0, 2+len(cfg.ISPGroups)+len(cfg.CustomGroups))
	out = append(out, cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)
	for _, g := range cfg.ISPGroups {
		if g.CloudReplace.Override {
			out = append(out, g.CloudReplace.CFDomain, g.CloudReplace.AWSDomain)
		}
	}
	for _, g := range cfg.CustomGroups {
		if g.CloudReplace.Override {
			out = append(out, g.CloudReplace.CFDomain, g.CloudReplace.AWSDomain)
		}
	}
	return out
}

// clientGroupsRoutingChanged 判断客户端分组路由是否变化（影响缓存命中率与正确性）。
// 判定原则：任何会改变"某个 scope 该用哪条上游"的字段变化都必须返回 true，否则旧缓存会串味。
// 注意 custom_groups 的顺序参与匹配（Priority 相同时按原顺序），因此按索引比对即可发现顺序变化。
func clientGroupsRoutingChanged(old, cur *config.Config) bool {
	if len(old.ISPGroups) != len(cur.ISPGroups) || len(old.CustomGroups) != len(cur.CustomGroups) {
		return true
	}
	for i := range old.ISPGroups {
		a, b := old.ISPGroups[i], cur.ISPGroups[i]
		if a.ISP != b.ISP || a.Enabled != b.Enabled || a.DNSMode != b.DNSMode ||
			a.IPPrefer != b.IPPrefer ||
			!slices.Equal(a.SplitRefs, b.SplitRefs) ||
			!slices.Equal(a.FallbackDNS, b.FallbackDNS) ||
			a.ECS != b.ECS ||
			a.CloudReplace != b.CloudReplace {
			return true
		}
	}
	for i := range old.CustomGroups {
		a, b := old.CustomGroups[i], cur.CustomGroups[i]
		if a.Name != b.Name || a.Enabled != b.Enabled || a.Priority != b.Priority ||
			a.DNSMode != b.DNSMode || a.IPPrefer != b.IPPrefer ||
			!slices.Equal(a.Match, b.Match) ||
			!slices.Equal(a.SplitRefs, b.SplitRefs) ||
			!slices.Equal(a.FallbackDNS, b.FallbackDNS) ||
			a.ECS != b.ECS ||
			a.CloudReplace != b.CloudReplace {
			return true
		}
	}
	return false
}

// syncSourceDB 按配置同步运营商段库：热切换「是否启用运营商识别 / 段库目录 / 自动更新参数」。
// 返回是否发生了影响匹配结果的变化（调用方据此清空缓存，避免旧 scope 的缓存串味）。
// 该函数同时用于启动与 ApplyConfig，保证两条路径行为一致。
func (h *RefactoredHandler) syncSourceDB(cfg *config.Config) bool {
	enabled := cfg.SourceEnabled && cfg.SourceDBDir != ""
	changed := false

	// 1. 需要卸载段库：识别被关闭，或段库目录变更（旧库对应的 IP 段已失效）
	if h.ispDB != nil && (!enabled || h.ispDBDir != cfg.SourceDBDir) {
		h.stopSourceAutoUpdate()
		h.ispDB = nil
		h.ispDBDir = ""
		h.clientGroupMatcher.SetISPLookup(nil)
		changed = true
	}

	// 2. 识别关闭：运营商分组一律不命中，等价于"没有客户端分组"
	if !enabled {
		if changed {
			h.Logger.Info("⏸️ [运营商识别已关闭，客户端分组不再按运营商命中] ", map[string]interface{}{
				"rule": "SOURCE_DISABLED",
			})
		}
		return changed
	}

	// 3. 首次启用，或目录变更后重建段库
	if h.ispDB == nil {
		db := source.New()
		if err := source.ReloadFromDir(db, cfg.SourceDBDir); err != nil {
			h.Logger.Warn("⚠️ [运营商段库目录不可用，将全部归入「其他」] ", map[string]interface{}{
				"rule":  "SOURCE_DB_LOAD_FAILED",
				"dir":   cfg.SourceDBDir,
				"error": err.Error(),
			})
		}
		h.ispDB = db
		h.ispDBDir = cfg.SourceDBDir
		h.clientGroupMatcher.SetISPLookup(db)
		changed = true
	}

	// 4. 自动更新：间隔/下载源变化时重建定时任务（首次启用会立即下载一次并热加载）
	key := ""
	if cfg.SourceUpdateHours > 0 {
		key = fmt.Sprintf("%s|%d", cfg.SourceBaseURL, cfg.SourceUpdateHours)
	}
	if h.sourceAutoKey != key {
		h.stopSourceAutoUpdate()
		if key != "" {
			h.sourceAutoStop = source.AutoUpdate(
				h.ispDB, cfg.SourceBaseURL, cfg.SourceDBDir,
				time.Duration(cfg.SourceUpdateHours)*time.Hour,
				func(err error) {
					h.Logger.Warn("⚠️ [运营商来源库自动更新失败] ", map[string]interface{}{
						"rule":  "SOURCE_DB_UPDATE_FAILED",
						"error": err.Error(),
					})
				},
			)
			h.sourceAutoKey = key
			h.Logger.Info("🔄 [运营商来源库自动更新已启用] ", map[string]interface{}{
				"rule":  "SOURCE_DB_AUTO_UPDATE",
				"base":  cfg.SourceBaseURL,
				"dir":   cfg.SourceDBDir,
				"hours": cfg.SourceUpdateHours,
			})
		}
	}

	if changed {
		h.Logger.Info("🔄 [运营商识别已启用，客户端分组按运营商自动命中] ", map[string]interface{}{
			"rule": "SOURCE_ENABLED",
			"dir":  cfg.SourceDBDir,
		})
	}
	return changed
}

// stopSourceAutoUpdate 停止段库定时更新任务（幂等）
func (h *RefactoredHandler) stopSourceAutoUpdate() {
	if h.sourceAutoStop != nil {
		h.sourceAutoStop()
		h.sourceAutoStop = nil
	}
	h.sourceAutoKey = ""
}

// splitListsNeedRestart 判断分流列表是否发生需重启才生效的结构性变更
// （列表增删/启用状态/域名文件/URL/刷新间隔；顺序、DNS、取反、ECS 变更均可热更新）
func splitListsNeedRestart(old, cur []config.SplitList) bool {
	if len(old) != len(cur) {
		return true
	}
	// 与顺序无关：按身份（名称/文件/URL）排序后逐条比对，避免仅调换顺序被误判为需重启
	a := sortedSplitLists(old)
	b := sortedSplitLists(cur)
	for i := range a {
		if a[i].Name != b[i].Name || a[i].DomainFile != b[i].DomainFile ||
			a[i].DomainURL != b[i].DomainURL || a[i].Enabled != b[i].Enabled ||
			a[i].Refresh != b[i].Refresh {
			return true
		}
	}
	return false
}

// sortedSplitLists 返回按身份（名称/文件/URL）排序的副本，供与顺序无关的比对使用
func sortedSplitLists(lists []config.SplitList) []config.SplitList {
	out := append([]config.SplitList(nil), lists...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].DomainFile != out[j].DomainFile {
			return out[i].DomainFile < out[j].DomainFile
		}
		return out[i].DomainURL < out[j].DomainURL
	})
	return out
}

// splitListsRoutingChanged 判断「域名→上游」的路由是否变化
// （顺序、取反、DNS、解析模式、ECS、A/AAAA 偏好、启用状态、域名文件；任一变化后缓存里的旧结果都不再适用）
func splitListsRoutingChanged(old, cur []config.SplitList) bool {
	if len(old) != len(cur) {
		return true
	}
	for i := range old {
		a, b := old[i], cur[i]
		if a.Invert != b.Invert || a.Enabled != b.Enabled || a.ECS != b.ECS ||
			a.DomainFile != b.DomainFile || a.DomainURL != b.DomainURL ||
			a.DNSMode != b.DNSMode || a.IPPrefer != b.IPPrefer ||
			!slices.Equal(a.DNS, b.DNS) {
			return true
		}
	}
	return false
}

// ServeDNS 实现dns.Handler接口（带panic恢复与协议守卫）
func (h *RefactoredHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			h.Logger.Error("💥 [DNS处理panic] ", map[string]interface{}{
				"rule":        "DNS_HANDLER_PANIC",
				"panic_msg":   fmt.Sprintf("%v", r),
				"client_addr": w.RemoteAddr().String(),
				"stack_trace": string(debug.Stack()),
			})
			// 发送错误响应
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		}
	}()

	if req == nil {
		return
	}

	// 协议守卫：QR=1的是响应而非查询，忽略以防请求回环（RFC 1035 §4.1.1）
	if req.Response {
		h.Logger.Debug("⏭️ 忽略QR=1的DNS消息", map[string]interface{}{
			"client_addr": w.RemoteAddr().String(),
		})
		return
	}

	// 协议守卫：仅支持标准查询Opcode，其他回NOTIMP
	if req.Opcode != dns.OpcodeQuery {
		h.Logger.Debug("⏭️ 非QUERY Opcode，回NOTIMP", map[string]interface{}{
			"opcode": req.Opcode,
		})
		h.sendErrorResponse(w, req, dns.RcodeNotImplemented)
		return
	}

	// 协议守卫：问题段为空回FORMERR
	if len(req.Question) == 0 {
		h.Logger.Warn("⚠️ 收到空DNS请求")
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	// 协议守卫：QDCOUNT>1回FORMERR（RFC 1035 §4.1.2，本服务仅支持单问题）
	if len(req.Question) > 1 {
		h.Logger.Debug("⏭️ QDCOUNT>1，回FORMERR", map[string]interface{}{
			"qdcount": len(req.Question),
		})
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	q := req.Question[0]

	// 域名合法性检查：非法域名回FORMERR，绝不静默丢弃让客户端空等
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if _, ok := dns.IsDomainName(domain); !ok {
		h.Logger.Warn("⚠️ 非法域名请求", map[string]interface{}{
			"domain": domain,
		})
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	// 本地域名篡改检查（最高优先级）：命中域名一律本地作答，不走缓存与上游
	if h.overrideMatcher.Match(domain) {
		if records := h.overrideMatcher.Lookup(domain, q.Qtype); len(records) > 0 {
			overrideResp := buildOverrideResponse(req, q.Qtype, records)
			if overrideResp == nil {
				h.Logger.Warn("⚠️ 域名篡改记录全部无效", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[q.Qtype],
				})
				h.sendErrorResponse(w, req, dns.RcodeServerFailure)
				h.recordQuery(w, querylog.Entry{
					Domain: domain, QType: dns.TypeToString[q.Qtype],
					Action: querylog.ActionError, Rcode: "SERVFAIL", Answers: "篡改记录全部无效",
				})
				return
			}
			h.writeResponse(w, req, overrideResp)
			h.Logger.Info("🔀 [域名篡改命中] ", map[string]interface{}{
				"rule":        "OVERRIDE_HIT",
				"domain":      domain,
				"qtype":       dns.TypeToString[q.Qtype],
				"client_addr": w.RemoteAddr().String(),
				"records":     len(overrideResp.Answer),
			})
			h.recordQuery(w, querylog.Entry{
				Domain: domain, QType: dns.TypeToString[q.Qtype],
				Action: querylog.ActionOverride, Rcode: dns.RcodeToString[overrideResp.Rcode],
				Answers: answersSummary(overrideResp),
			})
			return
		}

		// 已篡改域名但未配置该记录类型（如只配了A却查AAAA/HTTPS）：回NODATA，
		// 避免上游真CNAME等数据外泄导致客户端绕过篡改
		h.writeResponse(w, req, buildNODATAResponse(req))
		h.Logger.Info("🔀 [域名篡改NODATA] ", map[string]interface{}{
			"rule":        "OVERRIDE_NODATA",
			"domain":      domain,
			"qtype":       dns.TypeToString[q.Qtype],
			"client_addr": w.RemoteAddr().String(),
		})
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[q.Qtype],
			Action: querylog.ActionOverride, Rcode: dns.RcodeToString[dns.RcodeSuccess],
			Answers: "NODATA（域名已篡改，无该类型记录）",
		})
		return
	}

	// 解析客户端 IP 并确定缓存 scope
	_, scope := h.resolveClientAndScope(w)

	// 协议守卫：RD=0的非递归请求仅用缓存回答，缓存未命中回REFUSED
	if !req.RecursionDesired {
		if s, ok := h.cacheManager.GetServeScoped(scope, domain, q.Qtype); ok {
			h.serveCacheHit(w, req, s)
			h.recordQuery(w, querylog.Entry{
				Domain: domain, QType: dns.TypeToString[q.Qtype],
				Action: querylog.ActionCache, Rcode: dns.RcodeToString[s.Rcode],
				Answers: s.Answers,
			})
			return
		}
		resp, hit, _, _ := h.cacheManager.GetScoped(scope, domain, q.Qtype)
		if !hit {
			h.sendErrorResponse(w, req, dns.RcodeRefused)
			h.recordQuery(w, querylog.Entry{
				Domain: domain, QType: dns.TypeToString[q.Qtype],
				Action: querylog.ActionRefused, Rcode: dns.RcodeToString[dns.RcodeRefused],
				Answers: "RD=0 且缓存未命中",
			})
			return
		}
		h.writeResponse(w, req, resp)
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[q.Qtype],
			Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
			Answers: answersSummary(resp),
		})
		return
	}

	// A/AAAA 偏好档位：本地篡改优先级最高（已在上面处理），此处先于缓存判定，
	// 使「只A/优先A」能压过缓存里的 AAAA；RD=0 的「缓存或REFUSED」约束保持在前，不被本策略改写
	if h.filterAAAA(w, req, domain, q.Qtype, scope) {
		return
	}

	// 目前重点处理A和AAAA记录（IP地址记录）
	// 其他记录类型（如NS、MX等）也会被处理，但不经过云服务检测优化
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// 对于非A/AAAA记录，仍然进行查询，但跳过云服务检测和替换逻辑
		h.processNonIPQuery(w, req, domain, q.Qtype, scope)
		return
	}

	h.processQuery(w, req, domain, q.Qtype, scope)
}

// processNonIPQuery 处理非IP记录类型的DNS查询（如NS、MX、TXT等）
func (h *RefactoredHandler) processNonIPQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, scope string) {
	start := time.Now()

	clientDecision := h.clientDecisionFromScope(scope)

	// 1. 检查缓存（快路径直接打补丁写出预打包字节；不适用时回退到深拷贝路径）
	if s, ok := h.cacheManager.GetServeScoped(scope, domain, qtype); ok {
		h.serveCacheHit(w, req, s)
		h.Logger.Debug("✅ [DNS查询完成-非IP记录-缓存命中] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"source":      "cache_non_ip",
		})
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionCache, Rcode: dns.RcodeToString[s.Rcode],
			Answers: s.Answers, ElapsedMS: time.Since(start).Milliseconds(),
		})
		return
	}
	resp, hit, _, _ := h.cacheManager.GetScoped(scope, domain, qtype)
	if hit {
		h.writeResponse(w, req, resp)
		h.Logger.Debug("✅ [DNS查询完成-非IP记录-缓存命中] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"source":      "cache_non_ip",
		})
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
			Answers: answersSummary(resp), ElapsedMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// 2. 分流决策：客户端分组内引用规则优先，未命中走分组默认上游，再回退全局
	decision, upstreams := h.resolveRoute(domain, clientDecision)

	// 3. 执行查询（不经过云服务检测和替换逻辑）
	resp, server, err := h.queryWithFallback(req, upstreams, decision.DNSMode)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [非IP记录查询失败] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"error":       err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionError, Rcode: "SERVFAIL",
			Answers: "上游查询失败", ElapsedMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// 4. 验证响应是否有效（NOERROR或NXDOMAIN均可缓存返回）
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		h.Logger.Error("❌ [非IP记录响应无效] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"rcode":       dns.RcodeToString[resp.Rcode],
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionError, Rcode: "SERVFAIL",
			Answers: "上游响应无效: " + dns.RcodeToString[resp.Rcode], ElapsedMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// 5. 缓存并原样返回上游响应（不重建owner、不裁剪RRset）
	h.cacheManager.SetScoped(scope, domain, qtype, resp, false)
	h.writeResponse(w, req, resp)

	h.Logger.Debug("✅ [DNS查询完成-非IP记录] ", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"client_addr":  w.RemoteAddr().String(),
		"source":       "non_ip",
		"answer_count": len(resp.Answer),
		"rcode":        dns.RcodeToString[resp.Rcode],
	})

	action, listName, mode := splitLogFields(decision)
	h.recordQuery(w, querylog.Entry{
		Domain: domain, QType: dns.TypeToString[qtype],
		Action: action, ListName: listName, DNS: server, DNSMode: mode,
		Rcode: dns.RcodeToString[resp.Rcode], Answers: answersSummary(resp),
		ElapsedMS: time.Since(start).Milliseconds(),
	})
}

// processQuery 处理单个DNS查询
func (h *RefactoredHandler) processQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, scope string) {
	// 开始计时整个处理过程
	totalTimer := h.Logger.StartTimer("total_dns_request")
	defer totalTimer.End()

	clientDecision := h.clientDecisionFromScope(scope)

	// 1. 缓存检查（使用单飞行模式避免重复查询）
	//    快路径：域名未被标记为云服务时，直接打补丁写出预打包字节，省掉每次命中的整包深拷贝。
	//    被任何常见类型标记为云时交回原路径（保证「域名带云标记时优先云响应」的原有语义）。
	if s, ok := h.cacheManager.GetServeScoped(scope, domain, qtype); ok {
		if !h.cacheManager.IsDomainCloudScoped(scope, domain) {
			h.serveCacheHit(w, req, s)
			totalTime := totalTimer.End()
			h.Logger.Debug("✅ [DNS查询完成-缓存命中] ", map[string]interface{}{
				"domain":      domain,
				"qtype":       dns.TypeToString[qtype],
				"client_addr": w.RemoteAddr().String(),
				"source":      "cache_normal",
				"total_time":  totalTime,
			})
			h.recordQuery(w, querylog.Entry{
				Domain: domain, QType: dns.TypeToString[qtype],
				Action: querylog.ActionCache, Rcode: dns.RcodeToString[s.Rcode],
				Answers: s.Answers, ElapsedMS: totalTime.Milliseconds(),
			})
			return
		}
	}
	resp, hit, _, _ := h.cacheManager.GetWithFlightScoped(scope, domain, qtype)
	if hit {
		// 检查域名级别的云服务状态，确保A/AAAA记录处理一致性
		if h.cacheManager.IsDomainCloudScoped(scope, domain) {
			// 云域名：返回云替换响应缓存
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponseScoped(scope, domain, qtype); cloudHit {
				h.writeResponse(w, req, cloudResp)
				totalTime := totalTimer.End()
				h.Logger.Debug("✅ [DNS查询完成-缓存命中-云域名] ", map[string]interface{}{
					"domain":      domain,
					"qtype":       dns.TypeToString[qtype],
					"client_addr": w.RemoteAddr().String(),
					"source":      "cache_cloud",
					"total_time":  totalTime,
				})
				h.recordQuery(w, querylog.Entry{
					Domain: domain, QType: dns.TypeToString[qtype],
					Action: querylog.ActionCache, Rcode: dns.RcodeToString[cloudResp.Rcode],
					Answers: answersSummary(cloudResp), ElapsedMS: totalTime.Milliseconds(),
				})
				return
			}
		} else {
			// 普通域名缓存命中：resp已是递减TTL后的副本
			h.writeResponse(w, req, resp)
			totalTime := totalTimer.End()
			h.Logger.Debug("✅ [DNS查询完成-缓存命中] ", map[string]interface{}{
				"domain":      domain,
				"qtype":       dns.TypeToString[qtype],
				"client_addr": w.RemoteAddr().String(),
				"source":      "cache_normal",
				"total_time":  totalTime,
			})
			h.recordQuery(w, querylog.Entry{
				Domain: domain, QType: dns.TypeToString[qtype],
				Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
				Answers: answersSummary(resp), ElapsedMS: totalTime.Milliseconds(),
			})
			return
		}
	}

	// 2. 分流决策：客户端分组内引用规则优先，未命中走分组默认上游，再回退全局
	decision, upstreams := h.resolveRoute(domain, clientDecision)
	ecs := ecsSummary(req, decision)

	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query")

	// 3. 代理查询上游DNS服务器（按列表解析模式：竞速 / 串行故障转移；全部失败回退 BackupDNS）
	//    命中分流列表时按列表 ECS 策略处理请求副本（剥离客户端 ECS / 注入本地 ECS）
	resp, server, err := h.proxyQueryWithCaching(applySplitECS(req, decision), upstreams, domain, qtype, decision.DNSMode, scope)
	upstreamTime := upstreamTimer.End()

	if err != nil || resp == nil {
		totalTime := totalTimer.End()
		h.Logger.Error("❌ [上游域名查询失败，请检查上游] ", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"client_addr":   w.RemoteAddr().String(),
			"error":         err,
			"total_time":    totalTime,
			"upstream_time": upstreamTime,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionError, ListName: decision.ListName, DNSMode: decision.DNSMode,
			ECS: ecs, Rcode: "SERVFAIL", Answers: "上游查询失败", ElapsedMS: totalTime.Milliseconds(),
		})
		return
	}

	// 4. 云服务检测：沿CNAME链收集IP仅用于内部检测，不改写客户端响应
	var detection *CloudDetectionResult
	isCloud := false

	if decision.Matched && !decision.EnableCloudCheck {
		h.Logger.Debug("⏭️ 跳过云服务检测（分流列表未开启云检测）", map[string]interface{}{
			"domain": domain,
			"list":   decision.ListName,
		})
	} else if !h.cloudDetector.IsReplaceDomain(domain) {
		chainIPs := h.cnameProcessor.CollectChainIPs(resp, domain, qtype)
		if len(chainIPs) > 0 {
			probe := &dns.Msg{Answer: chainIPs}
			if h.getConfig().EnableCloudflareCheck {
				if d := h.cloudDetector.DetectCloudflareService(probe); d.Type != CloudTypeNone {
					detection = d
					isCloud = true
				}
			}
			if !isCloud && h.getConfig().EnableAWSCheck {
				if d := h.cloudDetector.DetectAWSService(probe); d.Type != CloudTypeNone {
					detection = d
					isCloud = true
				}
			}
		}
	}

	if isCloud && detection != nil {
		rc := h.effectiveReplaceConfig(clientDecision)
		effectiveDomain := rc.CFDomain
		if CloudType(detection.Type) == CloudTypeAWS {
			effectiveDomain = rc.AWSDomain
		}
		h.Logger.Debug("☁️ [云域名检测到，开始替换处理] ", map[string]interface{}{
			"domain":         domain,
			"cloud_type":     detection.Type,
			"replace_domain": effectiveDomain,
			"scope":          scope,
			"group_override": clientDecision.CloudReplace.Override,
		})

		// 云替换内部会自行写响应（与查询路径一致的缓存与出口处理）
		finalResp, _ := h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, int(detection.Type), resp,
			effectiveIPPrefer(h.getConfig().IPPrefer, decision), scope, rc)
		totalTime := totalTimer.End()
		h.Logger.Debug("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"client_addr":   w.RemoteAddr().String(),
			"source":        "cloud_replacement",
			"total_time":    totalTime,
			"upstream_time": upstreamTime,
		})
		h.recordQuery(w, querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype],
			Action: querylog.ActionCloud, ListName: decision.ListName, DNS: server, DNSMode: decision.DNSMode,
			ECS: ecs, Rcode: rcodeName(finalResp), Answers: answersSummary(finalResp),
			ElapsedMS: totalTime.Milliseconds(),
		})
		return
	}

	// 5. 非云域名：原样返回上游响应（owner、RRset完整保留）
	h.writeResponse(w, req, resp)

	// 检查域名是否命中分流列表
	isDomainCloud := h.cacheManager.IsDomainCloudScoped(scope, domain)

	var logSource string
	if isDomainCloud {
		logSource = "cloud"
	} else if decision.Matched {
		logSource = decision.ListName
	} else {
		logSource = "normal"
	}

	totalTime := totalTimer.End()
	h.Logger.Debug("✅ [DNS查询完成] ", map[string]interface{}{
		"domain":        domain,
		"qtype":         dns.TypeToString[qtype],
		"client_addr":   w.RemoteAddr().String(),
		"source":        logSource,
		"answer_count":  len(resp.Answer),
		"total_time":    totalTime,
		"upstream_time": upstreamTime,
	})

	// 记录解析日志：命中的分流列表、实际应答的上游、解析模式与最终结果
	action, listName, mode := splitLogFields(decision)
	h.recordQuery(w, querylog.Entry{
		Domain: domain, QType: dns.TypeToString[qtype],
		Action: action, ListName: listName, DNS: server, DNSMode: mode,
		ECS: ecs, Rcode: rcodeName(resp), Answers: answersSummary(resp),
		ElapsedMS: totalTime.Milliseconds(),
	})
}

// writeResponse 统一响应出口：所有路径（缓存命中/上游/云替换/错误）唯一WriteMsg的地方
// 统一处理：回写原始Question（保留客户端QNAME大小写）、清除AD位、回带EDNS OPT、UDP截断（TC位）
func (h *RefactoredHandler) writeResponse(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	if resp == nil {
		return
	}

	resp.Id = req.Id
	resp.Question = req.Question   // 保留客户端原始QNAME（含大小写，0x20随机化客户端可正常校验）
	resp.AuthenticatedData = false // 未做DNSSEC校验且可能改写响应，AD断言不成立，清零（RFC 4035）

	// 去掉上游可能携带的OPT记录，避免与下方回带的OPT重复
	extra := resp.Extra[:0]
	for _, rr := range resp.Extra {
		if _, isOPT := rr.(*dns.OPT); !isOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra

	// 按请求回带EDNS OPT（RFC 6891）
	opt := req.IsEdns0()
	if opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}

	resp.Compress = true

	// UDP截断：超过客户端通告payload size（无EDNS时为512）时设置TC=1，让客户端转TCP重试
	if w.RemoteAddr().Network() == "udp" {
		size := 512
		if opt != nil && opt.UDPSize() > 512 {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}

	w.WriteMsg(resp)
}

// wireBufPool 复用直写响应的字节缓冲
var wireBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 0, 4096) },
}

// serveCacheHit 缓存命中统一出口：优先直写预打包字节，不适用时按需从字节重建响应走深拷贝路径
func (h *RefactoredHandler) serveCacheHit(w dns.ResponseWriter, req *dns.Msg, s Serve) {
	if h.writeResponseWire(w, req, s) {
		return
	}
	// 回退：UDP 需截断、QNAME 编码不符等罕见场景。字节是权威内容，按需 Unpack 重建一份可写响应。
	// 重建出的 TTL 是写入缓存时的原始值，需按缓存时长递减，与直写路径保持一致。
	msg := new(dns.Msg)
	if err := msg.Unpack(s.Wire); err != nil {
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}
	decrementTTLs(msg, time.Since(s.StoredAt))
	h.writeResponse(w, req, msg)
}

// writeResponseWire 用缓存里的预打包字节直写响应：只改写 ID、AD位、Question 大小写与各 RR 的 TTL，
// 需要时按请求追加 EDNS OPT。语义与 writeResponse 对齐，但省掉每次命中的整包深拷贝。
// 返回 false 表示当前请求不适合直写（如 UDP 需要截断、Question 长度对不上），调用方应回退。
func (h *RefactoredHandler) writeResponseWire(w dns.ResponseWriter, req *dns.Msg, s Serve) bool {
	wire := s.Wire
	if !s.Meta.ok || len(wire) < 12 || len(req.Question) != 1 {
		return false
	}

	opt := req.IsEdns0()
	need := len(wire)
	if opt != nil {
		need += 11 // OPT: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
	}

	// UDP 截断交由 miekg 的 Msg.Truncate 处理（按需删记录并置 TC），这里直接回退
	if w.RemoteAddr().Network() == "udp" {
		size := 512
		if opt != nil && opt.UDPSize() > 512 {
			size = int(opt.UDPSize())
		}
		if need > size {
			return false
		}
	}

	buf := wireBufPool.Get().([]byte)
	if cap(buf) < need {
		buf = make([]byte, need)
	}
	buf = buf[:need]
	copy(buf, wire)

	// 报文 ID 与请求一致
	buf[0] = byte(req.Id >> 8)
	buf[1] = byte(req.Id)
	// 清 AD 位（未做 DNSSEC 校验且可能改写响应，RFC 4035）
	buf[3] &^= 0x20

	// Question 段回写客户端原始问题（与 writeResponse 的 resp.Question = req.Question 一致）
	// QNAME 必须按 wire 编码重写且保留大小写（0x20 随机化的客户端会校验）；
	// 编码长度与缓存中不一致（理论上不会发生，域名相同则结构相同）时回退
	q := req.Question[0]
	qlen := s.Meta.qnameLen
	if s.Meta.qnameOff+qlen+4 > len(wire) {
		wireBufPool.Put(buf[:0])
		return false
	}
	end, err := dns.PackDomainName(q.Name, buf, s.Meta.qnameOff, nil, false)
	if err != nil || end != s.Meta.qnameOff+qlen {
		wireBufPool.Put(buf[:0])
		return false
	}
	binary.BigEndian.PutUint16(buf[end:end+2], q.Qtype)
	binary.BigEndian.PutUint16(buf[end+2:end+4], q.Qclass)

	// TTL 按缓存时长递减（下限 0），规则与 decrementTTLs 一致
	if elapsed := uint32(time.Since(s.StoredAt).Seconds()); elapsed > 0 {
		for _, f := range s.Meta.ttls {
			ttl := f.ttl
			if ttl <= elapsed {
				ttl = 0
			} else {
				ttl -= elapsed
			}
			binary.BigEndian.PutUint32(buf[f.off:f.off+4], ttl)
		}
	}

	// 按请求回带 EDNS OPT（RFC 6891）
	if opt != nil {
		o := len(wire)
		buf[o] = 0    // NAME: 根
		buf[o+1] = 0  // TYPE 高字节
		buf[o+2] = 41 // TYPE = OPT(41)
		binary.BigEndian.PutUint16(buf[o+3:o+5], opt.UDPSize())
		buf[o+5] = 0 // 扩展 rcode
		buf[o+6] = 0 // version
		var flags uint16
		if opt.Do() {
			flags = 0x8000
		}
		binary.BigEndian.PutUint16(buf[o+7:o+9], flags)
		buf[o+9] = 0  // RDLEN 高字节
		buf[o+10] = 0 // RDLEN 低字节
		// ARCOUNT + 1
		binary.BigEndian.PutUint16(buf[10:12], binary.BigEndian.Uint16(buf[10:12])+1)
	}

	w.Write(buf)
	wireBufPool.Put(buf[:0])
	return true
}

// sendErrorResponse 发送错误响应（走统一响应出口）
func (h *RefactoredHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	h.writeResponse(w, req, resp)
}

// GetStats 获取统计信息
func (h *RefactoredHandler) GetStats() map[string]interface{} {
	cacheStats := h.cacheManager.GetStats(false)

	return map[string]interface{}{
		"cache": cacheStats,
	}
}

// GetCacheManager 获取缓存管理器
func (h *RefactoredHandler) GetCacheManager() *CacheManager {
	return h.cacheManager
}

// resolveClientAndScope 解析客户端 IP、匹配客户端分组，返回缓存 scope
// scope 用于缓存隔离：未命中分组为 "-"，命中内置运营商分组为该 ISP key，命中自定义组为 "c:<name>"
func (h *RefactoredHandler) resolveClientAndScope(w dns.ResponseWriter) (clientIP netip.Addr, scope string) {
	ip, source := h.ResolveClientIP(w)
	if !ip.IsValid() {
		return ip, "-"
	}

	decision := h.clientGroupMatcher.Match(ip)
	if !decision.Matched || decision.Scope == "" {
		return ip, "-"
	}

	h.Logger.Debug("🎯 [客户端分组命中] ", map[string]interface{}{
		"rule":      "CLIENT_GROUP_HIT",
		"group":     decision.Label,
		"scope":     decision.Scope,
		"client_ip": ip.String(),
		"ip_source": source,
	})
	return ip, decision.Scope
}

// clientDecisionFromScope 根据缓存 scope 反查客户端分组决策。
// 未命中分组（scope 为 "-"）或分组已被删除/禁用时返回零值决策，调用方按"无客户端分组"处理。
func (h *RefactoredHandler) clientDecisionFromScope(scope string) ClientDecision {
	return h.clientGroupMatcher.DecisionForScope(scope)
}

// Close 关闭处理器
func (h *RefactoredHandler) Close() {
	h.cancel()

	h.stopSourceAutoUpdate()
	h.ispDB = nil

	if h.cacheManager != nil {
		h.cacheManager.Close()
	}

	if h.queryOptimizer != nil {
		// 使用类型断言关闭不同类型的查询优化器
		if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
			modernOptimizer.Close()
		} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
			traditionalOptimizer.Close()
		}
	}

	// 关闭连接池
	if h.dotConnPool != nil {
		h.dotConnPool.Close()
	}
	if h.dohConnPool != nil {
		h.dohConnPool.Close()
	}
	if h.doh3ConnPool != nil {
		h.doh3ConnPool.Close()
	}
	if h.udpConnPool != nil {
		h.udpConnPool.Close()
	}
	if h.tcpConnPool != nil {
		h.tcpConnPool.Close()
	}

	h.Logger.Info("📪 重构后DNS处理器已关闭")
}

// refreshDNSRecord 刷新DNS记录（缓存回调）
func (h *RefactoredHandler) refreshDNSRecord(domain string, qtype uint16) error {
	return h.refreshHandler.RefreshDNSRecord(domain, qtype)
}

// upstreamsFor 由分流决策得出上游DNS服务器（未命中分流列表时回退全局上游）
func (h *RefactoredHandler) upstreamsFor(domain string, d SplitDecision) []string {
	if d.Matched {
		h.Logger.Debug("🎯 命中分流列表", map[string]interface{}{
			"domain":      domain,
			"list":        d.ListName,
			"dns_servers": d.DNS,
		})
		return d.DNS
	}
	return h.getConfig().Upstream
}

// effectiveReplaceConfig 计算本次生效的云替换目标：命中分组且开启覆写时用分组自带值，否则用全局
func (h *RefactoredHandler) effectiveReplaceConfig(cd ClientDecision) ReplaceConfig {
	if cd.CloudReplace.Override {
		return ReplaceConfig{
			CFDomain:  cd.CloudReplace.CFDomain,
			AWSDomain: cd.CloudReplace.AWSDomain,
			CFAPI:     cd.CloudReplace.CFAPI,
			APICount:  cd.CloudReplace.APICount,
		}
	}
	cfg := h.getConfig()
	return ReplaceConfig{
		CFDomain:  cfg.ReplaceCFDomain,
		AWSDomain: cfg.ReplaceAWSDomain,
		CFAPI:     cfg.ReplaceCFAPI,
		APICount:  cfg.ReplaceAPICount,
	}
}

// resolveRoute 计算本次查询最终使用的「分流决策 + 上游列表」。
//
//  1. 客户端未命中分组 → 走全局域名分流（原有行为）
//  2. 客户端命中分组：
//     a. 先按分组的 SplitRefs 引用顺序匹配域名分流列表（命中哪条复用哪条的策略）
//     b. 全部未命中 → 用分组 FallbackDNS 兜底（覆盖全局上游）；FallbackDNS 为空则回退全局 upstream
func (h *RefactoredHandler) resolveRoute(domain string, cd ClientDecision) (SplitDecision, []string) {
	if !cd.Matched {
		d := h.matcherHandler.MatchDomain(domain)
		// 域名分流全部未命中（d.DNSMode 为空）：套用全局默认解析模式（race/failover/wrandom）。
		// 命中分流列表时其 DNSMode 已由 normDNSMode 归一化为非空，不会被覆盖。
		if d.DNSMode == "" {
			d.DNSMode = normDNSMode(h.getConfig().DNSMode)
		}
		return d, h.upstreamsFor(domain, d)
	}

	// a. 按分组引用顺序匹配域名分流：命中即复用该分流列表的 DNS/模式/ECS/偏好/云检测
	if len(cd.SplitRefs) > 0 {
		if d := h.matcherHandler.MatchDomainWithin(domain, cd.SplitRefs); d.Matched {
			// 命中引用分流：分组配了 ECS 即统一用分组 ECS 覆写列表自带 ECS，
			// 保证按分组的线路解析（不区分明文/加密上游）；分组未开 ECS 则保留列表自身策略。
			if cd.ECS.Enabled {
				d.ECS = cd.ECS
			}
			h.Logger.Debug("🎯 [客户端分组命中，复用引用分流] ", map[string]interface{}{
				"rule":   "CLIENT_GROUP_SUBDIVERT",
				"group":  cd.Label,
				"scope":  cd.Scope,
				"domain": domain,
				"list":   d.ListName,
			})
			return d, d.DNS
		}
	}

	// b. 引用分流未命中：使用分组兜底 DNS
	upstreams := cd.FallbackDNS
	if len(upstreams) == 0 {
		upstreams = h.getConfig().Upstream
	}
	// 兜底查询按分组配置的解析模式 / A-AAAA 偏好 / ECS 策略处理
	// EnableCloudCheck 置 true：分组兜底路径默认执行云检测（不与分流列表的云检测开关相关）
	d := SplitDecision{
		Matched:          true,
		DNS:              upstreams,
		DNSMode:          normDNSMode(cd.DNSMode),
		ListName:         cd.Label,
		EnableCloudCheck: true,
		IPPrefer:         cd.IPPrefer,
		ECS:              cd.ECS,
	}
	h.Logger.Debug("🎯 [客户端分组命中，分流未命中走兜底 DNS] ", map[string]interface{}{
		"rule":   "CLIENT_GROUP_FALLBACK",
		"group":  cd.Label,
		"scope":  cd.Scope,
		"domain": domain,
		"dns":    upstreams,
	})
	return d, upstreams
}

// formatAnswerRecords 格式化回答记录用于日志
func formatAnswerRecords(records []dns.RR) []map[string]interface{} {
	formatted := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		recordInfo := map[string]interface{}{
			"type": dns.TypeToString[record.Header().Rrtype],
			"name": record.Header().Name,
		}
		switch rr := record.(type) {
		case *dns.A:
			recordInfo["ip"] = rr.A.String()
		case *dns.AAAA:
			recordInfo["ip"] = rr.AAAA.String()
		case *dns.CNAME:
			recordInfo["target"] = rr.Target
		}
		formatted = append(formatted, recordInfo)
	}
	return formatted
}

// getUDPQueryFunc 返回UDP查询函数
func (h *RefactoredHandler) getUDPQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryUDP
}

// getTCPQueryFunc 返回TCP查询函数
func (h *RefactoredHandler) getTCPQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryTCP
}

// getDoHQueryFunc 返回DoH查询函数
func (h *RefactoredHandler) getDoHQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryDoH
}

// getDoTQueryFunc 返回DoT查询函数
func (h *RefactoredHandler) getDoTQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryDoT
}

// getDoH3QueryFunc 返回DoH3查询函数
func (h *RefactoredHandler) getDoH3QueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryDoH3
}
