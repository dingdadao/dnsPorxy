package dns

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// CacheManager 缓存管理器
type CacheManager struct {
	cache  *OptimizedDNSCache
	cfgMu  sync.RWMutex
	config *config.Config
	logger *utils.EnhancedLogger

	// 异步刷新相关
	asyncChan  chan *AsyncRefreshTask
	asyncSet   map[string]struct{}
	asyncMu    sync.RWMutex
	workerPool *AsyncWorkerPool

	// 域名处理锁，防止多个worker同时处理同一个域名
	domainLocks map[string]*sync.Mutex
	locksMu     sync.RWMutex

	// 刷新回调
	refreshCallback RefreshCallback

	// 单飞行组，用于避免对同一域名的重复查询
	flightGroup singleflight.Group
}

// AsyncRefreshTask 异步刷新任务
type AsyncRefreshTask struct {
	Domain     string
	QType      uint16
	ExpireTime time.Time
	Priority   int // 优先级：0-正常，1-高优先级
}

// AsyncWorkerPool 异步工作池
type AsyncWorkerPool struct {
	workers int
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewCacheManager 创建缓存管理器
// 注意：云检测统一在查询流程中执行（见 handler.processQuery），
// 缓存层不再做云检测，避免同一响应被重复扫描。
func NewCacheManager(cfg *config.Config, logger *utils.EnhancedLogger) *CacheManager {
	cm := &CacheManager{
		cache:       NewOptimizedDNSCache(cfg.Cache.MaxItems, cfg.Cache.TTL),
		config:      cfg,
		logger:      logger,
		asyncChan:   make(chan *AsyncRefreshTask, 1000),
		asyncSet:    make(map[string]struct{}),
		domainLocks: make(map[string]*sync.Mutex),
		workerPool: &AsyncWorkerPool{
			workers: cfg.Cache.MaxAsyncWorkers,
			stopCh:  make(chan struct{}),
		},
		flightGroup: singleflight.Group{},
	}

	// 启动异步工作池
	cm.startAsyncWorkers()

	// 过期宽限（serve-stale 窗口）从配置传导到缓存层
	cm.cache.SetStaleTTL(cfg.Cache.StaleTTL)

	// 按需刷新模式下不启动定期扫描任务
	// if cfg.Cache.EnableAsyncRefresh {
	// 	go cm.startCacheScanTask()
	// }

	logger.Info("🗄️ 缓存管理器初始化完成", map[string]interface{}{
		"max_items":     cfg.Cache.MaxItems,
		"ttl":           cfg.Cache.TTL.String(),
		"async_workers": cfg.Cache.MaxAsyncWorkers,
		"async_refresh": true, // 异步刷新默认启用
	})

	return cm
}

// getConfig 获取当前配置（web保存后热切换）
func (cm *CacheManager) getConfig() *config.Config {
	cm.cfgMu.RLock()
	defer cm.cfgMu.RUnlock()
	return cm.config
}

// UpdateConfig 热更新配置引用
func (cm *CacheManager) UpdateConfig(cfg *config.Config) {
	cm.cfgMu.Lock()
	cm.config = cfg
	cm.cfgMu.Unlock()
	// 兜底TTL热更新传导到缓存层（容量/线程数仍需重启）
	cm.cache.SetDefaultTTL(cfg.Cache.TTL)
	// 过期宽限热更新传导到缓存层
	cm.cache.SetStaleTTL(cfg.Cache.StaleTTL)
}

// Get 获取缓存（默认 scope "-"）
func (cm *CacheManager) Get(domain string, qtype uint16) (*dns.Msg, bool, bool, int) {
	return cm.GetScoped("-", domain, qtype)
}

// GetScoped 获取指定 scope 的缓存
func (cm *CacheManager) GetScoped(scope, domain string, qtype uint16) (*dns.Msg, bool, bool, int) {
	timer := cm.logger.StartTimer("cache_get", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"scope":  scope,
	})
	defer timer.End()

	resp, hit, isCloud, cloudType := cm.cache.Get(scope, domain, qtype)

	if hit {
		cm.logger.Debug("💾 缓存命中详细信息", map[string]interface{}{
			"domain":   domain,
			"qtype":    dns.TypeToString[qtype],
			"is_cloud": isCloud,
			"hit_type": "normal_cache",
		})
		// 命中（含宽限内的过期旧值）一律不触发后台刷新：过期旧值由客户端下次重查时同步回源
	} else {
		cm.logger.Debug("🔍 缓存未命中详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": "cache_miss",
		})
	}

	return resp, hit, isCloud, cloudType
}

// GetServeScoped 命中快路径：返回预打包字节，供处理器直接打补丁写出。
// 仅在「未过期 + 非云条目 + 有可用预打包字节」时返回 true；
// 云条目、过期陈旧响应、打包失败一律返回 false，由调用方回退到 GetScoped 的重建路径。
func (cm *CacheManager) GetServeScoped(scope, domain string, qtype uint16) (Serve, bool) {
	timer := cm.logger.StartTimer("cache_get", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"scope":  scope,
	})
	defer timer.End()

	return cm.cache.GetServe(scope, domain, qtype)
}

// GetCloudResponse 获取云域名的替换响应缓存（默认 scope "-"）
func (cm *CacheManager) GetCloudResponse(domain string, qtype uint16) (*dns.Msg, bool, int) {
	return cm.GetCloudResponseScoped("-", domain, qtype)
}

// GetCloudResponseScoped 获取指定 scope 的云响应缓存
func (cm *CacheManager) GetCloudResponseScoped(scope, domain string, qtype uint16) (*dns.Msg, bool, int) {
	timer := cm.logger.StartTimer("cache_get_cloud", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})
	defer timer.End()

	resp, hit, cloudType := cm.cache.GetCloudResponse(scope, domain, qtype)

	if hit {
		cm.logger.Debug("☁️ 云响应缓存命中详细信息", map[string]interface{}{
			"domain":     domain,
			"qtype":      dns.TypeToString[qtype],
			"cloud_type": cloudType,
			"hit_type":   "cloud_response_cache",
		})
		// 命中不再触发后台刷新，过期由 Get 的宽限逻辑与客户端重查处理
	} else {
		cm.logger.Debug("☁️ 云响应缓存未命中详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": "cloud_response_cache_miss",
		})
	}

	return resp, hit, cloudType
}

// GetWithFlight 获取缓存响应（使用单飞行模式避免重复查询，默认 scope "-"）
func (cm *CacheManager) GetWithFlight(domain string, qtype uint16) (*dns.Msg, bool, bool, int) {
	return cm.GetWithFlightScoped("-", domain, qtype)
}

// GetWithFlightScoped 获取指定 scope 的缓存响应（使用单飞行模式）
func (cm *CacheManager) GetWithFlightScoped(scope, domain string, qtype uint16) (*dns.Msg, bool, bool, int) {
	// 使用单飞行模式来避免对同一域名的重复查询
	v, err, _ := cm.flightGroup.Do(scope+"|"+domain+"|"+dns.TypeToString[qtype], func() (interface{}, error) {
		resp, hit, isCloud, cloudType := cm.cache.Get(scope, domain, qtype)
		return struct {
			Resp      *dns.Msg
			Hit       bool
			IsCloud   bool
			CloudType int
		}{resp, hit, isCloud, cloudType}, nil
	})

	if err != nil {
		cm.logger.Error("单飞行查询错误", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"scope":  scope,
			"error":  err,
		})
		return nil, false, false, 0
	}

	result := v.(struct {
		Resp      *dns.Msg
		Hit       bool
		IsCloud   bool
		CloudType int
	})

	if result.Hit {
		cm.logger.Debug("💾 单飞行缓存命中", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"scope":  scope,
		})
		// 命中（含宽限内的过期旧值）一律不触发后台刷新：过期旧值由客户端下次重查时同步回源
	} else {
		cm.logger.Debug("🔍 单飞行缓存未命中", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"scope":  scope,
		})
	}

	return result.Resp, result.Hit, result.IsCloud, result.CloudType
}

// SetCloudResponse 设置云域名的替换响应缓存（默认 scope "-"）
func (cm *CacheManager) SetCloudResponse(domain string, qtype uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	cm.SetCloudResponseScoped("-", domain, qtype, response, cloudType, customTTL...)
}

// SetCloudResponseScoped 设置指定 scope 的云域名的替换响应缓存
func (cm *CacheManager) SetCloudResponseScoped(scope, domain string, qtype uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	timer := cm.logger.StartTimer("cache_set_cloud", map[string]interface{}{
		"domain":     domain,
		"qtype":      dns.TypeToString[qtype],
		"cloud_type": cloudType,
	})
	defer timer.End()

	if response == nil {
		cm.logger.Warn("尝试缓存空的云响应", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	// 使用自定义TTL或默认TTL
	ttl := cm.getConfig().Cache.TTL
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	}

	cm.cache.SetCloudResponse(scope, domain, qtype, response, cloudType, ttl)

	cm.logger.Info("📋 [缓存设置-云响应] ", map[string]interface{}{
		"domain":     domain,
		"rule":       "CACHE_SET_CLOUD",
		"cloud_type": cloudType,
	})

	cm.logger.Debug("☁️ 云响应缓存详细信息", map[string]interface{}{
		"domain":     domain,
		"qtype":      dns.TypeToString[qtype],
		"cloud_type": cloudType,
		"ttl":        ttl.String(),
		"answers":    len(response.Answer),
		"operation":  "cloud_response_cached",
	})

	// 如果TTL较短，提交异步刷新任务（不再在这里检查，移到Get时检查）
	// if cm.getConfig().Cache.EnableAsyncRefresh && ttl <= cm.getConfig().Cache.RefreshThreshold {
	//     cm.submitAsyncRefresh(domain, qtype, time.Now().Add(ttl), 1) // 高优先级
	// }
}

// IsCloud 检查域名是否为云服务域名
func (cm *CacheManager) IsCloud(domain string, qtype uint16) bool {
	return cm.cache.IsCloud("-", domain, qtype)
}

// IsDomainCloud 检查域名是否为云服务域名（默认 scope "-"）
func (cm *CacheManager) IsDomainCloud(domain string) bool {
	return cm.IsDomainCloudScoped("-", domain)
}

// IsDomainCloudScoped 检查指定 scope 的域名是否为云服务域名（跨所有查询类型）
func (cm *CacheManager) IsDomainCloudScoped(scope, domain string) bool {
	// 检查任何类型的查询是否标记为云服务域名
	// 检查常见的DNS查询类型
	commonTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT}
	for _, qtype := range commonTypes {
		if cm.cache.IsCloud(scope, domain, qtype) {
			return true
		}
	}
	return false
}

// MarkDomainAsCloud 将整个域名标记为云服务域名（默认 scope "-"）
func (cm *CacheManager) MarkDomainAsCloud(domain string, qtype uint16, cloudType int) {
	cm.MarkDomainAsCloudScoped("-", domain, qtype, cloudType)
}

// MarkDomainAsCloudScoped 将指定 scope 的整个域名标记为云服务域名（跨所有查询类型）
func (cm *CacheManager) MarkDomainAsCloudScoped(scope, domain string, qtype uint16, cloudType int) {
	// 首先标记当前查询类型
	cm.cache.Set(scope, domain, qtype, nil, true, cloudType)

	// 然后标记常见查询类型，以确保一致性
	commonTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT}
	for _, qt := range commonTypes {
		if qt != qtype {
			// 对于其他类型，只设置云标记，不覆盖已有的响应
			if !cm.cache.IsCloud(scope, domain, qt) {
				cm.cache.Set(scope, domain, qt, nil, true, cloudType)
			}
		}
	}
}

// Set 设置缓存（只缓存成功的响应，默认 scope "-"）
func (cm *CacheManager) Set(domain string, qtype uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	cm.SetScoped("-", domain, qtype, response, isCloud, cloudType...)
}

// SetScoped 设置指定 scope 的缓存（只缓存成功的响应）
func (cm *CacheManager) SetScoped(scope, domain string, qtype uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	timer := cm.logger.StartTimer("cache_set", map[string]interface{}{
		"domain":   domain,
		"qtype":    dns.TypeToString[qtype],
		"is_cloud": isCloud,
	})
	defer timer.End()

	// 云服务域名特殊处理
	if isCloud {
		cm.cache.Set(scope, domain, qtype, nil, true, cloudType...)
		cm.logger.Info("📋 [缓存设置-云标记] ", map[string]interface{}{
			"domain": domain,
			"rule":   "CACHE_SET_CLOUD_MARK",
		})
		cm.logger.Debug("☁️ 云服务域名标记缓存详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	if response == nil {
		cm.logger.Warn("尝试缓存空响应", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	// 非成功响应缓存策略（对齐 AdGuard Home）：
	//   NXDOMAIN 且 Authority 段含 SOA → 负缓存（RFC 2308，TTL 取最小记录 TTL）
	//   SERVFAIL → 短缓存 15s，避免上游抖动被放大成连续失败
	//   其余非成功响应 → 不缓存
	if response.Rcode != dns.RcodeSuccess {
		if ttl, ok := nonSuccessCacheTTL(response); ok {
			cm.cache.SetWithTTL(scope, domain, qtype, response, isCloud, ttl, cloudType...)
			cm.logger.Debug("非成功响应已缓存", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
				"rcode":  dns.RcodeToString[response.Rcode],
				"ttl":    ttl.String(),
			})
			return
		}
		cm.logger.Debug("非成功响应不可缓存", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"rcode":  dns.RcodeToString[response.Rcode],
		})
		return
	}

	// 缓存普通成功响应
	cm.cache.Set(scope, domain, qtype, response, isCloud, cloudType...)
	cm.logger.Debug("💾 普通响应已缓存", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"rcode":  dns.RcodeToString[response.Rcode],
	})
}

// SetWithTTL 设置缓存（使用自定义TTL，默认 scope "-"）
func (cm *CacheManager) SetWithTTL(domain string, qtype uint16, response *dns.Msg, isCloud bool, customTTL time.Duration, cloudType ...int) {
	cm.SetWithTTLScoped("-", domain, qtype, response, isCloud, customTTL, cloudType...)
}

// SetWithTTLScoped 设置指定 scope 的缓存（使用自定义TTL）
func (cm *CacheManager) SetWithTTLScoped(scope, domain string, qtype uint16, response *dns.Msg, isCloud bool, customTTL time.Duration, cloudType ...int) {
	timer := cm.logger.StartTimer("cache_set", map[string]interface{}{
		"domain":   domain,
		"qtype":    dns.TypeToString[qtype],
		"is_cloud": isCloud,
	})
	defer timer.End()

	// 云服务域名特殊处理
	if isCloud {
		cm.cache.Set(scope, domain, qtype, nil, true, cloudType...)
		cm.logger.Info("📋 [缓存设置-云标记] ", map[string]interface{}{
			"domain": domain,
			"rule":   "CACHE_SET_CLOUD_MARK",
		})
		cm.logger.Debug("☁️ 云服务域名标记缓存详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	if response == nil {
		cm.logger.Warn("尝试缓存空响应", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	// 非成功响应缓存策略（对齐 AdGuard Home）：
	//   NXDOMAIN 且 Authority 段含 SOA → 负缓存（RFC 2308，TTL 取最小记录 TTL）
	//   SERVFAIL → 短缓存 15s，避免上游抖动被放大成连续失败
	//   其余非成功响应 → 不缓存
	if response.Rcode != dns.RcodeSuccess {
		if ttl, ok := nonSuccessCacheTTL(response); ok {
			cm.cache.SetWithTTL(scope, domain, qtype, response, isCloud, ttl, cloudType...)
			cm.logger.Debug("非成功响应已缓存", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
				"rcode":  dns.RcodeToString[response.Rcode],
				"ttl":    ttl.String(),
			})
			return
		}
		cm.logger.Debug("非成功响应不可缓存", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"rcode":  dns.RcodeToString[response.Rcode],
		})
		return
	}

	// 使用自定义TTL缓存响应
	cm.cache.SetWithTTL(scope, domain, qtype, response, isCloud, customTTL, cloudType...)
	cm.logger.Debug("💾 普通响应已缓存", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"rcode":  dns.RcodeToString[response.Rcode],
	})
}

// servFailCacheTTL SERVFAIL 的短缓存时长（上限 15s）
const servFailCacheTTL = 15 * time.Second

// nonSuccessCacheTTL 返回非成功响应可用的缓存 TTL（与 AdGuard Home 对齐）：
// SERVFAIL 固定短缓存 15s；NXDOMAIN 且 Authority 含 SOA 走 RFC 2308 负缓存；其余不可缓存
func nonSuccessCacheTTL(m *dns.Msg) (time.Duration, bool) {
	if m == nil {
		return 0, false
	}
	if m.Rcode == dns.RcodeServerFailure {
		return servFailCacheTTL, true
	}
	return cacheableNegativeTTL(m)
}

// cacheableNegativeTTL 判定非成功响应是否可做负缓存并返回其 TTL（RFC 2308，与 dnsproxy 一致）：
// 仅 NXDOMAIN 且 Authority 段含 SOA、不含 NS 时可缓存；TTL 取整条响应中最小的记录 TTL
func cacheableNegativeTTL(m *dns.Msg) (time.Duration, bool) {
	if m == nil || m.Rcode != dns.RcodeNameError {
		return 0, false
	}
	var hasSOA, hasNS bool
	var minTTL uint32
	for _, rr := range m.Ns {
		if rr == nil {
			continue
		}
		switch rr.(type) {
		case *dns.SOA:
			hasSOA = true
		case *dns.NS:
			hasNS = true
		}
	}
	if !hasSOA || hasNS {
		return 0, false
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr == nil {
				continue
			}
			if t := rr.Header().Ttl; t > 0 && (minTTL == 0 || t < minTTL) {
				minTTL = t
			}
		}
	}
	if minTTL == 0 {
		return 0, false
	}
	return time.Duration(minTTL) * time.Second, true
}

// isValidDNSResponse 验证DNS响应是否值得缓存
// 成功响应（NOERROR）、SERVFAIL 短缓存、以及可负缓存的 NXDOMAIN（Authority 含 SOA）均值得缓存
func (cm *CacheManager) isValidDNSResponse(domain string, qtype uint16, response *dns.Msg) bool {
	if response == nil {
		return false
	}

	if response.Rcode == dns.RcodeSuccess {
		return true
	}
	if _, ok := nonSuccessCacheTTL(response); ok {
		return true
	}

	cm.logger.Debug("🔍 DNS响应非成功，不缓存", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"rcode":  dns.RcodeToString[response.Rcode],
	})
	return false
}

// isInvalidIP 检查IP地址是否为无效/不应该缓存的IP
func (cm *CacheManager) isInvalidIP(ip string) bool {
	// 空字符串
	if ip == "" {
		return true
	}

	// 常见的无效IP地址
	invalidIPs := []string{
		"0.0.0.0",         // 未指定地址
		"127.0.0.1",       // 本地地址
		"255.255.255.255", // 广播地址
		"::1",             // IPv6本地地址
		"::",              // IPv6未指定地址
	}

	for _, invalidIP := range invalidIPs {
		if ip == invalidIP {
			return true
		}
	}

	// 检查可疑的IP模式（如停放页面常用的IP）
	suspiciousPatterns := []string{
		"127.",     // 本地回环
		"169.254.", // 自动配置地址
		"224.",     // 多播地址
		"239.",     // 多播地址
	}

	for _, pattern := range suspiciousPatterns {
		if len(ip) > len(pattern) && ip[:len(pattern)] == pattern {
			cm.logger.Debug("⚠️ 检测到可疑IP模式", map[string]interface{}{
				"ip":      ip,
				"pattern": pattern,
			})
			return true
		}
	}

	return false
}

// shouldRefresh 检查是否应该刷新缓存
func (cm *CacheManager) shouldRefresh(domain string, qtype uint16) bool {
	// 使用配置中的刷新阈值检查是否需要刷新
	shouldRefresh := cm.cache.ShouldRefreshWithThreshold("-", domain, qtype, 30*time.Second) // 使用默认30秒阈值

	// 添加调试日志
	cm.logger.Debug("🔍 shouldRefresh检查", map[string]interface{}{
		"domain":            domain,
		"qtype":             dns.TypeToString[qtype],
		"should_refresh":    shouldRefresh,
		"async_enabled":     true,  // 异步刷新默认启用
		"refresh_threshold": "30s", // 默认30秒阈值
	})

	return shouldRefresh
}

// shouldRefreshOnDemand 检查是否应该按需刷新（缓存已过期）
func (cm *CacheManager) shouldRefreshOnDemand(domain string, qtype uint16) bool {
	// 直接看过期时间即可：存在且已过期才需要按需刷新（省掉多余的响应反解）
	expireAt := cm.cache.GetExpireTime("-", domain, qtype)
	shouldRefresh := !expireAt.IsZero() && time.Until(expireAt) <= 0

	cm.logger.Debug("🔍 shouldRefreshOnDemand检查", map[string]interface{}{
		"domain":         domain,
		"qtype":          dns.TypeToString[qtype],
		"should_refresh": shouldRefresh,
		"hit":            !expireAt.IsZero(),
		"async_enabled":  true, // 异步刷新默认启用
	})

	return shouldRefresh
}

// submitAsyncRefresh 提交异步刷新任务
func (cm *CacheManager) submitAsyncRefresh(domain string, qtype uint16, expireTime time.Time, priority int) {
	key := fmt.Sprintf("%s:%d", domain, qtype)

	cm.asyncMu.Lock()
	if _, exists := cm.asyncSet[key]; exists {
		cm.asyncMu.Unlock()
		return
	}
	cm.asyncSet[key] = struct{}{}
	cm.asyncMu.Unlock()

	task := &AsyncRefreshTask{
		Domain:     domain,
		QType:      qtype,
		ExpireTime: expireTime,
		Priority:   priority,
	}

	select {
	case cm.asyncChan <- task:
		cm.logger.Debug("📋 异步刷新任务已提交", map[string]interface{}{
			"domain":   domain,
			"qtype":    dns.TypeToString[qtype],
			"priority": priority,
		})
	default:
		cm.logger.Warn("⚠️ 异步刷新队列已满", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		cm.asyncMu.Lock()
		delete(cm.asyncSet, key)
		cm.asyncMu.Unlock()
	}
}

// submitOnDemandRefresh 提交按需刷新任务
func (cm *CacheManager) submitOnDemandRefresh(domain string, qtype uint16) {
	key := fmt.Sprintf("%s:%d", domain, qtype)

	cm.asyncMu.Lock()
	if _, exists := cm.asyncSet[key]; exists {
		cm.asyncMu.Unlock()
		return
	}
	cm.asyncSet[key] = struct{}{}
	cm.asyncMu.Unlock()

	// 设置一个较短的过期时间，确保任务能尽快执行
	expireTime := time.Now().Add(10 * time.Second)

	task := &AsyncRefreshTask{
		Domain:     domain,
		QType:      qtype,
		ExpireTime: expireTime,
		Priority:   2, // 按需刷新具有较高优先级
	}

	select {
	case cm.asyncChan <- task:
		cm.logger.Debug("📋 按需刷新任务已提交", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
	default:
		cm.logger.Warn("⚠️ 异步刷新队列已满", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		cm.asyncMu.Lock()
		delete(cm.asyncSet, key)
		cm.asyncMu.Unlock()
	}
}

// startCacheScanTask 启动定期缓存扫描任务（带panic恢复）
// 按需刷新模式下已禁用此功能
/*
func (cm *CacheManager) startCacheScanTask() {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			cm.logger.Error("💥 [缓存扫描任务panic] ", map[string]interface{}{
				"rule":        "CACHE_SCAN_PANIC",
				"panic_msg":   fmt.Sprintf("%v", r),
				"stack_trace": string(debug.Stack()),
			})
			// 重新启动扫描任务
			time.Sleep(10 * time.Second) // 等待一段时间再重启
			go cm.startCacheScanTask()
		}
	}()

	// 每30秒扫描一次缓存（降低扫描频率）
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	cm.logger.Info("🔍 定期缓存扫描任务已启动", map[string]interface{}{
		"scan_interval":     "30s",
		"refresh_threshold": cm.getConfig().Cache.RefreshThreshold.String(),
	})

	for {
		select {
		case <-ticker.C:
			cm.scanCacheForRefresh()
		case <-cm.workerPool.stopCh:
			cm.logger.Info("🔍 定期缓存扫描任务已停止")
			return
		}
	}
}
*/

// scanCacheForRefresh 扫描缓存并提交需要刷新的条目
// 按需刷新模式下已禁用此功能
/*
func (cm *CacheManager) scanCacheForRefresh() {
	stats := cm.cache.GetStats()
	if stats.Size == 0 {
		cm.logger.Debug("🔍 缓存为空，跳过扫描")
		return
	}

	cm.logger.Debug("🔍 开始扫描缓存条目", map[string]interface{}{
		"cache_size": stats.Size,
	})

	// 获取需要刷新的条目
	entriesToRefresh := cm.cache.GetExpiringSoonEntries(cm.getConfig().Cache.RefreshThreshold)

	if len(entriesToRefresh) > 0 {
		cm.logger.Info("🔄 发现需要刷新的缓存条目", map[string]interface{}{
			"count":             len(entriesToRefresh),
			"refresh_threshold": cm.getConfig().Cache.RefreshThreshold.String(),
		})

		// 限制同时提交的刷新任务数量，防止队列溢出
		maxTasks := cap(cm.asyncChan) / 2
		submitted := 0

		for _, entry := range entriesToRefresh {
			if submitted >= maxTasks {
				cm.logger.Warn("⚠️ 刷新任务达到上限，停止提交新任务", map[string]interface{}{
					"submitted": submitted,
					"max_tasks": maxTasks,
				})
				break
			}

			// 计算过期时间（当前时间 + TTL）
			expireTime := time.Now().Add(cm.getConfig().Cache.TTL)
			priority := 0
			if entry.IsCloud {
				priority = 1 // 云域名高优先级
			}
			cm.logger.Debug("📋 提交异步刷新任务", map[string]interface{}{
				"domain":   entry.Domain,
				"qtype":    dns.TypeToString[entry.QType],
				"is_cloud": entry.IsCloud,
				"priority": priority,
			})
			cm.submitAsyncRefresh(entry.Domain, entry.QType, expireTime, priority)
			submitted++
		}
	} else {
		cm.logger.Debug("🔍 未发现需要刷新的缓存条目", map[string]interface{}{
			"cache_size": stats.Size,
		})
	}
}
*/

// CacheEntryInfo 缓存条目信息
type CacheEntryInfo struct {
	Domain  string
	QType   uint16
	IsCloud bool
}

// startAsyncWorkers 启动异步工作器
func (cm *CacheManager) startAsyncWorkers() {
	workers := cm.getConfig().Cache.MaxAsyncWorkers
	if workers <= 0 {
		workers = 5
	}

	for i := 0; i < workers; i++ {
		go cm.asyncWorker(i)
	}

	cm.logger.Info("🔄 异步刷新工作器启动完成", map[string]interface{}{
		"workers": workers,
	})
}

// asyncWorker 异步工作器（带panic恢复）
func (cm *CacheManager) asyncWorker(workerID int) {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			cm.logger.Error("💥 [异步工作器panic] ", map[string]interface{}{
				"rule":        "ASYNC_WORKER_PANIC",
				"worker_id":   workerID,
				"panic_msg":   fmt.Sprintf("%v", r),
				"stack_trace": string(debug.Stack()),
			})
			// 重新启动工作器
			time.Sleep(1 * time.Second) // 短暂等待后再重启
			go cm.asyncWorker(workerID)
		}
	}()

	cm.logger.Debug("🔄 异步工作器启动", map[string]interface{}{
		"worker_id": workerID,
	})

	// 为每个工作器设置处理超时，防止任务卡住
	for {
		select {
		case task := <-cm.asyncChan:
			// 为每个任务设置超时
			taskCtx, taskCancel := context.WithTimeout(context.Background(), 10*time.Second)

			done := make(chan struct{})
			go func() {
				cm.processAsyncTask(task, workerID)
				close(done)
			}()

			select {
			case <-done:
				// 任务完成
			case <-taskCtx.Done():
				// 任务超时
				cm.logger.Warn("⏰ 异步任务处理超时", map[string]interface{}{
					"domain":    task.Domain,
					"qtype":     dns.TypeToString[task.QType],
					"worker_id": workerID,
				})

				// 清理任务状态
				key := fmt.Sprintf("%s:%d", task.Domain, task.QType)
				cm.asyncMu.Lock()
				delete(cm.asyncSet, key)
				cm.asyncMu.Unlock()
			}

			taskCancel()
		case <-cm.workerPool.stopCh:
			cm.logger.Debug("🔄 异步工作器停止", map[string]interface{}{
				"worker_id": workerID,
			})
			return
		}
	}
}

// processAsyncTask 处理异步任务
func (cm *CacheManager) processAsyncTask(task *AsyncRefreshTask, workerID int) {
	key := fmt.Sprintf("%s:%d", task.Domain, task.QType)

	// 获取域名锁，防止多个worker同时处理同一个域名
	cm.locksMu.Lock()
	lock, exists := cm.domainLocks[task.Domain]
	if !exists {
		lock = &sync.Mutex{}
		cm.domainLocks[task.Domain] = lock
	}
	cm.locksMu.Unlock()

	// 获取锁
	lock.Lock()
	defer func() {
		// 释放锁
		lock.Unlock()

		// 添加panic恢复机制
		if r := recover(); r != nil {
			cm.logger.Error("💥 [异步任务处理panic] ", map[string]interface{}{
				"rule":        "ASYNC_TASK_PANIC",
				"worker_id":   workerID,
				"domain":      task.Domain,
				"qtype":       dns.TypeToString[task.QType],
				"panic_msg":   fmt.Sprintf("%v", r),
				"stack_trace": string(debug.Stack()),
			})
		}

		cm.asyncMu.Lock()
		delete(cm.asyncSet, key)
		cm.asyncMu.Unlock()
	}()

	// 检查任务是否过期
	if time.Now().After(task.ExpireTime) {
		cm.logger.Debug("⏰ 异步任务已过期", map[string]interface{}{
			"domain":    task.Domain,
			"qtype":     dns.TypeToString[task.QType],
			"worker_id": workerID,
		})
		return
	}

	timer := cm.logger.StartTimer("async_refresh", map[string]interface{}{
		"domain":    task.Domain,
		"qtype":     dns.TypeToString[task.QType],
		"worker_id": workerID,
		"priority":  task.Priority,
	})

	cm.logger.Debug("🔄 开始异步刷新", map[string]interface{}{
		"domain":    task.Domain,
		"qtype":     dns.TypeToString[task.QType],
		"worker_id": workerID,
	})

	// 这里需要从handler获取刷新函数
	// 由于循环依赖，我们通过回调方式处理
	if cm.refreshCallback != nil {
		if err := cm.refreshCallback(task.Domain, task.QType); err != nil {
			timer.EndWithError(err)
			cm.logger.Error("🔄 异步刷新失败", map[string]interface{}{
				"domain":    task.Domain,
				"qtype":     dns.TypeToString[task.QType],
				"worker_id": workerID,
				"error":     err.Error(),
			})

			// 刷新失败时，删除过期缓存条目
			cm.cache.Delete("-", task.Domain, task.QType)
			cm.logger.Debug("🗑️ 缓存条目已删除", map[string]interface{}{
				"domain": task.Domain,
				"qtype":  dns.TypeToString[task.QType],
			})
		} else {
			timer.End()
			cm.logger.Debug("✅ 异步刷新完成", map[string]interface{}{
				"domain":    task.Domain,
				"qtype":     dns.TypeToString[task.QType],
				"worker_id": workerID,
			})
		}
	} else {
		timer.EndWithError(fmt.Errorf("refresh callback is nil"))
		cm.logger.Warn("⚠️ 刷新回调未设置", map[string]interface{}{
			"domain":    task.Domain,
			"qtype":     dns.TypeToString[task.QType],
			"worker_id": workerID,
		})
	}
}

// RefreshCallback 刷新回调函数类型
type RefreshCallback func(domain string, qtype uint16) error

// SetRefreshCallback 设置刷新回调
func (cm *CacheManager) SetRefreshCallback(callback RefreshCallback) {
	cm.refreshCallback = callback
}

// Clear 清空缓存
func (cm *CacheManager) Clear() {
	cm.cache.Clear()

	// 清空异步任务
	cm.asyncMu.Lock()
	cm.asyncSet = make(map[string]struct{})
	cm.asyncMu.Unlock()

	// 清空队列
	for len(cm.asyncChan) > 0 {
		<-cm.asyncChan
	}

	cm.logger.Info("🗑️ 缓存已清空")
}

// GetStats 获取缓存统计信息
func (cm *CacheManager) GetStats(includeEntries bool) *CacheStats {
	stats := cm.cache.GetStats(includeEntries)
	// 添加IP统计信息
	ipCounts := cm.cache.CountCachedIPs()
	if stats != nil {
		stats.IPCounts = ipCounts
	}
	return stats
}

// GetHotEntries 获取热点条目
func (cm *CacheManager) GetHotEntries(limit int) []HotEntry {
	return cm.cache.GetHotEntries(limit)
}

// ExtendTTL 延长缓存条目的过期时间
func (cm *CacheManager) ExtendTTL(domain string, qtype uint16, duration time.Duration) {
	cm.cache.ExtendTTL("-", domain, qtype, duration)
	cm.logger.Debug("🕒 缓存TTL已延长", map[string]interface{}{
		"domain":   domain,
		"qtype":    dns.TypeToString[qtype],
		"duration": duration.String(),
	})
}

// Close 关闭缓存管理器
func (cm *CacheManager) Close() {
	cm.workerPool.mu.Lock()
	if !cm.workerPool.stopped {
		close(cm.workerPool.stopCh)
		cm.workerPool.stopped = true
	}
	cm.workerPool.mu.Unlock()

	cm.Clear()
	// 注意：不能关闭 asyncChan。worker 统一由 stopCh 退出，一旦关闭该 channel，
	// 晚一步进入 select 的 worker 会立刻读到 nil 任务并在 processAsyncTask 空指针崩溃；
	// 提交端也会因 "send on closed channel" panic。

	cm.logger.Info("📪 缓存管理器已关闭")
}
