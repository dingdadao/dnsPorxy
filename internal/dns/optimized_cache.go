package dns

import (
	"encoding/binary"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	ExpireAt         time.Time
	StoredAt         time.Time     // 写入缓存的时间，用于命中时递减TTL（RFC 1035 §4.3.1）
	IsCloud          bool          // 标记是否为云服务域名
	CloudType        int           // 云服务类型（0-无，1-Cloudflare，2-AWS）
	CloudResponse    *dns.Msg      // 云域名的替换响应缓存
	RefreshThreshold time.Duration // 异步刷新阈值
	lastAccess       atomic.Int64  // 最后访问时间（UnixNano）：命中路径原子写，避免抢分片写锁
	wire             []byte        // 预打包响应字节（已剔除OPT、已压缩），命中时直接打补丁写出
	wmeta            wireMeta      // wire 的补丁元信息；wire 无效时为 ok=false

	// 以下为普通（非云）条目的预计算结果：命中快路径的日志与统计需要，避免每次从 wire 反解
	rcode       int    // 响应 RCODE
	answers     string // 预计算的 answersSummary
	answerCount int    // Answer 段记录数
	ipv4Count   int    // Answer 段 A 记录数
	ipv6Count   int    // Answer 段 AAAA 记录数

	// Response 仅作为 buildWire 失败（极少数不可预打包响应）时的兜底对象树，正常条目为 nil
	Response *dns.Msg
}

// ttlField 一个 RR 的 TTL 字段在 wire 中的偏移及其写入缓存时的原始值
type ttlField struct {
	off uint16
	ttl uint32
}

// wireMeta 预打包响应的补丁元信息
type wireMeta struct {
	ok       bool       // 扫描成功才可用于直写
	qnameOff int        // Question 段 NAME 的起始偏移
	qnameLen int        // Question 段 NAME 的编码长度（含结尾的 0x00）
	ttls     []ttlField // 全部 RR（Answer/Ns/Extra）的 TTL 字段位置
}

// touch 记录一次访问（原子写，命中路径无需持锁）
func (e *CacheEntry) touch() { e.touchAt(time.Now()) }

// touchAt 用给定时刻记录一次访问
func (e *CacheEntry) touchAt(t time.Time) { e.lastAccess.Store(t.UnixNano()) }

// lastAccessTime 读取最后访问时间
func (e *CacheEntry) lastAccessTime() time.Time { return time.Unix(0, e.lastAccess.Load()) }

// CacheShard 缓存分片
type CacheShard struct {
	mu          sync.RWMutex
	store       map[string]*CacheEntry
	flightGroup singleflight.Group
}

// CacheEntryPool CacheEntry对象池
type CacheEntryPool struct {
	pool sync.Pool
}

// NewCacheEntryPool 创建CacheEntry对象池
func NewCacheEntryPool() *CacheEntryPool {
	return &CacheEntryPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &CacheEntry{}
			},
		},
	}
}

// Get 从对象池获取CacheEntry
func (p *CacheEntryPool) Get() *CacheEntry {
	return p.pool.Get().(*CacheEntry)
}

// Put 将CacheEntry放回对象池
func (p *CacheEntryPool) Put(entry *CacheEntry) {
	// 重置字段
	entry.Response = nil
	entry.CloudResponse = nil
	entry.wire = nil
	entry.wmeta = wireMeta{}
	entry.rcode = 0
	entry.answers = ""
	entry.answerCount = 0
	entry.ipv4Count = 0
	entry.ipv6Count = 0
	entry.ExpireAt = time.Time{}
	entry.StoredAt = time.Time{}
	entry.IsCloud = false
	entry.CloudType = 0
	entry.RefreshThreshold = 0
	entry.lastAccess.Store(0)
	p.pool.Put(entry)
}

// OptimizedDNSCache 优化的DNS缓存系统
type OptimizedDNSCache struct {
	shards     []*CacheShard
	shardCount int
	maxSize    int
	defaultTTL atomic.Int64 // 兜底TTL（纳秒），支持热更新
	staleTTL   atomic.Int64 // 过期宽限（纳秒），0=禁用 serve-stale；支持热更新
	entryPool  *CacheEntryPool
}

// NewOptimizedDNSCache 创建一个新的优化DNS缓存系统
func NewOptimizedDNSCache(maxSize int, defaultTTL time.Duration) *OptimizedDNSCache {
	// 确定分片数量，根据CPU核心数或固定值
	shardCount := 16
	if shardCount <= 0 {
		shardCount = 8 // 默认8个分片
	}

	shards := make([]*CacheShard, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = &CacheShard{
			store:       make(map[string]*CacheEntry),
			flightGroup: singleflight.Group{},
		}
	}

	cache := &OptimizedDNSCache{
		shards:     shards,
		shardCount: shardCount,
		maxSize:    maxSize,
		entryPool:  NewCacheEntryPool(),
	}
	cache.defaultTTL.Store(int64(defaultTTL))

	// 启动后台清理协程
	go cache.cleanupRoutine()

	return cache
}

// defTTL 返回当前兜底TTL
func (c *OptimizedDNSCache) defTTL() time.Duration {
	return time.Duration(c.defaultTTL.Load())
}

// SetDefaultTTL 热更新兜底TTL
func (c *OptimizedDNSCache) SetDefaultTTL(ttl time.Duration) {
	c.defaultTTL.Store(int64(ttl))
}

// SetStaleTTL 热更新过期宽限（0=禁用 serve-stale，过期即未命中）
func (c *OptimizedDNSCache) SetStaleTTL(ttl time.Duration) {
	c.staleTTL.Store(int64(ttl))
}

// staleGrace 返回当前过期宽限
func (c *OptimizedDNSCache) staleGrace() time.Duration {
	return time.Duration(c.staleTTL.Load())
}

// key 生成缓存键，scope 用于客户端分组隔离（未命中分组为 "-"）
func (c *OptimizedDNSCache) key(scope, domain string, qType uint16) string {
	if scope == "" {
		scope = "-"
	}
	return scope + "|" + domain + "|" + dns.TypeToString[qType]
}

// getShard 根据键获取对应的缓存分片
func (c *OptimizedDNSCache) getShard(key string) *CacheShard {
	// 使用简单的哈希函数将键映射到分片
	hash := 0
	for i := 0; i < len(key); i++ {
		hash = (hash << 5) - hash + int(key[i])
	}
	if hash < 0 {
		hash = -hash
	}
	return c.shards[hash%c.shardCount]
}

// decrementTTLs 按缓存时长递减响应中所有RR的TTL（下限0），跳过OPT记录
// 符合 RFC 1035 §4.3.1：TTL表示剩余生存时间，缓存返回时必须按 now - storedAt 递减
func decrementTTLs(msg *dns.Msg, elapsed time.Duration) {
	if msg == nil || elapsed <= 0 {
		return
	}
	secs := uint32(elapsed.Seconds())
	if secs == 0 {
		return
	}
	dec := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, isOPT := rr.(*dns.OPT); isOPT {
				continue // OPT的TTL字段是扩展rcode/flags，不能递减
			}
			h := rr.Header()
			if h.Ttl <= secs {
				h.Ttl = 0
			} else {
				h.Ttl -= secs
			}
		}
	}
	dec(msg.Answer)
	dec(msg.Ns)
	dec(msg.Extra)
}

// buildWire 把响应预打包为字节并扫描出补丁元信息。
// 会就地剥离 Extra 段中的 OPT（响应出口由 writeResponse 按请求回带 OPT），
// 剥离失败或结构不支持时返回 ok=false，命中时自动回退到深拷贝路径。
func buildWire(msg *dns.Msg) ([]byte, wireMeta) {
	if msg == nil {
		return nil, wireMeta{}
	}

	// 剥离 OPT：与 writeResponse 的行为保持一致，避免把首个客户端的 EDNS 参数固化进缓存
	if len(msg.Extra) > 0 {
		extra := msg.Extra[:0]
		for _, rr := range msg.Extra {
			if _, isOPT := rr.(*dns.OPT); !isOPT {
				extra = append(extra, rr)
			}
		}
		msg.Extra = extra
	}
	msg.Compress = true

	data, err := msg.Pack()
	if err != nil {
		return nil, wireMeta{}
	}
	meta := scanWire(data)
	if !meta.ok {
		return nil, wireMeta{}
	}
	return data, meta
}

// storeWire 把响应预打包到条目上，并预计算命中快路径所需的日志/统计字段。
// 预打包失败（极少数不可直写的响应）时保留对象树兜底，保证缓存语义不变。
func (e *CacheEntry) storeWire(response *dns.Msg) {
	e.rcode, e.answers, e.answerCount, e.ipv4Count, e.ipv6Count = entrySummary(response)
	e.wire, e.wmeta = buildWire(response)
	if !e.wmeta.ok {
		e.Response = response
		e.wire = nil
		e.wmeta = wireMeta{}
	}
}

// scanWire 扫描已打包的响应，记录 Question 段 NAME 位置与所有 RR 的 TTL 字段偏移。
// 任何超出预期的结构（多问题、Question 段带压缩指针、长度对不上）都判定为不支持。
func scanWire(b []byte) wireMeta {
	meta := wireMeta{}
	if len(b) < 12 {
		return meta
	}

	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))
	if qd != 1 {
		return meta // 命中快路径只支持单问题响应
	}

	off := 12
	meta.qnameOff = off
	// Question 段 NAME：不支持压缩指针
	for {
		if off >= len(b) {
			return wireMeta{}
		}
		l := int(b[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			return wireMeta{}
		}
		off += 1 + l
	}
	meta.qnameLen = off - meta.qnameOff

	// QTYPE + QCLASS
	if off+4 > len(b) {
		return wireMeta{}
	}
	off += 4

	// 逐个 RR 记录 TTL 偏移（NAME 可能带压缩指针，按指针/标签跳过）
	meta.ttls = make([]ttlField, 0, an+ns+ar)
	for i := 0; i < an+ns+ar; i++ {
		for {
			if off >= len(b) {
				return wireMeta{}
			}
			c := b[off]
			if c&0xC0 == 0xC0 {
				off += 2
				break
			}
			if c == 0 {
				off++
				break
			}
			off += 1 + int(c)
		}
		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
		if off+10 > len(b) {
			return wireMeta{}
		}
		ttlOff := off + 4
		meta.ttls = append(meta.ttls, ttlField{
			off: uint16(ttlOff),
			ttl: binary.BigEndian.Uint32(b[ttlOff : ttlOff+4]),
		})
		off += 10 + int(binary.BigEndian.Uint16(b[off+8:off+10]))
		if off > len(b) {
			return wireMeta{}
		}
	}

	if off != len(b) {
		return wireMeta{} // 没能恰好走完整包，说明扫描逻辑与结构不符
	}
	meta.ok = true
	return meta
}

// entrySummary 汇总一条响应在缓存里需要预先算好的日志/统计字段
func entrySummary(resp *dns.Msg) (rcode int, answers string, answerCount, ipv4, ipv6 int) {
	if resp == nil {
		return 0, "", 0, 0, 0
	}
	rcode = resp.Rcode
	answerCount = len(resp.Answer)
	answers = answersSummary(resp)
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A:
			ipv4++
		case *dns.AAAA:
			ipv6++
		}
	}
	return rcode, answers, answerCount, ipv4, ipv6
}

// materialize 用预打包字节重建一份可写响应；不可预打包的兜底条目回退到保留的对象树副本。
// 返回 nil 表示该条目没有可用的响应内容。
func materialize(wire []byte, meta wireMeta, fallback *dns.Msg) *dns.Msg {
	if wire != nil && meta.ok {
		m := new(dns.Msg)
		if err := m.Unpack(wire); err == nil {
			return m
		}
	}
	if fallback != nil {
		return fallback.Copy()
	}
	return nil
}

// Serve 命中快路径结果：Wire 是缓存内部对象，调用方只能读，不能修改
type Serve struct {
	Wire     []byte
	Meta     wireMeta
	StoredAt time.Time
	Rcode    int    // 预计算的响应 RCODE，供命中日志使用
	Answers  string // 预计算的 answersSummary，供命中日志使用
}

// GetServe 命中快路径查询：返回预打包字节，供处理器直接打补丁写出。
// 仅在「未过期 + 非云条目 + 有可用预打包字节」时返回 ok=true，
// 其余情况（云条目、过期陈旧响应、打包失败）一律返回 false，由调用方回退到 Get 的路径。
func (c *OptimizedDNSCache) GetServe(scope, domain string, qType uint16) (Serve, bool) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	if !exists {
		shard.mu.RUnlock()
		return Serve{}, false
	}
	isCloud := entry.IsCloud
	wire := entry.wire
	meta := entry.wmeta
	storedAt := entry.StoredAt
	expireAt := entry.ExpireAt
	rcode := entry.rcode
	answers := entry.answers
	shard.mu.RUnlock()

	if isCloud || wire == nil || !meta.ok {
		return Serve{}, false
	}

	now := time.Now()
	if now.After(expireAt) {
		return Serve{}, false // 过期陈旧响应仍走原路径（含 TTL 调整与按需刷新）
	}
	entry.touchAt(now)

	return Serve{
		Wire:     wire,
		Meta:     meta,
		StoredAt: storedAt,
		Rcode:    rcode,
		Answers:  answers,
	}, true
}

// GetCloudResponse 获取云域名的替换响应缓存
func (c *OptimizedDNSCache) GetCloudResponse(scope, domain string, qType uint16) (*dns.Msg, bool, int) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists || !entry.IsCloud {
		return nil, false, 0
	}

	// 检查是否过期
	if time.Now().After(entry.ExpireAt) {
		// 异步删除过期条目
		go func() {
			shard.mu.Lock()
			delete(shard.store, key)
			shard.mu.Unlock()
		}()
		return nil, false, 0
	}

	// 更新最后访问时间（原子写，无需持锁）
	entry.touch()

	// 返回云响应缓存（副本，递减TTL）
	if entry.CloudResponse != nil {
		resp := entry.CloudResponse.Copy()
		decrementTTLs(resp, time.Since(entry.StoredAt))
		return resp, true, entry.CloudType
	}
	return nil, false, entry.CloudType
}

// SetCloudResponse 设置云域名的替换响应缓存
func (c *OptimizedDNSCache) SetCloudResponse(scope, domain string, qType uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	// 使用自定义TTL或默认TTL
	ttl := c.defTTL()
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	}

	// 计算刷新阈值（TTL的30%）
	refreshThreshold := time.Duration(float64(ttl) * 0.3)

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.Response = nil // 不缓存原始响应
	entry.CloudResponse = response.Copy()
	entry.ExpireAt = time.Now().Add(ttl)
	entry.StoredAt = time.Now()
	entry.IsCloud = true
	entry.CloudType = cloudType
	entry.RefreshThreshold = refreshThreshold
	entry.touch()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查是否需要清理缓存
	if len(shard.store) >= c.maxSize/c.shardCount {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储云域名缓存
	shard.store[key] = entry
}

// Get 获取缓存响应
func (c *OptimizedDNSCache) Get(scope, domain string, qType uint16) (*dns.Msg, bool, bool, int) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	if exists {
		// StoredAt/IsCloud/CloudResponse 等字段写入后不再变更，可在读锁内安全取出
		storedAt := entry.StoredAt
		isCloud := entry.IsCloud
		cloudType := entry.CloudType
		wire := entry.wire
		meta := entry.wmeta
		fallback := entry.Response
		rcode := entry.rcode
		cloudResponse := entry.CloudResponse
		expireAt := entry.ExpireAt
		shard.mu.RUnlock()

		// 命中路径只取一次当前时间，LastAccess 用原子写，不再抢分片写锁
		now := time.Now()
		entry.touchAt(now)

		if now.After(expireAt) {
			// 已缓存的负响应（NXDOMAIN）过期后不再返回陈旧值，直接删除并按未命中回源
			if !isCloud && rcode != dns.RcodeSuccess {
				shard.mu.Lock()
				delete(shard.store, key)
				shard.mu.Unlock()
				return nil, false, false, 0
			}
			// 超出过期宽限：删除条目并按未命中处理，由本次请求同步回源刷新（不做后台刷新）
			if grace := c.staleGrace(); grace <= 0 || now.After(expireAt.Add(grace)) {
				shard.mu.Lock()
				delete(shard.store, key)
				shard.mu.Unlock()
				return nil, false, false, 0
			}
			// 宽限内：返回旧响应（TTL 压小），交由客户端稍后重查时同步回源
			if isCloud && cloudResponse != nil {
				resp := cloudResponse.Copy()
				c.adjustExpiredResponseTTL(resp, 5*time.Second)
				return resp, true, true, cloudType
			} else if !isCloud {
				if resp := materialize(wire, meta, fallback); resp != nil {
					c.adjustExpiredResponseTTL(resp, 5*time.Second)
					return resp, true, false, 0
				}
			}
			return nil, true, isCloud, cloudType
		}

		// 命中统一返回副本并按缓存时长递减TTL，避免共享对象竞争（调用方无需再Copy）
		if isCloud {
			if cloudResponse != nil {
				resp := cloudResponse.Copy()
				decrementTTLs(resp, now.Sub(storedAt))
				return resp, true, true, cloudType
			}
			return nil, true, true, cloudType
		}

		resp := materialize(wire, meta, fallback)
		if resp == nil {
			return nil, false, false, 0
		}
		decrementTTLs(resp, now.Sub(storedAt))
		return resp, true, false, 0
	}
	shard.mu.RUnlock()

	return nil, false, false, 0
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Size           int                  `json:"size"`
	MaxSize        int                  `json:"max_size"`
	HitCount       int64                `json:"hit_count"`
	MissCount      int64                `json:"miss_count"`
	Entries        map[string]EntryInfo `json:"entries,omitempty"`
	HotEntries     []HotEntry           `json:"hot_entries,omitempty"`
	ExpiredEntries []string             `json:"expired_entries,omitempty"`
	ValidEntries   int                  `json:"valid_entries"`
	ExpiredCount   int                  `json:"expired_count"`
	IPCounts       map[string]int       `json:"ip_counts,omitempty"`
}

// EntryInfo 单个缓存条目信息
type EntryInfo struct {
	Domain      string    `json:"domain"`
	QType       string    `json:"qtype"`
	IsExpired   bool      `json:"is_expired"`
	IsCloud     bool      `json:"is_cloud"`
	ExpireAt    time.Time `json:"expire_at"`
	LastAccess  time.Time `json:"last_access"`
	AnswerCount int       `json:"answer_count"`
}

// HotEntry 热点条目
type HotEntry struct {
	Domain      string    `json:"domain"`
	QType       string    `json:"qtype"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int       `json:"access_count"`
}

// GetWithFlight 获取缓存响应，使用单飞行模式避免重复查询
func (c *OptimizedDNSCache) GetWithFlight(scope, domain string, qType uint16) (*dns.Msg, bool, bool, int) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	if exists {
		// StoredAt/IsCloud/CloudResponse 等字段写入后不再变更，可在读锁内安全取出
		storedAt := entry.StoredAt
		isCloud := entry.IsCloud
		cloudType := entry.CloudType
		wire := entry.wire
		meta := entry.wmeta
		fallback := entry.Response
		rcode := entry.rcode
		cloudResponse := entry.CloudResponse
		expireAt := entry.ExpireAt
		shard.mu.RUnlock()

		// 命中路径只取一次当前时间，LastAccess 用原子写，不再抢分片写锁
		now := time.Now()
		entry.touchAt(now)

		if now.After(expireAt) {
			// 已缓存的负响应（NXDOMAIN）过期后不再返回陈旧值，直接删除并按未命中回源
			if !isCloud && rcode != dns.RcodeSuccess {
				shard.mu.Lock()
				delete(shard.store, key)
				shard.mu.Unlock()
				return nil, false, false, 0
			}
			// 超出过期宽限：删除条目并按未命中处理，由本次请求同步回源刷新（不做后台刷新）
			if grace := c.staleGrace(); grace <= 0 || now.After(expireAt.Add(grace)) {
				shard.mu.Lock()
				delete(shard.store, key)
				shard.mu.Unlock()
				return nil, false, false, 0
			}
			// 宽限内：返回旧响应（TTL 压小），不再触发任何后台刷新
			if isCloud && cloudResponse != nil {
				resp := cloudResponse.Copy()
				c.adjustExpiredResponseTTL(resp, 5*time.Second)
				return resp, true, true, cloudType
			} else if !isCloud {
				if resp := materialize(wire, meta, fallback); resp != nil {
					c.adjustExpiredResponseTTL(resp, 5*time.Second)
					return resp, true, false, 0
				}
			}
			return nil, true, isCloud, cloudType
		}

		// 命中统一返回副本并按缓存时长递减TTL，避免共享对象竞争（调用方无需再Copy）
		if isCloud {
			if cloudResponse != nil {
				resp := cloudResponse.Copy()
				decrementTTLs(resp, now.Sub(storedAt))
				return resp, true, true, cloudType
			}
			return nil, true, true, cloudType
		}

		resp := materialize(wire, meta, fallback)
		if resp == nil {
			return nil, false, false, 0
		}
		decrementTTLs(resp, now.Sub(storedAt))
		return resp, true, false, 0
	}
	shard.mu.RUnlock()

	return nil, false, false, 0
}

// adjustExpiredResponseTTL 调整过期响应的TTL值
// 仅调整Answer段：Ns/Extra段可能包含OPT等记录，其TTL字段并非生存时间
func (c *OptimizedDNSCache) adjustExpiredResponseTTL(resp *dns.Msg, newTTL time.Duration) {
	if resp == nil {
		return
	}

	newTTLValue := uint32(newTTL.Seconds())
	for _, rr := range resp.Answer {
		rr.Header().Ttl = newTTLValue
	}
}

// GetExpireTime 获取缓存条目的过期时间
func (c *OptimizedDNSCache) GetExpireTime(scope, domain string, qType uint16) time.Time {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.store[key]
	if !exists {
		return time.Time{} // 返回零时间
	}

	return entry.ExpireAt
}

// IsCloud 检查域名是否为云服务域名（即使缓存已过期）
func (c *OptimizedDNSCache) IsCloud(scope, domain string, qType uint16) bool {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return false
	}

	return entry.IsCloud
}

// Set 设置缓存响应
// 注意：云服务的查询结果只缓存标记，不缓存响应内容
func (c *OptimizedDNSCache) Set(scope, domain string, qType uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		shard.mu.Lock()
		defer shard.mu.Unlock()

		// 检查是否需要清理缓存
		if len(shard.store) >= c.maxSize/c.shardCount {
			c.evictLeastRecentlyUsed(shard)
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := shard.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 从对象池获取CacheEntry
		entry := c.entryPool.Get()
		// 只存储云服务标记，不存储原始响应内容
		entry.Response = nil                            // 不缓存原始响应内容
		entry.CloudResponse = existingCloudResponse     // 保留已有的云响应或为空
		entry.ExpireAt = time.Now().Add(24 * time.Hour) // 云服务标记缓存24小时
		entry.StoredAt = time.Now()
		entry.IsCloud = true
		entry.CloudType = cType
		entry.RefreshThreshold = 6 * time.Hour // 云标记外6小时后刷新
		entry.touch()

		// 存储缓存条目
		shard.store[key] = entry
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 计算实际TTL：遵循上游响应中的最小TTL，绝不抬高；无有效TTL时用默认TTL兜底
	actualTTL := c.defTTL()
	if responseCopy != nil && len(responseCopy.Answer) > 0 {
		// 从响应中获取最小的TTL
		var minTTL uint32 = 0
		for _, rr := range responseCopy.Answer {
			if rr.Header().Ttl > 0 {
				if minTTL == 0 || rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
		}

		// 如果有有效的TTL，直接使用上游TTL
		if minTTL > 0 {
			actualTTL = time.Duration(minTTL) * time.Second
		}
	}

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.CloudResponse = nil
	// 预打包响应字节：命中时原地打补丁写出，省掉每次命中的 dns.Msg 深拷贝
	entry.storeWire(responseCopy)
	entry.ExpireAt = expireAt
	entry.StoredAt = time.Now()
	entry.IsCloud = isCloud
	entry.CloudType = 0
	entry.RefreshThreshold = refreshThreshold
	entry.touch()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(shard.store) >= c.maxSize/c.shardCount && c.maxSize > 0 {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储缓存条目
	shard.store[key] = entry
}

// SetWithTTL 设置缓存响应（使用自定义TTL）
func (c *OptimizedDNSCache) SetWithTTL(scope, domain string, qType uint16, response *dns.Msg, isCloud bool, customTTL time.Duration, cloudType ...int) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		shard.mu.Lock()
		defer shard.mu.Unlock()

		// 检查是否需要清理缓存
		if len(shard.store) >= c.maxSize/c.shardCount {
			c.evictLeastRecentlyUsed(shard)
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := shard.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 从对象池获取CacheEntry
		entry := c.entryPool.Get()
		// 只存储云服务标记，不存储原始响应内容
		entry.Response = nil                            // 不缓存原始响应内容
		entry.CloudResponse = existingCloudResponse     // 保留已有的云响应或为空
		entry.ExpireAt = time.Now().Add(24 * time.Hour) // 云服务标记缓存24小时
		entry.StoredAt = time.Now()
		entry.IsCloud = true
		entry.CloudType = cType
		entry.RefreshThreshold = 6 * time.Hour // 云标记外6小时后刷新
		entry.touch()

		// 存储缓存条目
		shard.store[key] = entry
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 使用调用方给定的TTL（如负缓存TTL），绝不抬高
	actualTTL := customTTL

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.CloudResponse = nil
	// 预打包响应字节：命中时原地打补丁写出，省掉每次命中的 dns.Msg 深拷贝
	entry.storeWire(responseCopy)
	entry.ExpireAt = expireAt
	entry.StoredAt = time.Now()
	entry.IsCloud = isCloud
	entry.CloudType = 0
	entry.RefreshThreshold = refreshThreshold
	entry.touch()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(shard.store) >= c.maxSize/c.shardCount && c.maxSize > 0 {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储缓存条目
	shard.store[key] = entry
}

// ShouldRefreshWithThreshold 检查是否应该刷新缓存（使用指定的刷新阈值）
func (c *OptimizedDNSCache) ShouldRefreshWithThreshold(scope, domain string, qType uint16, refreshThreshold time.Duration) bool {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return false
	}

	// 计算剩余TTL
	remainingTTL := time.Until(entry.ExpireAt)

	// 如果已经过期或即将过期，不需要刷新
	if remainingTTL <= 0 {
		return false
	}

	// 使用传入的刷新阈值
	shouldRefresh := remainingTTL <= refreshThreshold

	return shouldRefresh
}

// ShouldRefresh 检查是否应该刷新缓存（TTL剩余时间低于刷新阈值）
func (c *OptimizedDNSCache) ShouldRefresh(scope, domain string, qType uint16) bool {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return false
	}

	// 计算剩余TTL
	remainingTTL := time.Until(entry.ExpireAt)

	// 如果已经过期或即将过期，不需要刷新
	if remainingTTL <= 0 {
		return false
	}

	// 使用自定义刷新阈值或动态计算
	var refreshThreshold time.Duration
	if entry.RefreshThreshold > 0 {
		// 使用设置的刷新阈值
		refreshThreshold = entry.RefreshThreshold
	} else {
		// 动态计算：使用条目总生存时间的30%作为刷新阈值
		totalTTL := time.Since(entry.lastAccessTime().Add(-c.defTTL())) // 计算条目的总生存时间
		if totalTTL > 0 {
			refreshThreshold = time.Duration(float64(totalTTL) * 0.3)
		} else {
			// 备用方案：使用默认TTL的30%
			refreshThreshold = time.Duration(float64(c.defTTL()) * 0.3)
		}
	}

	// 设置最小刷新间隔，避免过于频繁的刷新
	minRefreshInterval := 30 * time.Second
	if refreshThreshold < minRefreshInterval {
		refreshThreshold = minRefreshInterval
	}

	// 如果剩余TTL小于刷新阈值，则需要刷新
	shouldRefresh := remainingTTL <= refreshThreshold

	return shouldRefresh
}

// asyncRefresh 异步刷新缓存（由外部调用）
func (c *OptimizedDNSCache) asyncRefresh(domain string, qType uint16, refreshFn func(string, uint16) (*dns.Msg, error)) {
	// 这个方法由外部的异步刷新机制调用，这里只提供一个接口
}

// evictLeastRecentlyUsed 淘汰最少使用的条目
func (c *OptimizedDNSCache) evictLeastRecentlyUsed(shard *CacheShard) {
	if len(shard.store) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// 找到最久未访问的条目
	for key, entry := range shard.store {
		la := entry.lastAccessTime()
		if oldestKey == "" || la.Before(oldestTime) {
			oldestKey = key
			oldestTime = la
		}
	}

	// 删除最久未访问的条目
	if oldestKey != "" {
		// 先获取条目，然后删除，最后放回对象池
		entry := shard.store[oldestKey]
		delete(shard.store, oldestKey)
		// 将条目放回对象池
		c.entryPool.Put(entry)
	}
}

// Lock 实现互斥锁接口（空实现，因为我们使用分片锁）
func (c *OptimizedDNSCache) Lock() {
	// 由于使用了分片锁，这里不需要全局锁
}

// Unlock 实现互斥锁接口（空实现，因为我们使用分片锁）
func (c *OptimizedDNSCache) Unlock() {
	// 由于使用了分片锁，这里不需要全局锁
}

// CleanupExpired 清理过期条目
func (c *OptimizedDNSCache) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// 遍历所有分片
		for _, shard := range c.shards {
			shard.mu.Lock()
			for k, v := range shard.store {
				if time.Now().After(v.ExpireAt) {
					// 删除过期条目并放回对象池
					delete(shard.store, k)
					c.entryPool.Put(v)
				}
			}
			shard.mu.Unlock()
		}
	}
}

// Clear 清空缓存
func (c *OptimizedDNSCache) Clear() {
	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.Lock()
		// 清空缓存并将所有条目放回对象池
		for _, entry := range shard.store {
			c.entryPool.Put(entry)
		}
		shard.store = make(map[string]*CacheEntry)
		shard.mu.Unlock()
	}
}

// Delete 删除指定的缓存条目
func (c *OptimizedDNSCache) Delete(scope, domain string, qType uint16) {
	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.Lock()
	if entry, exists := shard.store[key]; exists {
		delete(shard.store, key)
		// 将删除的条目放回对象池
		c.entryPool.Put(entry)
	}
	shard.mu.Unlock()
}

// GetExpiringSoonEntries 获取即将过期的缓存条目列表
func (c *OptimizedDNSCache) GetExpiringSoonEntries(refreshThreshold time.Duration) []CacheEntryInfo {
	var expiringSoon []CacheEntryInfo
	now := time.Now()

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
			// 计算剩余TTL
			remainingTTL := entry.ExpireAt.Sub(now)

			// 如果剩余TTL小于或等于刷新阈值，则添加到列表
			if remainingTTL > 0 && remainingTTL <= refreshThreshold {
				// 解析缓存键获取domain和qtype（新格式 scope|domain|qtype）
				parts := strings.Split(key, "|")
				if len(parts) == 3 {
					domain := parts[1]
					qtypeStr := parts[2]

					// 将qtype字符串转换为uint16
					for qtype, qtypeString := range dns.TypeToString {
						if qtypeString == qtypeStr {
							expiringSoon = append(expiringSoon, CacheEntryInfo{
								Domain:  domain,
								QType:   qtype,
								IsCloud: entry.IsCloud,
							})
							break
						}
					}
				}
			}
		}
		shard.mu.RUnlock()
	}

	return expiringSoon
}

// ExtendTTL 延长缓存条目的过期时间
func (c *OptimizedDNSCache) ExtendTTL(scope, domain string, qType uint16, duration time.Duration) {
	// 添加空指针检查
	if c == nil {
		return
	}

	key := c.key(scope, domain, qType)
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, exists := shard.store[key]; exists {
		// 检查当前剩余TTL
		remainingTTL := time.Until(entry.ExpireAt)

		// 如果当前剩余TTL已经大于要延长的时间，则不进行延长
		// 这样可以避免频繁刷新导致的过度延长
		if remainingTTL > duration {
			return
		}

		// 延长过期时间，但不超过配置的最大TTL
		newTTL := duration
		if newTTL > c.defTTL()*2 { // 最多延长到默认TTL的2倍
			newTTL = c.defTTL() * 2
		}

		entry.ExpireAt = time.Now().Add(newTTL)
		// 更新最后访问时间
		entry.touch()
	}
}

// DebugCache 输出缓存内容用于调试
func (c *OptimizedDNSCache) DebugCache() {
	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for _, _ = range shard.store {
			// 仅作为调试接口，实际应用中可能需要记录缓存内容
		}
		shard.mu.RUnlock()
	}
}

// GetStats 获取缓存统计信息
func (c *OptimizedDNSCache) GetStats(includeEntries bool) *CacheStats {
	stats := &CacheStats{
		Size:    0,
		MaxSize: c.maxSize,
		Entries: make(map[string]EntryInfo),
	}

	currentTime := time.Now()
	validEntries := 0
	expiredEntries := []string{}

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
			stats.Size++
			isExpired := currentTime.After(entry.ExpireAt)
			if isExpired {
				expiredEntries = append(expiredEntries, key)
			} else {
				validEntries++
			}

			// 解析域名和查询类型（scope|domain|qtype）
			parts := strings.Split(key, "|")
			domain := "unknown"
			qtype := "unknown"
			if len(parts) >= 3 {
				domain = parts[1]
				qtype = parts[2]
			}

			answerCount := entry.answerCount
			if entry.IsCloud && entry.CloudResponse != nil {
				answerCount = len(entry.CloudResponse.Answer)
			}

			if includeEntries {
				stats.Entries[key] = EntryInfo{
					Domain:      domain,
					QType:       qtype,
					IsExpired:   isExpired,
					IsCloud:     entry.IsCloud,
					ExpireAt:    entry.ExpireAt,
					LastAccess:  entry.lastAccessTime(),
					AnswerCount: answerCount,
				}
			}
		}
		shard.mu.RUnlock()
	}

	stats.ValidEntries = validEntries
	stats.ExpiredCount = len(expiredEntries)
	stats.ExpiredEntries = expiredEntries

	// 如果不需要详细条目信息，则清空Entries字段
	if !includeEntries {
		stats.Entries = nil
	}

	return stats
}

// GetHotEntries 获取热点条目（最近访问的条目）
func (c *OptimizedDNSCache) GetHotEntries(limit int) []HotEntry {
	// 创建临时切片存储所有条目及其访问信息
	allEntries := make([]struct {
		Key        string
		Entry      *CacheEntry
		LastAccess time.Time
	}, 0, c.maxSize)

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
			allEntries = append(allEntries, struct {
				Key        string
				Entry      *CacheEntry
				LastAccess time.Time
			}{key, entry, entry.lastAccessTime()})
		}
		shard.mu.RUnlock()
	}

	// 按最后访问时间排序（最新的在前）
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].LastAccess.After(allEntries[j].LastAccess)
	})

	// 获取前N个热点条目
	hotEntries := make([]HotEntry, 0, limit)
	count := 0
	for _, item := range allEntries {
		if count >= limit {
			break
		}

		parts := strings.Split(item.Key, "|")
		domain := "unknown"
		qtype := "unknown"
		if len(parts) >= 3 {
			domain = parts[1]
			qtype = parts[2]
		}

		hotEntries = append(hotEntries, HotEntry{
			Domain:     domain,
			QType:      qtype,
			LastAccess: item.LastAccess,
		})
		count++
	}

	return hotEntries
}

// CountCachedIPs 统计缓存中的IP数量
func (c *OptimizedDNSCache) CountCachedIPs() map[string]int {
	ipCounts := make(map[string]int)
	currentTime := time.Now()

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for _, entry := range shard.store {
			// 检查条目是否已过期
			if currentTime.After(entry.ExpireAt) {
				continue // 跳过已过期的条目
			}

			// 检查响应中的IP记录
			if entry.IsCloud {
				if entry.CloudResponse != nil {
					for _, rr := range entry.CloudResponse.Answer {
						switch rr.(type) {
						case *dns.A:
							ipCounts["A"]++
						case *dns.AAAA:
							ipCounts["AAAA"]++
						}
					}
				}
				continue
			}

			// 普通条目用写入时预计算的 A/AAAA 计数，避免逐条从 wire 反解
			if entry.ipv4Count > 0 {
				ipCounts["A"] += entry.ipv4Count
			}
			if entry.ipv6Count > 0 {
				ipCounts["AAAA"] += entry.ipv6Count
			}
		}
		shard.mu.RUnlock()
	}

	return ipCounts
}
