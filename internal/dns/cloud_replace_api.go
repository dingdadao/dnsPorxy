package dns

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsPorxy/internal/utils"
)

const (
	// replaceAPIFetchTimeout 取接口的超时，避免查询路径被 HTTP 拖慢
	replaceAPIFetchTimeout = 5 * time.Second
	// replaceAPIRecordTTL 接口来源 A 记录的 TTL（秒）：接口没有上游 TTL 可循，
	// 取短 TTL 让客户端更快拿到刷新后的优选 IP
	replaceAPIRecordTTL = 60
	// replaceAPIMaxBody 接口响应最大读取字节数，防止异常响应撑爆内存
	replaceAPIMaxBody = 1 << 20
)

// ReplaceAPIClient 从 HTTP 接口获取云替换优选 IP（如 https://cf.niao.fun/api/results?select=cm）
// 结果按 ttl 缓存：命中缓存直接返回；缓存过期时先返回旧值并异步刷新（提前预取），
// 让 DNS 查询路径不因接口抖动而变慢；完全没有缓存时才同步取一次。
type ReplaceAPIClient struct {
	url    string
	count  int
	ttl    time.Duration
	logger *utils.EnhancedLogger
	client *http.Client

	mu        sync.RWMutex
	ips       []netip.Addr
	fetchedAt time.Time

	refreshing atomic.Bool // 后台刷新单飞标志，避免并发重复取接口
}

// NewReplaceAPIClient 创建接口客户端（count<=0 时按 1 处理）
func NewReplaceAPIClient(url string, count int, ttl time.Duration, logger *utils.EnhancedLogger) *ReplaceAPIClient {
	if count <= 0 {
		count = 1
	}
	return &ReplaceAPIClient{
		url:    url,
		count:  count,
		ttl:    ttl,
		logger: logger,
		client: &http.Client{Timeout: replaceAPIFetchTimeout},
	}
}

// IPs 返回接口给出的替换 IP：有缓存立即返回；缓存过期则返回旧值并后台刷新；无缓存才同步取
func (c *ReplaceAPIClient) IPs() ([]netip.Addr, error) {
	c.mu.RLock()
	ips, fetchedAt := c.ips, c.fetchedAt
	c.mu.RUnlock()

	if len(ips) > 0 {
		if c.ttl <= 0 || time.Since(fetchedAt) >= c.ttl {
			c.Prefetch() // 提前预取：旧值先用着，后台换新的
		}
		return ips, nil
	}

	return c.fetch()
}

// Prefetch 后台刷新缓存（单飞去重，已有刷新在跑时直接返回）
func (c *ReplaceAPIClient) Prefetch() {
	if !c.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.refreshing.Store(false)
		if _, err := c.fetch(); err != nil {
			c.logger.Warn("⚠️ 替换接口预取失败", map[string]interface{}{
				"url":   c.url,
				"error": err.Error(),
			})
		}
	}()
}

// fetch 同步请求接口并刷新缓存；失败时保留旧值并返回错误
func (c *ReplaceAPIClient) fetch() ([]netip.Addr, error) {
	ips, err := c.request()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.ips = ips
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	c.logger.Info("🌐 [替换接口已刷新] ", map[string]interface{}{
		"rule":       "REPLACE_API_REFRESHED",
		"url":        c.url,
		"ip_count":   len(ips),
		"cache_time": c.ttl.String(),
	})
	return ips, nil
}

// request 发起一次 HTTP GET 并解析出前 count 个 IPv4
func (c *ReplaceAPIClient) request() ([]netip.Addr, error) {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return nil, fmt.Errorf("接口请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("接口返回状态码 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, replaceAPIMaxBody))
	if err != nil {
		return nil, fmt.Errorf("接口响应读取失败: %w", err)
	}

	ips := parseReplaceAPIIPs(string(body), c.count)
	if len(ips) == 0 {
		return nil, fmt.Errorf("接口响应中未解析到 IPv4 地址")
	}
	return ips, nil
}

// parseReplaceAPIIPs 解析接口文本，每行形如 "104.24.64.153:443#联通CF_LAX 184.45ms 14.78MB/s"：
// 取首个字段中 "#" 之前、去掉 ":端口" 的 IPv4，按出现顺序去重，最多返回 limit 个（limit<=0 视为 1）
func parseReplaceAPIIPs(body string, limit int) []netip.Addr {
	if limit <= 0 {
		limit = 1
	}
	var out []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		host := fields[0]
		if i := strings.IndexByte(host, '#'); i >= 0 {
			host = host[:i]
		}
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is4() || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
		if len(out) >= limit {
			break
		}
	}
	return out
}
