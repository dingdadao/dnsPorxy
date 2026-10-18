package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ConfigJSON 配置的 JSON 表示（web API 与 SQLite 存储共用）
// 时长字段统一使用 "1.5s"、"5m"、"24h" 格式的字符串，便于阅读与编辑
type ConfigJSON struct {
	ListenPort            int             `json:"listen_port"`
	WebAddr               string          `json:"web_addr"`
	WebTLSAddr            string          `json:"web_tls_addr"`
	Upstream              []string        `json:"upstream"`
	Timeout               string          `json:"timeout"`
	ModernTimeout         string          `json:"modern_timeout"`
	ReplaceCacheTime      string          `json:"replace_cache_time"`
	MaxIPRecords          int             `json:"max_ip_records"`
	CNAMERecursionDepth   int             `json:"cname_recursion_depth"`
	ReplaceCFDomain       string          `json:"replace_cf_domain"`
	ReplaceAWSDomain      string          `json:"replace_aws_domain"`
	ReplaceCFAPI          string          `json:"replace_cf_api"`
	ReplaceAPICount       int             `json:"replace_api_count"`
	BackupDNS             string          `json:"backup_dns"`
	DNSMode               string          `json:"dns_mode"`
	IPPrefer              string          `json:"ip_prefer"`
	SplitLists            []SplitListJSON `json:"split_lists"`
	CloudflareNetFile     string          `json:"cloudflare_net_file"`
	CloudflareNetFile6    string          `json:"cloudflare_net_file6"`
	AWSNetFile            string          `json:"aws_net_file"`
	NetworkRefresh        string          `json:"network_refresh"`
	LogLevel              string          `json:"log_level"`
	LogFormat             string          `json:"log_format"`
	Cache                 CacheJSON       `json:"cache"`
	QueryLog              QueryLogJSON    `json:"query_log"`
	EnableCloudflareCheck bool            `json:"enable_cloudflare_check"`
	EnableAWSCheck        bool            `json:"enable_aws_check"`

	EnableDot         bool              `json:"enable_dot"`
	DotAddr           string            `json:"dot_addr"`
	EnableDoh         bool              `json:"enable_doh"`
	DohAddr           string            `json:"doh_addr"`
	DohPath           string            `json:"doh_path"`
	EnableDoh3        bool              `json:"enable_doh3"`
	Doh3Addr          string            `json:"doh3_addr"`
	DohAltSvc         string            `json:"doh_alt_svc"`
	Doh3QuicMaxIdle   string            `json:"doh3_quic_max_idle"`
	Doh3QuicKeepalive string            `json:"doh3_quic_keepalive"`
	Doh3Allow0Rtt     bool              `json:"doh3_allow_0rtt"`
	CertStoreDir      string            `json:"cert_store_dir"`
	CertDefault       string            `json:"cert_default"`
	WebTLS            bool              `json:"web_tls"`
	WebhookToken      string            `json:"webhook_token"`
	TrustedProxies    stringOrList      `json:"trusted_proxies"`
	ClientIPSources   stringOrList      `json:"client_ip_sources"`
	ClientIPHeaders   stringOrList      `json:"client_ip_headers"`
	ClientIPStatic    map[string]string `json:"client_ip_static,omitempty"`
	ISPGroups         []ISPGroupJSON    `json:"isp_groups"`
	CustomGroups      []CustomGroupJSON `json:"custom_groups"`
	AllowACLs         stringOrList      `json:"allow_acls"`
	SourceEnabled     bool              `json:"source_enabled"`
	SourceDBDir       string            `json:"source_db_dir"`
	SourceBaseURL     string            `json:"source_base_url"`
	SourceUpdateHours int               `json:"source_update_hours"`

	// 以下为旧版（两组硬编码分流列表）字段，仅用于导入兼容。
	// 读取时若 split_lists 为空则据此合成迁移；写入时不再输出。
	LegacyDefaultDNS             string `json:"default_dns,omitempty"`
	LegacyChinaDNS               string `json:"china_dns,omitempty"`
	LegacyDesignatedDomain       string `json:"designated_domain,omitempty"`
	LegacyDesignatedDomainURL    string `json:"designated_domain_url,omitempty"`
	LegacyDesignatedRefresh      string `json:"designated_refresh,omitempty"`
	LegacyChinaDomainFile        string `json:"china_domain_file,omitempty"`
	LegacyChinaDomainFileURL     string `json:"china_domain_file_url,omitempty"`
	LegacyChinaDomainRefresh     string `json:"china_domain_refresh,omitempty"`
	LegacyEnableChinaDomainCheck bool   `json:"enable_china_domain_check,omitempty"`

	// 旧版客户端分组（自由命名 + IP/CIDR + 取反），仅用于导入迁移，写入时不再输出
	LegacyClientGroups []legacyClientGroupJSON `json:"client_groups,omitempty"`
}

// stringOrList 兼容 dns 字段的历史写法（单个字符串）与列表写法（字符串数组）
type stringOrList []string

func (s *stringOrList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = oneOrNil(one)
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// oneOrNil 单值转单元素数组，空串返回 nil
func oneOrNil(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// SplitListJSON 域名分流列表的 JSON 表示
type SplitListJSON struct {
	Name             string        `json:"name"`
	Enabled          bool          `json:"enabled"`
	Invert           bool          `json:"invert"`
	DNS              stringOrList  `json:"dns"`
	DNSMode          string        `json:"dns_mode"`
	DomainFile       string        `json:"domain_file"`
	DomainURL        string        `json:"domain_url"`
	Refresh          string        `json:"refresh"`
	EnableCloudCheck bool          `json:"enable_cloud_check"`
	ECS              ECSPolicyJSON `json:"ecs"`
	IPPrefer         string        `json:"ip_prefer"`
}

// CloudReplacePolicyJSON 分组云替换线路策略的 JSON 表示
// override 为 false 时本组完全跟随全局（cf_domain/aws_domain/cf_api 忽略）
type CloudReplacePolicyJSON struct {
	Override  bool   `json:"override"`
	CFDomain  string `json:"cf_domain"`
	AWSDomain string `json:"aws_domain"`
	CFAPI     string `json:"cf_api"`
	APICount  int    `json:"api_count"`
}

// ISPGroupJSON 运营商固定分组的 JSON 表示
type ISPGroupJSON struct {
	ISP          string                 `json:"isp"`
	Enabled      bool                   `json:"enabled"`
	SplitRefs    stringOrList           `json:"split_refs"`
	FallbackDNS  stringOrList           `json:"fallback_dns"`
	DNSMode      string                 `json:"dns_mode"`
	IPPrefer     string                 `json:"ip_prefer"`
	ECS          ECSPolicyJSON          `json:"ecs"`
	CloudReplace CloudReplacePolicyJSON `json:"cloud_replace"`

	// 以下为旧版字段，仅用于导入迁移（旧 dns → fallback_dns；旧 split_refs 直接沿用）。
	// 写回时不再输出。
	LegacyDNS stringOrList `json:"dns,omitempty"`
}

// CustomGroupJSON 自定义分组的 JSON 表示
type CustomGroupJSON struct {
	Name         string                 `json:"name"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority"`
	Match        stringOrList           `json:"match"`
	SplitRefs    stringOrList           `json:"split_refs"`
	FallbackDNS  stringOrList           `json:"fallback_dns"`
	DNSMode      string                 `json:"dns_mode"`
	IPPrefer     string                 `json:"ip_prefer"`
	ECS          ECSPolicyJSON          `json:"ecs"`
	CloudReplace CloudReplacePolicyJSON `json:"cloud_replace"`

	LegacyDNS stringOrList `json:"dns,omitempty"`
}

// cloudReplacePolicyToJSON 内存策略转 JSON 表示
func cloudReplacePolicyToJSON(p CloudReplacePolicy) CloudReplacePolicyJSON {
	return CloudReplacePolicyJSON{
		Override:  p.Override,
		CFDomain:  p.CFDomain,
		AWSDomain: p.AWSDomain,
		CFAPI:     p.CFAPI,
		APICount:  p.APICount,
	}
}

// cloudReplacePolicyFromJSON JSON 表示转内存策略（归一化交由 ValidateConfig 统一处理）
func cloudReplacePolicyFromJSON(p CloudReplacePolicyJSON) CloudReplacePolicy {
	return CloudReplacePolicy{
		Override:  p.Override,
		CFDomain:  p.CFDomain,
		AWSDomain: p.AWSDomain,
		CFAPI:     p.CFAPI,
		APICount:  p.APICount,
	}
}

// legacyClientGroupJSON 旧版客户端分组的 JSON 表示，仅用于导入迁移，写入时不再输出
type legacyClientGroupJSON struct {
	Name             string        `json:"name"`
	Enabled          bool          `json:"enabled"`
	Priority         int           `json:"priority"`
	Match            stringOrList  `json:"match"`
	Invert           bool          `json:"invert"`
	DNS              stringOrList  `json:"dns"`
	DNSMode          string        `json:"dns_mode"`
	ECS              ECSPolicyJSON `json:"ecs"`
	EnableCloudCheck bool          `json:"enable_cloud_check"`
	IPPrefer         string        `json:"ip_prefer"`
	AllowDomainSplit bool          `json:"allow_domain_split"`
}

// ECSPolicyJSON ECS 策略的 JSON 表示（缺字段时为零值＝关闭，老配置不受影响）
type ECSPolicyJSON struct {
	Enabled bool   `json:"enabled"`
	ISPType string `json:"isp_type"`
	Subnet  string `json:"subnet"`
}

// CacheJSON 缓存配置的 JSON 表示
type CacheJSON struct {
	MaxItems        int    `json:"max_items"`
	TTL             string `json:"ttl"`
	StaleTTL        string `json:"stale_ttl"`
	MaxAsyncWorkers int    `json:"max_async_workers"`
}

// QueryLogJSON 解析日志配置的 JSON 表示（缺字段时按默认策略启用，老配置不受影响）
type QueryLogJSON struct {
	Enabled   bool   `json:"enabled"`
	Retention string `json:"retention"`
	MaxRows   int    `json:"max_rows"`
}

// ToJSON 将内存配置转换为 JSON 表示
func (c *Config) ToJSON() *ConfigJSON {
	lists := make([]SplitListJSON, 0, len(c.SplitLists))
	for _, l := range c.SplitLists {
		lists = append(lists, SplitListJSON{
			Name:             l.Name,
			Enabled:          l.Enabled,
			Invert:           l.Invert,
			DNS:              stringOrList(l.DNS),
			DNSMode:          l.DNSMode,
			DomainFile:       l.DomainFile,
			DomainURL:        l.DomainURL,
			Refresh:          l.Refresh.String(),
			EnableCloudCheck: l.EnableCloudCheck,
			ECS: ECSPolicyJSON{
				Enabled: l.ECS.Enabled,
				ISPType: l.ECS.ISPType,
				Subnet:  l.ECS.Subnet,
			},
			IPPrefer: l.IPPrefer,
		})
	}

	ispGroups := make([]ISPGroupJSON, 0, len(c.ISPGroups))
	for _, g := range c.ISPGroups {
		ispGroups = append(ispGroups, ISPGroupJSON{
			ISP:         string(g.ISP),
			Enabled:     g.Enabled,
			SplitRefs:   stringOrList(g.SplitRefs),
			FallbackDNS: stringOrList(g.FallbackDNS),
			DNSMode:     g.DNSMode,
			IPPrefer:    g.IPPrefer,
			ECS: ECSPolicyJSON{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			CloudReplace: cloudReplacePolicyToJSON(g.CloudReplace),
		})
	}

	customGroups := make([]CustomGroupJSON, 0, len(c.CustomGroups))
	for _, g := range c.CustomGroups {
		customGroups = append(customGroups, CustomGroupJSON{
			Name:        g.Name,
			Enabled:     g.Enabled,
			Priority:    g.Priority,
			Match:       stringOrList(g.Match),
			SplitRefs:   stringOrList(g.SplitRefs),
			FallbackDNS: stringOrList(g.FallbackDNS),
			DNSMode:     g.DNSMode,
			IPPrefer:    g.IPPrefer,
			ECS: ECSPolicyJSON{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			CloudReplace: cloudReplacePolicyToJSON(g.CloudReplace),
		})
	}

	return &ConfigJSON{
		ListenPort:          c.ListenPort,
		WebAddr:             c.WebAddr,
		WebTLSAddr:          c.WebTLSAddr,
		Upstream:            c.Upstream,
		Timeout:             c.Timeout.String(),
		ModernTimeout:       c.ModernTimeout.String(),
		ReplaceCacheTime:    c.ReplaceCacheTime.String(),
		MaxIPRecords:        c.MaxIPRecords,
		CNAMERecursionDepth: c.CNAMERecursionDepth,
		ReplaceCFDomain:     c.ReplaceCFDomain,
		ReplaceAWSDomain:    c.ReplaceAWSDomain,
		ReplaceCFAPI:        c.ReplaceCFAPI,
		ReplaceAPICount:     c.ReplaceAPICount,
		BackupDNS:           c.BackupDNS,
		DNSMode:             c.DNSMode,
		IPPrefer:            c.IPPrefer,
		SplitLists:          lists,
		CloudflareNetFile:   c.CloudflareNetFile,
		CloudflareNetFile6:  c.CloudflareNetFile6,
		AWSNetFile:          c.AWSNetFile,
		NetworkRefresh:      c.NetworkRefreshInterval.String(),
		LogLevel:            c.LogLevel,
		LogFormat:           c.LogFormat,
		Cache: CacheJSON{
			MaxItems:        c.Cache.MaxItems,
			TTL:             c.Cache.TTL.String(),
			StaleTTL:        c.Cache.StaleTTL.String(),
			MaxAsyncWorkers: c.Cache.MaxAsyncWorkers,
		},
		QueryLog: QueryLogJSON{
			Enabled:   c.QueryLog.Enabled,
			Retention: c.QueryLog.Retention.String(),
			MaxRows:   c.QueryLog.MaxRows,
		},
		EnableCloudflareCheck: c.EnableCloudflareCheck,
		EnableAWSCheck:        c.EnableAWSCheck,

		EnableDot:         c.EnableDoT,
		DotAddr:           c.DoTAddr,
		EnableDoh:         c.EnableDoH,
		DohAddr:           c.DoHAddr,
		DohPath:           c.DoHPath,
		EnableDoh3:        c.EnableDoH3,
		Doh3Addr:          c.DoH3Addr,
		DohAltSvc:         c.DoHAltSvc,
		Doh3QuicMaxIdle:   c.DoH3QUICMaxIdle.String(),
		Doh3QuicKeepalive: c.DoH3QUICKeepAlive.String(),
		Doh3Allow0Rtt:     c.DoH3Allow0RTT,
		CertStoreDir:      c.CertStoreDir,
		CertDefault:       c.CertDefault,
		WebTLS:            c.WebTLS,
		WebhookToken:      c.WebhookToken,
		TrustedProxies:    stringOrList(c.TrustedProxies),
		ClientIPSources:   stringOrList(c.ClientIPSources),
		ClientIPHeaders:   stringOrList(c.ClientIPHeaders),
		ClientIPStatic:    c.ClientIPStatic,
		ISPGroups:         ispGroups,
		CustomGroups:      customGroups,
		AllowACLs:         stringOrList(c.AllowACLs),
		SourceEnabled:     c.SourceEnabled,
		SourceDBDir:       c.SourceDBDir,
		SourceBaseURL:     c.SourceBaseURL,
		SourceUpdateHours: c.SourceUpdateHours,
	}
}

// parseDuration 解析时长字符串，空值返回 fallback
func parseDuration(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d, nil
}

// legacySplitLists 将旧版两组硬编码字段合成为分流列表（用于旧配置迁移）
func (j *ConfigJSON) legacySplitLists() []SplitList {
	refreshOr := func(s string, fallback time.Duration) time.Duration {
		d, err := parseDuration(s, fallback)
		if err != nil {
			return fallback
		}
		return d
	}

	lists := make([]SplitList, 0, 2)
	if j.LegacyDefaultDNS != "" || j.LegacyDesignatedDomain != "" || j.LegacyDesignatedDomainURL != "" {
		lists = append(lists, SplitList{
			Name:       "定向域名",
			Enabled:    true,
			DNS:        oneOrNil(j.LegacyDefaultDNS),
			DomainFile: j.LegacyDesignatedDomain,
			DomainURL:  j.LegacyDesignatedDomainURL,
			Refresh:    refreshOr(j.LegacyDesignatedRefresh, 30*time.Minute),
		})
	}
	if j.LegacyChinaDNS != "" || j.LegacyChinaDomainFile != "" || j.LegacyChinaDomainFileURL != "" {
		lists = append(lists, SplitList{
			Name:       "中国域名",
			Enabled:    j.LegacyEnableChinaDomainCheck,
			DNS:        oneOrNil(j.LegacyChinaDNS),
			DomainFile: j.LegacyChinaDomainFile,
			DomainURL:  j.LegacyChinaDomainFileURL,
			Refresh:    refreshOr(j.LegacyChinaDomainRefresh, 24*time.Hour),
		})
	}
	return lists
}

// ToConfig 将 JSON 表示转换为内存配置（解析时长字符串并校验）
func (j *ConfigJSON) ToConfig() (*Config, error) {
	def := DefaultConfig()

	splitLists := make([]SplitList, 0, len(j.SplitLists))
	for i, l := range j.SplitLists {
		refresh, err := parseDuration(l.Refresh, 0)
		if err != nil {
			return nil, fmt.Errorf("split_lists[%d].refresh: %w", i, err)
		}
		if !ValidIPPrefer(l.IPPrefer) {
			return nil, fmt.Errorf("split_lists[%d].ip_prefer: 非法取值 %q", i, l.IPPrefer)
		}
		splitLists = append(splitLists, SplitList{
			Name:             l.Name,
			Enabled:          l.Enabled,
			Invert:           l.Invert,
			DNS:              []string(l.DNS),
			DNSMode:          l.DNSMode,
			DomainFile:       l.DomainFile,
			DomainURL:        l.DomainURL,
			Refresh:          refresh,
			EnableCloudCheck: l.EnableCloudCheck,
			ECS: ECSPolicy{
				Enabled: l.ECS.Enabled,
				ISPType: l.ECS.ISPType,
				Subnet:  l.ECS.Subnet,
			},
			IPPrefer: l.IPPrefer,
		})
	}
	if len(splitLists) == 0 {
		splitLists = j.legacySplitLists()
	}

	// A/AAAA 偏好档位：空值=不干预，非法值直接拒绝（避免静默失效）
	if !ValidIPPrefer(j.IPPrefer) {
		return nil, fmt.Errorf("ip_prefer: 非法取值 %q", j.IPPrefer)
	}

	// 全局默认解析模式：非法值直接拒绝（旧配置缺 dns_mode 字段时为空串＝跟随默认 race）
	if !ValidDNSMode(j.DNSMode) {
		return nil, fmt.Errorf("dns_mode: 非法取值 %q（可选 race/failover/wrandom）", j.DNSMode)
	}
	if j.DNSMode == "" {
		j.DNSMode = def.DNSMode
	}

	// 老配置里没有 query_log 字段（retention 与 max_rows 均为零值）时整体按默认策略，默认启用
	queryLog := QueryLogConfig{Enabled: j.QueryLog.Enabled, MaxRows: j.QueryLog.MaxRows}
	if j.QueryLog.Retention == "" && j.QueryLog.MaxRows == 0 {
		queryLog = def.QueryLog
	}

	cfg := &Config{
		ListenPort:          j.ListenPort,
		WebAddr:             j.WebAddr,
		WebTLSAddr:          j.WebTLSAddr,
		Upstream:            j.Upstream,
		MaxIPRecords:        j.MaxIPRecords,
		CNAMERecursionDepth: j.CNAMERecursionDepth,
		ReplaceCFDomain:     j.ReplaceCFDomain,
		ReplaceAWSDomain:    j.ReplaceAWSDomain,
		ReplaceCFAPI:        j.ReplaceCFAPI,
		ReplaceAPICount:     j.ReplaceAPICount,
		BackupDNS:           j.BackupDNS,
		DNSMode:             j.DNSMode,
		IPPrefer:            j.IPPrefer,
		SplitLists:          splitLists,
		CloudflareNetFile:   j.CloudflareNetFile,
		CloudflareNetFile6:  j.CloudflareNetFile6,
		AWSNetFile:          j.AWSNetFile,
		LogLevel:            j.LogLevel,
		LogFormat:           j.LogFormat,
		Cache: CacheConfig{
			MaxItems:        j.Cache.MaxItems,
			MaxAsyncWorkers: j.Cache.MaxAsyncWorkers,
		},
		QueryLog:              queryLog,
		EnableCloudflareCheck: j.EnableCloudflareCheck,
		EnableAWSCheck:        j.EnableAWSCheck,
	}

	ispGroups := make([]ISPGroup, 0, len(j.ISPGroups))
	for i, g := range j.ISPGroups {
		key, ok := ParseISPKey(g.ISP)
		if !ok {
			return nil, fmt.Errorf("isp_groups[%d].isp: 非法分组标识 %q", i, g.ISP)
		}
		// 新字段 fallback_dns 为空时回退到旧字段 dns（兼容旧版 DNS-only 模型）
		fallback := []string(g.FallbackDNS)
		if len(fallback) == 0 && len(g.LegacyDNS) > 0 {
			fallback = []string(g.LegacyDNS)
		}
		ispGroups = append(ispGroups, ISPGroup{
			ISP:         key,
			Enabled:     g.Enabled,
			SplitRefs:   []string(g.SplitRefs),
			FallbackDNS: fallback,
			DNSMode:     g.DNSMode,
			IPPrefer:    g.IPPrefer,
			ECS: ECSPolicy{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			CloudReplace: cloudReplacePolicyFromJSON(g.CloudReplace),
		})
	}

	customGroups := make([]CustomGroup, 0, len(j.CustomGroups))
	for _, g := range j.CustomGroups {
		fallback := []string(g.FallbackDNS)
		if len(fallback) == 0 && len(g.LegacyDNS) > 0 {
			fallback = []string(g.LegacyDNS)
		}
		customGroups = append(customGroups, CustomGroup{
			Name:        g.Name,
			Enabled:     g.Enabled,
			Priority:    g.Priority,
			Match:       []string(g.Match),
			SplitRefs:   []string(g.SplitRefs),
			FallbackDNS: fallback,
			DNSMode:     g.DNSMode,
			IPPrefer:    g.IPPrefer,
			ECS: ECSPolicy{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			CloudReplace: cloudReplacePolicyFromJSON(g.CloudReplace),
		})
	}

	// 旧版 client_groups 迁移：仅当新版字段全空时才启用，避免与新版并存时互相覆盖
	if len(ispGroups) == 0 && len(customGroups) == 0 && len(j.LegacyClientGroups) > 0 {
		ispGroups, customGroups = migrateLegacyClientGroups(j.LegacyClientGroups)
	}

	cfg.ISPGroups = ispGroups
	cfg.CustomGroups = customGroups

	// 运营商识别：老配置里没有 source_* 字段（四项全为零值）时按默认策略启用。
	// 只要任一字段有值就说明是新版写出的配置，原样尊重用户的开关选择。
	if j.SourceDBDir == "" && j.SourceBaseURL == "" && !j.SourceEnabled && j.SourceUpdateHours == 0 {
		cfg.SourceEnabled = def.SourceEnabled
		cfg.SourceDBDir = def.SourceDBDir
		cfg.SourceBaseURL = def.SourceBaseURL
		cfg.SourceUpdateHours = def.SourceUpdateHours
	} else {
		cfg.SourceEnabled = j.SourceEnabled
		cfg.SourceDBDir = j.SourceDBDir
		cfg.SourceBaseURL = j.SourceBaseURL
		cfg.SourceUpdateHours = j.SourceUpdateHours
	}
	if cfg.SourceBaseURL == "" {
		cfg.SourceBaseURL = def.SourceBaseURL
	}
	if cfg.SourceDBDir == "" {
		cfg.SourceDBDir = def.SourceDBDir
	}
	cfg.TrustedProxies = []string(j.TrustedProxies)
	cfg.ClientIPSources = []string(j.ClientIPSources)
	cfg.ClientIPHeaders = []string(j.ClientIPHeaders)
	cfg.ClientIPStatic = j.ClientIPStatic
	cfg.AllowACLs = []string(j.AllowACLs)

	cfg.EnableDoT = j.EnableDot
	cfg.DoTAddr = j.DotAddr
	cfg.EnableDoH = j.EnableDoh
	cfg.DoHAddr = j.DohAddr
	cfg.DoHPath = j.DohPath
	cfg.EnableDoH3 = j.EnableDoh3
	cfg.DoH3Addr = j.Doh3Addr
	cfg.DoHAltSvc = j.DohAltSvc
	cfg.DoH3Allow0RTT = j.Doh3Allow0Rtt
	cfg.CertStoreDir = j.CertStoreDir
	cfg.CertDefault = j.CertDefault
	cfg.WebTLS = j.WebTLS
	cfg.WebhookToken = j.WebhookToken

	var err error
	if cfg.Timeout, err = parseDuration(j.Timeout, def.Timeout); err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	if cfg.ModernTimeout, err = parseDuration(j.ModernTimeout, def.ModernTimeout); err != nil {
		return nil, fmt.Errorf("modern_timeout: %w", err)
	}
	if cfg.ReplaceCacheTime, err = parseDuration(j.ReplaceCacheTime, def.ReplaceCacheTime); err != nil {
		return nil, fmt.Errorf("replace_cache_time: %w", err)
	}
	if cfg.NetworkRefreshInterval, err = parseDuration(j.NetworkRefresh, def.NetworkRefreshInterval); err != nil {
		return nil, fmt.Errorf("network_refresh: %w", err)
	}
	if cfg.Cache.TTL, err = parseDuration(j.Cache.TTL, def.Cache.TTL); err != nil {
		return nil, fmt.Errorf("cache.ttl: %w", err)
	}
	if cfg.Cache.StaleTTL, err = parseDuration(j.Cache.StaleTTL, def.Cache.StaleTTL); err != nil {
		return nil, fmt.Errorf("cache.stale_ttl: %w", err)
	}
	if cfg.QueryLog.Retention, err = parseDuration(j.QueryLog.Retention, queryLog.Retention); err != nil {
		return nil, fmt.Errorf("query_log.retention: %w", err)
	}
	if cfg.DoH3QUICMaxIdle, err = parseDuration(j.Doh3QuicMaxIdle, def.DoH3QUICMaxIdle); err != nil {
		return nil, fmt.Errorf("doh3_quic_max_idle: %w", err)
	}
	if cfg.DoH3QUICKeepAlive, err = parseDuration(j.Doh3QuicKeepalive, def.DoH3QUICKeepAlive); err != nil {
		return nil, fmt.Errorf("doh3_quic_keepalive: %w", err)
	}

	return cfg, nil
}

// migrateLegacyClientGroups 把旧版「自由命名 + IP/CIDR/isp: + 取反」的客户端分组迁移为新模型。
//
// 规则：
//   - `isp:<name>`  → 对应运营商固定分组（启用；兜底 DNS = 旧组 DNS，不再引用分流列表）
//   - 纯 IP/CIDR    → 自定义分组（保留 IP 匹配能力；兜底 DNS = 旧组 DNS）
//   - invert        → 丢弃（旧取反语义与新模型冲突）
//   - 旧组 DNS  → fallback_dns（分流未命中时兜底，与旧「命中即用组 DNS」行为最接近）
//
// 仅当旧组非空且至少有一条 DNS 时才迁移；否则跳过，避免生成"启用即不合法"的配置。
func migrateLegacyClientGroups(legacy []legacyClientGroupJSON) ([]ISPGroup, []CustomGroup) {
	var isps []ISPGroup
	var customs []CustomGroup
	seenISP := map[ISPKey]bool{}

	for _, g := range legacy {
		if !g.Enabled {
			continue
		}
		fallback := []string(g.DNS)
		if len(fallback) == 0 {
			// 没有 DNS 即视为未配置，不迁移
			continue
		}
		var ips []string
		for _, m := range g.Match {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if strings.HasPrefix(m, "isp:") {
				key, ok := ParseISPKey(strings.TrimPrefix(m, "isp:"))
				if !ok || seenISP[key] {
					continue
				}
				seenISP[key] = true
				isps = append(isps, ISPGroup{
					ISP:         key,
					Enabled:     true,
					FallbackDNS: fallback,
					DNSMode:     g.DNSMode,
				})
				continue
			}
			ips = append(ips, m)
		}
		if len(ips) > 0 {
			customs = append(customs, CustomGroup{
				Name:        g.Name,
				Enabled:     true,
				Priority:    g.Priority,
				Match:       ips,
				FallbackDNS: fallback,
				DNSMode:     g.DNSMode,
			})
		}
	}
	return isps, customs
}
