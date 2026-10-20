package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// 常量定义
const (
	DefaultStorePath    = "./data/config.db"    // SQLite 配置库存储路径
	DefaultQueryLogPath = "./data/query_log.db" // 解析日志库存储路径（独立于配置库）
	DefaultWebAddr      = ":8880"               // Web 管理端默认 HTTP 监听地址
	DefaultWebTLSAddr   = ":8843"               // Web 管理端默认 HTTPS 监听地址
	DefaultLogLevel     = "info"
)

// 解析日志默认保留策略
const (
	DefaultQueryLogRetention = 72 * time.Hour // 默认保留 3 天
	DefaultQueryLogMaxRows   = 200000         // 默认最多 20 万条
)

// 支持的 ECS 线路类型（白名单外的取值一律不注入）
const (
	ECSTypeTelecom = "telecom" // 电信
	ECSTypeUnicom  = "unicom"  // 联通
	ECSTypeMobile  = "mobile"  // 移动
)

// ValidECSType 判断线路类型是否受支持
func ValidECSType(t string) bool {
	switch t {
	case ECSTypeTelecom, ECSTypeUnicom, ECSTypeMobile:
		return true
	}
	return false
}

// ECSPolicy 分流列表的 EDNS Client Subnet 策略（RFC 7871）：按手动指定的公网 IP 让上游返回对应线路的结果
type ECSPolicy struct {
	Enabled bool   // 是否向上游注入 ECS（关闭时命中该列表仅剥离客户端自带 ECS）
	ISPType string // 线路类型：telecom/unicom/mobile
	Subnet  string // 手动指定的公网 IP 或 CIDR（裸 IP 按 /24，IPv6 裸 IP 按 /56）
}

// Resolve 解析待注入的地址前缀：开关未打开、类型不在白名单、地址不可解析时均返回 ok=false（不注入）
func (e ECSPolicy) Resolve() (netip.Prefix, bool) {
	if !e.Enabled || !ValidECSType(e.ISPType) {
		return netip.Prefix{}, false
	}
	s := strings.TrimSpace(e.Subnet)
	if s == "" {
		return netip.Prefix{}, false
	}
	// CIDR 写法直接取其前缀
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	// 裸 IP 按运营商可识别的最小前缀补齐
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 24 // IPv4
	if ip.Is6() {
		bits = 56 // IPv6（RFC 7871 建议值）
	}
	p := netip.PrefixFrom(ip, bits)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// CacheConfig 缓存配置
type CacheConfig struct {
	MaxItems        int           // 最大缓存条目数
	TTL             time.Duration // 兜底缓存TTL：上游未提供TTL时使用，不再抬高上游TTL
	StaleTTL        time.Duration // 过期宽限：条目过期后仍可在该时长内把旧响应返回客户端（0=禁用，过期即未命中）
	MaxAsyncWorkers int           // 最大异步工作线程数
}

// 分流列表的 DNS 解析模式
const (
	DNSModeRace     = "race"     // 并发竞速：同时查询所有 DNS，取最快成功的结果（默认）
	DNSModeFailover = "failover" // 串行故障转移：按 DNS 顺序依次查询，前一个失败/超时才用下一个
	DNSModeWRandom  = "wrandom"  // 权重随机：按地址 #权重 随机选一台查询（每次 miss 只发 1 次），失败再从其余选一台
)

// ValidDNSMode 判断 DNS 解析模式取值是否合法（空串＝默认 race）
func ValidDNSMode(mode string) bool {
	switch mode {
	case "", DNSModeRace, DNSModeFailover, DNSModeWRandom:
		return true
	}
	return false
}

// A/AAAA 偏好档位：列表未配置时跟随全局默认，全局默认与"不干预"等效
// 语义前提：客户端 QTYPE 永远被尊重（查A回A、查AAAA回AAAA），"优先"只能靠抑制次优类型（返回空 NODATA）实现
const (
	IPPreferAuto  = ""            // 不干预：完全按客户端 QTYPE 返回（默认）
	IPPreferA     = "prefer_a"    // 优先A：查询AAAA且该域名确有A记录时返回空 NODATA；无A（纯v6域名）则照常返回AAAA
	IPPreferAAAA  = "prefer_aaaa" // 优先AAAA：不抑制A；AAAA不因云替换缺v6而被置空，降级返回上游真实AAAA
	IPPreferOnlyA = "only_a"      // 只能A：查询AAAA一律返回空 NODATA
)

// ValidIPPrefer 判断 A/AAAA 偏好档位取值是否合法（空串＝不干预）
func ValidIPPrefer(v string) bool {
	switch v {
	case IPPreferAuto, IPPreferA, IPPreferAAAA, IPPreferOnlyA:
		return true
	}
	return false
}

// SplitList 域名分流列表：命中列表内域名时改用该列表的 DNS 解析
// 数组顺序即匹配优先级，命中第一条即生效
type SplitList struct {
	Name             string        // 自定义名称（仅用于展示与日志）
	Enabled          bool          // 是否启用该列表
	Invert           bool          // 取反匹配：域名不在清单内时命中本列表（清单为空时不参与匹配）
	DNS              []string      // 命中后使用的 DNS 服务器列表（按 DNSMode 解析；支持 udp/tcp/https/tls/h3）
	DNSMode          string        // DNS 解析模式：race(并发竞速，默认/空值)/failover(串行故障转移)/wrandom(权重随机)
	DomainFile       string        // 域名列表本地文件路径
	DomainURL        string        // 域名列表远程 URL（优先于本地文件）
	Refresh          time.Duration // 列表刷新间隔
	EnableCloudCheck bool          // 命中该列表后是否仍做云服务检测（默认否=跳过检测与替换）
	ECS              ECSPolicy     // 命中该列表后的 EDNS Client Subnet 策略
	IPPrefer         string        // A/AAAA 偏好档位（空值=跟随全局默认）
}

// QueryLogConfig 解析日志配置：每次客户端查询记录一行（独立 SQLite 库）
type QueryLogConfig struct {
	Enabled   bool          // 是否记录解析日志
	Retention time.Duration // 保留时长，超期自动删除
	MaxRows   int           // 最大保留条数，超出后删除最旧记录
}

// ISPKey 运营商固定分组标识（内置枚举，不可自定义；仅 4 个）
// 标识即缓存 scope，固定不变，避免"改个名字缓存全失效"
type ISPKey string

const (
	ISPGroupTelecom ISPKey = "telecom" // 中国电信
	ISPGroupUnicom  ISPKey = "unicom"  // 中国联通
	ISPGroupCMCC    ISPKey = "cmcc"    // 中国移动（含铁通）
	ISPGroupOther   ISPKey = "other"   // 其他（未识别 / 境外 / 教育网 / 广电 / 长宽）
)

// KnownISPGroups 返回全部运营商固定分组，顺序即 UI 展示顺序
func KnownISPGroups() []ISPKey {
	return []ISPKey{ISPGroupTelecom, ISPGroupUnicom, ISPGroupCMCC, ISPGroupOther}
}

// ISPGroupLabel 返回内置展示名（完全内置，不可自定义）
func ISPGroupLabel(k ISPKey) string {
	switch k {
	case ISPGroupTelecom:
		return "中国电信"
	case ISPGroupUnicom:
		return "中国联通"
	case ISPGroupCMCC:
		return "中国移动"
	case ISPGroupOther:
		return "其他"
	}
	return string(k)
}

// ParseISPKey 解析运营商分组标识（兼容常见别名），未知返回 ok=false
func ParseISPKey(s string) (ISPKey, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "telecom", "chinatelecom", "电信":
		return ISPGroupTelecom, true
	case "unicom", "cnc", "cuc", "联通":
		return ISPGroupUnicom, true
	case "cmcc", "mobile", "moving", "移动":
		return ISPGroupCMCC, true
	case "other", "其他":
		return ISPGroupOther, true
	}
	return "", false
}

// ValidISPKey 判断是否为内置运营商分组
func ValidISPKey(k ISPKey) bool {
	for _, x := range KnownISPGroups() {
		if x == k {
			return true
		}
	}
	return false
}

// CloudReplacePolicy 云替换线路策略：分组级覆写全局云 IP 替换目标。
// Override 为 false 时本组完全跟随全局 replace_cf_domain / replace_aws_domain / replace_cf_api；
// 为 true 时用本组字段（空值的类型等同该类型不替换，走既有降级逻辑返回上游真实 IP）。
type CloudReplacePolicy struct {
	Override  bool   // 是否覆写全局云替换目标
	CFDomain  string // Cloudflare 替换域名
	AWSDomain string // AWS 替换域名
	CFAPI     string // CF 替换 IP 接口（非空时改从接口取 IP）
	APICount  int    // 从替换接口取前 N 条 IP
}

// ISPGroup 运营商固定分组：来源运营商自动决定分组。
// 命中分组后先按 SplitRefs 引用的域名分流列表匹配（命中哪条复用哪条的策略）；
// 全部未命中时用 FallbackDNS 兜底（覆盖全局上游），兜底查询按 DNSMode/IPPrefer/ECS 处理。
type ISPGroup struct {
	ISP          ISPKey             // 固定标识（唯一键，决定缓存 scope）
	Enabled      bool               // 未启用 = 不干预，走全局默认
	SplitRefs    []string           // 引用「上游与域名分流」里的列表名，顺序即匹配顺序（命中复用该列表 DNS/模式/ECS/偏好/云检测）
	FallbackDNS  []string           // 兜底上游：引用分流全部未命中时使用；为空则回退全局 upstream
	DNSMode      string             // race / failover / wrandom，仅作用于 FallbackDNS
	IPPrefer     string             // 兜底查询的 A/AAAA 偏好档位（空值=跟随全局默认）
	ECS          ECSPolicy          // 兜底查询的 EDNS Client Subnet 策略
	CloudReplace CloudReplacePolicy // 本线路的云替换目标（可覆写全局）
}

// CustomGroup 自定义分组：按 IP/CIDR 匹配，覆盖"非运营商"需求（机房出口、专线等）。
// 路由语义与运营商分组一致：先按 SplitRefs 匹配域名分流，未命中走 FallbackDNS 兜底。
// 越级（Priority 大的优先）排于 ISP 组之前。
type CustomGroup struct {
	Name         string // 展示名
	Enabled      bool
	Priority     int                // 大者优先（仅自定义组之间排序；整体优先于运营商组）
	Match        []string           // 裸 IP / CIDR（v4/v6）
	SplitRefs    []string           // 引用「上游与域名分流」里的列表名，顺序即匹配顺序
	FallbackDNS  []string           // 兜底上游：引用分流全部未命中时使用；为空则回退全局 upstream
	DNSMode      string             // race / failover / wrandom，仅作用于 FallbackDNS
	IPPrefer     string             // 兜底查询的 A/AAAA 偏好档位（空值=跟随全局默认）
	ECS          ECSPolicy          // 兜底查询的 EDNS Client Subnet 策略
	CloudReplace CloudReplacePolicy // 本线路的云替换目标（可覆写全局）
}

// CustomScope 自定义分组的缓存 scope（前缀 c: 与内置 ISP key 区分，避免重名串味）
func CustomScope(name string) string { return "c:" + name }

// Config 配置结构体（内存表示，时长为 time.Duration）
type Config struct {
	ListenPort             int
	WebAddr                string         // Web 管理端 HTTP 监听地址
	WebTLSAddr             string         // Web 管理端 HTTPS 监听地址
	Upstream               []string       // 上游DNS服务器（统一URL scheme）
	Timeout                time.Duration  // 传统协议(UDP/TCP)查询超时
	ModernTimeout          time.Duration  // 现代协议(DoH/DoT/DoH3)查询超时
	ReplaceCacheTime       time.Duration  // 云替换响应缓存时间
	MaxIPRecords           int            // 替换域名使用的最大IP数
	CNAMERecursionDepth    int            // CNAME链收集深度（仅用于云检测）
	ReplaceCFDomain        string         // Cloudflare IP 替换域名
	ReplaceAWSDomain       string         // AWS IP 替换域名
	ReplaceCFAPI           string         // CF 替换 IP 接口地址（非空时改从接口取 IP，不再解析 ReplaceCFDomain）
	ReplaceAPICount        int            // 从替换接口取前 N 条 IP（默认 1）
	BackupDNS              string         // 所有上游失败后的备用DNS
	DNSMode                string         // 全局默认解析模式：race(竞速，默认/空值)/failover(串行)/wrandom(权重随机)
	IPPrefer               string         // 全局默认 A/AAAA 偏好档位（未命中分流列表或列表未配置时生效）
	SplitLists             []SplitList    // 域名分流列表（按顺序匹配）
	CloudflareNetFile      string         // Cloudflare IP段数据文件
	CloudflareNetFile6     string         // Cloudflare IPv6段数据文件
	AWSNetFile             string         // AWS IP段数据文件
	NetworkRefreshInterval time.Duration  // 云IP段数据文件刷新间隔
	LogLevel               string         // 日志级别：debug/info/warn/error
	LogFormat              string         // 日志格式：text/json
	Cache                  CacheConfig    // 缓存配置
	QueryLog               QueryLogConfig // 解析日志配置
	EnableCloudflareCheck  bool           // Cloudflare IP 检测与替换开关
	EnableAWSCheck         bool           // AWS IP 检测与替换开关

	// 入站加密服务
	EnableDoT  bool
	DoTAddr    string
	EnableDoH  bool
	DoHAddr    string
	DoHPath    string
	EnableDoH3 bool
	DoH3Addr   string

	// DoH/DoH3 调优
	DoHAltSvc         string
	DoH3QUICMaxIdle   time.Duration
	DoH3QUICKeepAlive time.Duration
	DoH3Allow0RTT     bool

	// 证书托管
	CertStoreDir string
	CertDefault  string
	WebTLS       bool

	// Webhook 与客户端 IP
	WebhookToken    string
	TrustedProxies  []string
	ClientIPSources []string
	ClientIPHeaders []string
	ClientIPStatic  map[string]string // 连接 IP -> 客户端 IP 静态映射
	ISPGroups       []ISPGroup        // 运营商固定分组（内置 4 个，不可增删）
	CustomGroups    []CustomGroup     // 自定义分组（按 IP/CIDR 匹配，可增删）
	AllowACLs       []string

	// 客户端来源识别（运营商 IP 段库）
	SourceEnabled     bool   // 是否启用运营商识别
	SourceDBDir       string // 运营商段库目录（内含 <isp>.txt，逐行 CIDR）
	SourceBaseURL     string // 运营商段下载源目录（如 https://ispip.clang.cn）
	SourceUpdateHours int    // 自动更新间隔（小时）；0 表示不自动更新
}

// DefaultConfig 返回内置默认配置（首次启动且数据库中无配置时使用）
func DefaultConfig() *Config {
	return &Config{
		ListenPort: 53,
		WebAddr:    DefaultWebAddr,
		Upstream: []string{
			"https://223.5.5.5/dns-query", // 阿里DNS
			"https://doh.pub/dns-query",   // 腾讯DoH
			"udp://119.29.29.29:53",       // 腾讯DNS
		},
		Timeout:             1500 * time.Millisecond,
		ModernTimeout:       1000 * time.Millisecond,
		ReplaceCacheTime:    30 * time.Minute,
		MaxIPRecords:        2,
		CNAMERecursionDepth: 1,
		ReplaceCFDomain:     "cf.blogluo.eu.org",
		ReplaceAWSDomain:    "cc.cloudfront.182682.xyz",
		ReplaceCFAPI:        "",
		ReplaceAPICount:     1,
		BackupDNS:           "udp://114.114.114.114:53",
		DNSMode:             DNSModeRace,
		SplitLists: []SplitList{
			{
				Name:       "定向域名",
				Enabled:    true,
				DNS:        []string{"https://223.6.6.6/dns-query"},
				DomainFile: "./data/designated.yaml",
				DomainURL:  "https://raw.githubusercontent.com/dingdadao/dnsPorxy/refs/heads/master/scripts/shell/designated.yaml",
				Refresh:    30 * time.Minute,
			},
			{
				Name:       "中国域名",
				Enabled:    true,
				DNS:        []string{"udp://223.5.5.5:53"},
				DomainFile: "./data/china_domains.yaml",
				DomainURL:  "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China_Domain.yaml",
				Refresh:    24 * time.Hour,
			},
		},
		CloudflareNetFile:      "./data/cf_mrs_file4.txt",
		CloudflareNetFile6:     "./data/cf_mrs_file6.txt",
		AWSNetFile:             "./data/aws.txt",
		NetworkRefreshInterval: 96 * time.Hour,
		LogLevel:               "debug",
		LogFormat:              "text",
		Cache: CacheConfig{
			MaxItems:        5000,
			TTL:             5 * time.Minute,
			StaleTTL:        5 * time.Minute,
			MaxAsyncWorkers: 2,
		},
		QueryLog: QueryLogConfig{
			Enabled:   true,
			Retention: DefaultQueryLogRetention,
			MaxRows:   DefaultQueryLogMaxRows,
		},
		EnableCloudflareCheck: true,
		EnableAWSCheck:        false,

		EnableDoT:  false,
		DoTAddr:    ":853",
		EnableDoH:  false,
		DoHAddr:    ":443",
		DoHPath:    "/dns-query",
		EnableDoH3: false,
		DoH3Addr:   "",

		DoHAltSvc:         "h3=\":443\"; ma=86400",
		DoH3QUICMaxIdle:   3 * time.Minute,
		DoH3QUICKeepAlive: 30 * time.Second,
		DoH3Allow0RTT:     false,

		CertStoreDir: "./data/certs",
		CertDefault:  "",
		WebTLS:       true,
		WebTLSAddr:   DefaultWebTLSAddr,

		TrustedProxies:    []string{"127.0.0.1/32", "::1/128"},
		ClientIPSources:   []string{"static", "header", "socket"},
		ClientIPHeaders:   []string{"cf-connecting-ip", "x-forwarded-for", "x-real-ip"},
		ISPGroups:         []ISPGroup{},
		CustomGroups:      []CustomGroup{},
		AllowACLs:         []string{},
		SourceEnabled:     true,
		SourceDBDir:       "./data/ispdb",
		SourceBaseURL:     "https://ispip.clang.cn",
		SourceUpdateHours: 24,
	}
}

// ValidateConfig 验证配置
func ValidateConfig(cfg *Config) error {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", cfg.ListenPort)
	}
	if len(cfg.Upstream) == 0 {
		return fmt.Errorf("no upstream servers configured")
	}

	// 全局默认解析模式：非法值直接拒绝，避免静默失效
	if !ValidDNSMode(cfg.DNSMode) {
		return fmt.Errorf("dns_mode: 非法取值 %q（可选 race/failover/wrandom）", cfg.DNSMode)
	}

	// 上游地址归一化：缺端口按协议补默认端口（udp/tcp→53、tls→853），非法值直接拒绝
	// 不补端口会让 dial 报 "missing port in address"，且旧配置里的 udp://1.1.1.1 写法会静默失效
	if err := normalizeUpstreamList("upstream", cfg.Upstream); err != nil {
		return err
	}
	if norm, err := normalizeUpstreamField("backup_dns", cfg.BackupDNS); err != nil {
		return err
	} else {
		cfg.BackupDNS = norm
	}
	for i := range cfg.SplitLists {
		if err := normalizeUpstreamList(fmt.Sprintf("split_lists[%d].dns", i), cfg.SplitLists[i].DNS); err != nil {
			return err
		}
	}
	for i := range cfg.ISPGroups {
		if err := normalizeUpstreamList(fmt.Sprintf("isp_groups[%d].fallback_dns", i), cfg.ISPGroups[i].FallbackDNS); err != nil {
			return err
		}
		cfg.ISPGroups[i].SplitRefs = normalizeRefs(cfg.ISPGroups[i].SplitRefs)
		if err := normalizeCloudReplacePolicy(fmt.Sprintf("isp_groups[%d]", i), &cfg.ISPGroups[i].CloudReplace); err != nil {
			return err
		}
	}
	for i := range cfg.CustomGroups {
		if err := normalizeUpstreamList(fmt.Sprintf("custom_groups[%d].fallback_dns", i), cfg.CustomGroups[i].FallbackDNS); err != nil {
			return err
		}
		cfg.CustomGroups[i].SplitRefs = normalizeRefs(cfg.CustomGroups[i].SplitRefs)
		cfg.CustomGroups[i].Match = normalizeRefs(cfg.CustomGroups[i].Match)
		if err := normalizeCloudReplacePolicy(fmt.Sprintf("custom_groups[%d]", i), &cfg.CustomGroups[i].CloudReplace); err != nil {
			return err
		}
	}

	if cfg.WebAddr == "" {
		cfg.WebAddr = DefaultWebAddr
	}
	if cfg.WebTLSAddr == "" {
		cfg.WebTLSAddr = DefaultWebTLSAddr
	}
	if cfg.Cache.MaxItems <= 0 {
		cfg.Cache.MaxItems = 5000
	}
	if cfg.Cache.TTL <= 0 {
		cfg.Cache.TTL = 5 * time.Minute
	}
	if cfg.Cache.MaxAsyncWorkers <= 0 {
		cfg.Cache.MaxAsyncWorkers = 2
	}
	// 过期宽限允许为 0（禁用 serve-stale），仅把负值归零避免出现"负宽限"
	if cfg.Cache.StaleTTL < 0 {
		cfg.Cache.StaleTTL = 0
	}
	if cfg.QueryLog.Retention <= 0 {
		cfg.QueryLog.Retention = DefaultQueryLogRetention
	}
	if cfg.QueryLog.MaxRows <= 0 {
		cfg.QueryLog.MaxRows = DefaultQueryLogMaxRows
	}
	if cfg.ReplaceCFAPI != "" && !strings.HasPrefix(cfg.ReplaceCFAPI, "http://") && !strings.HasPrefix(cfg.ReplaceCFAPI, "https://") {
		return fmt.Errorf("invalid replace_cf_api: %s", cfg.ReplaceCFAPI)
	}
	if cfg.ReplaceAPICount <= 0 {
		cfg.ReplaceAPICount = 1
	}

	// 入站服务默认端口
	if cfg.DoTAddr == "" {
		cfg.DoTAddr = ":853"
	}
	if cfg.DoHAddr == "" {
		cfg.DoHAddr = ":443"
	}
	if cfg.DoHPath == "" {
		cfg.DoHPath = "/dns-query"
	}
	if !strings.HasPrefix(cfg.DoHPath, "/") {
		cfg.DoHPath = "/" + cfg.DoHPath
	}
	if cfg.DoH3Addr == "" {
		cfg.DoH3Addr = cfg.DoHAddr
	}
	if cfg.DoHAltSvc == "" {
		cfg.DoHAltSvc = "h3=\":443\"; ma=86400"
	}
	if cfg.DoH3QUICMaxIdle <= 0 {
		cfg.DoH3QUICMaxIdle = 3 * time.Minute
	}
	if cfg.DoH3QUICKeepAlive <= 0 {
		cfg.DoH3QUICKeepAlive = 30 * time.Second
	}
	if cfg.CertStoreDir == "" {
		cfg.CertStoreDir = "./data/certs"
	}
	if len(cfg.ClientIPSources) == 0 {
		cfg.ClientIPSources = []string{"static", "header", "socket"}
	}
	if len(cfg.ClientIPHeaders) == 0 {
		cfg.ClientIPHeaders = []string{"cf-connecting-ip", "x-forwarded-for", "x-real-ip"}
	}

	// 校验客户端 IP 取值来源：非法值会让该优先级静默失效
	for _, src := range cfg.ClientIPSources {
		switch strings.TrimSpace(src) {
		case "", "static", "header", "socket":
		default:
			return fmt.Errorf("client_ip_sources: 非法取值 %q（可选 static/header/socket）", src)
		}
	}

	// 校验可信代理：非法网段会导致请求头永不采信
	for _, p := range cfg.TrustedProxies {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !ValidIPOrCIDR(p) {
			return fmt.Errorf("trusted_proxies: 非法 IP/CIDR %q", p)
		}
	}

	// 分流列表名称集合：分组 SplitRefs 引用的列表必须真实存在，否则运行时静默兜底，很难排查
	splitNames := make(map[string]bool, len(cfg.SplitLists))
	for _, l := range cfg.SplitLists {
		if n := strings.TrimSpace(l.Name); n != "" {
			splitNames[n] = true
		}
	}
	validateGroupRouting := func(prefix, label string, refs []string, ipPrefer string, ecs ECSPolicy) error {
		for _, ref := range refs {
			if !splitNames[ref] {
				return fmt.Errorf("%s（%s）: 引用的分流列表 %q 不存在（请在「上游与域名分流」中先定义）", prefix, label, ref)
			}
		}
		if !ValidIPPrefer(ipPrefer) {
			return fmt.Errorf("%s.ip_prefer: 非法取值 %q", prefix, ipPrefer)
		}
		if ecs.Enabled && !ValidECSType(ecs.ISPType) {
			return fmt.Errorf("%s.ecs.isp_type: 非法取值 %q", prefix, ecs.ISPType)
		}
		if ecs.Enabled && strings.TrimSpace(ecs.Subnet) == "" {
			return fmt.Errorf("%s.ecs.subnet: 启用 ECS 注入时必须填写公网 IP 或 CIDR", prefix)
		}
		return nil
	}

	// 校验运营商固定分组
	seenISP := map[ISPKey]bool{}
	for i := range cfg.ISPGroups {
		g := &cfg.ISPGroups[i]
		if !ValidISPKey(g.ISP) {
			return fmt.Errorf("isp_groups[%d].isp: 非法分组标识 %q（可选 telecom/unicom/cmcc/other）", i, g.ISP)
		}
		if seenISP[g.ISP] {
			return fmt.Errorf("isp_groups: 分组 %q 重复", g.ISP)
		}
		seenISP[g.ISP] = true
		if g.DNSMode != "" && g.DNSMode != DNSModeRace && g.DNSMode != DNSModeFailover && g.DNSMode != DNSModeWRandom {
			return fmt.Errorf("isp_groups[%d].dns_mode: 非法取值 %q", i, g.DNSMode)
		}
		if err := validateGroupRouting(fmt.Sprintf("isp_groups[%d]", i), ISPGroupLabel(g.ISP), g.SplitRefs, g.IPPrefer, g.ECS); err != nil {
			return err
		}
		if !g.Enabled {
			continue
		}
		if len(g.SplitRefs) == 0 && len(g.FallbackDNS) == 0 {
			return fmt.Errorf("isp_groups[%d]（%s）: 启用时必须至少引用一条分流规则或配置一条兜底 DNS", i, ISPGroupLabel(g.ISP))
		}
	}

	// 校验自定义分组
	seenName := map[string]bool{}
	for i := range cfg.CustomGroups {
		g := &cfg.CustomGroups[i]
		g.Name = strings.TrimSpace(g.Name)
		if g.Name == "" {
			return fmt.Errorf("custom_groups[%d]: name 不能为空", i)
		}
		if seenName[g.Name] {
			return fmt.Errorf("custom_groups: 名称 %q 重复", g.Name)
		}
		seenName[g.Name] = true
		if g.DNSMode != "" && g.DNSMode != DNSModeRace && g.DNSMode != DNSModeFailover && g.DNSMode != DNSModeWRandom {
			return fmt.Errorf("custom_groups[%d].dns_mode: 非法取值 %q", i, g.DNSMode)
		}
		for _, m := range g.Match {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if !ValidIPOrCIDR(m) {
				return fmt.Errorf("custom_groups[%d].match: 非法 IP/CIDR %q", i, m)
			}
		}
		if err := validateGroupRouting(fmt.Sprintf("custom_groups[%d]", i), g.Name, g.SplitRefs, g.IPPrefer, g.ECS); err != nil {
			return err
		}
		if !g.Enabled {
			continue
		}
		if len(normalizeRefs(g.Match)) == 0 {
			return fmt.Errorf("custom_groups[%d]（%s）: 启用时必须至少一条匹配条件", i, g.Name)
		}
		if len(g.SplitRefs) == 0 && len(g.FallbackDNS) == 0 {
			return fmt.Errorf("custom_groups[%d]（%s）: 启用时必须至少引用一条分流规则或配置一条兜底 DNS", i, g.Name)
		}
	}

	return nil
}

// normalizeRefs 去掉空白项并保留顺序（就地归一化用）
func normalizeRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// normalizeCloudReplacePolicy 归一化分组级云替换策略：去空白、APICount 兜底、
// CFAPI 非空时校验协议前缀（对齐全局 replace_cf_api 的校验）
func normalizeCloudReplacePolicy(prefix string, p *CloudReplacePolicy) error {
	p.CFDomain = strings.TrimSpace(p.CFDomain)
	p.AWSDomain = strings.TrimSpace(p.AWSDomain)
	p.CFAPI = strings.TrimSpace(p.CFAPI)
	if p.APICount <= 0 {
		p.APICount = 1
	}
	if p.CFAPI != "" && !strings.HasPrefix(p.CFAPI, "http://") && !strings.HasPrefix(p.CFAPI, "https://") {
		return fmt.Errorf("invalid %s.cloud_replace.cf_api: %s", prefix, p.CFAPI)
	}
	return nil
}

// ValidIPOrCIDR 判断字符串是否为合法的裸 IP（v4/v6）或 CIDR 网段
func ValidIPOrCIDR(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}
