// Package querylog 解析日志：记录每次客户端 DNS 查询走了哪条路（篡改/缓存/分流/上游/云替换）
// 用的什么策略（列表、DNS 服务器、解析模式、ECS）以及最终结果。
// 存储使用独立于配置库的 SQLite 文件：WAL 模式 + 单连接 + 异步批量写入，
// 写入失败或队列打满都不影响 DNS 解析主链路；按保留时长与条数上限自动清理。
package querylog

import (
	"database/sql"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsPorxy/internal/utils"

	_ "modernc.org/sqlite" // 纯Go SQLite驱动（免cgo）
)

// 解析动作类型（action 字段取值）
const (
	ActionOverride = "override" // 本地域名篡改命中（最高优先级）
	ActionCache    = "cache"    // 缓存命中（含云替换响应缓存）
	ActionSplit    = "split"    // 命中域名分流列表
	ActionUpstream = "upstream" // 走全局上游
	ActionCloud    = "cloud"    // 云 IP 检测后替换
	ActionFiltered = "filtered" // 被 A/AAAA 偏好策略置空（返回空 NODATA）
	ActionRefused  = "refused"  // RD=0 且缓存未命中
	ActionError    = "error"    // 解析失败或错误响应
)

// 来源维度取值（source_kind / via / protocol 字段）
const (
	SourceOuter   = "outer"   // 外网：客户端 IP 为公网地址
	SourceInner   = "inner"   // 内网：客户端 IP 命中内网网段
	SourceUnknown = "unknown" // 未知：客户端 IP 缺失或无法解析

	ViaProxy  = "proxy"  // 经代理：客户端 IP 取自前置代理透传的请求头
	ViaDirect = "direct" // 直连：客户端 IP 取自连接对端地址或静态映射

	ProtoUDP  = "UDP"
	ProtoTCP  = "TCP"
	ProtoDoT  = "DoT"
	ProtoDoH  = "DoH"
	ProtoDoH3 = "DoH3"
)

// 来源维度相关的统计算法上限
const (
	defaultTopClients = 20  // 统计页 Top 客户端来源默认条数
	maxTopClients     = 100 // 统计页 Top 客户端来源条数上限
)

const (
	queueSize  = 8192        // 异步写入队列长度，打满即丢弃并计数
	batchSize  = 256         // 单次事务最大条数
	flushEvery = time.Second // 队列未满时的最大落库间隔
	pruneEvery = 10 * time.Minute
	pruneLimit = 50000 // 单次清理上限，避免长时间持有写锁
	maxLimit   = 500   // 单次查询最大条数

	defaultTopDomains = 20  // 统计页 Top 域名默认条数
	maxTopDomains     = 100 // 统计页 Top 域名条数上限
	dayLayout         = "2006-01-02"
)

// 默认保留策略（配置缺省时使用）
const (
	DefaultRetention = 72 * time.Hour
	DefaultMaxRows   = 200000
)

// Entry 单条解析日志（全量明细：每次客户端查询一行）
type Entry struct {
	ID         int64  `json:"id"`
	Time       int64  `json:"time"` // Unix 秒
	Domain     string `json:"domain"`
	QType      string `json:"qtype"`
	Client     string `json:"client"`      // 归一化客户端 IP（不含端口）
	ClientISP  string `json:"client_isp"`  // 客户端 IP 归属运营商（telecom/unicom/... 空为未识别）
	Protocol   string `json:"protocol"`    // 接入协议 UDP/TCP/DoT/DoH/DoH3
	SourceKind string `json:"source_kind"` // 来源类型 外网 outer / 内网 inner / 未知 unknown
	Via        string `json:"via"`         // 接入方式 经代理 proxy / 直连 direct
	Action     string `json:"action"`
	ListName   string `json:"list_name"` // 命中的分流列表名称（篡改/缓存/上游为空）
	DNS        string `json:"dns"`       // 实际应答的上游服务器
	DNSMode    string `json:"dns_mode"`  // race/failover
	ECS        string `json:"ecs"`       // ECS 处理说明（注入 xxx / 剥离客户端 ECS）
	Rcode      string `json:"rcode"`
	Answers    string `json:"answers"` // 应答记录摘要
	ElapsedMS  int64  `json:"elapsed_ms"`
}

// GroupStat 单维度聚合结果（来源 / 类型 / 结果分布）
type GroupStat struct {
	Key          string  `json:"key"`
	Count        int64   `json:"count"`
	AvgElapsedMS float64 `json:"avg_elapsed_ms"`
}

// ListStat 分流列表命中情况（Actions 为该列表内的来源构成）
type ListStat struct {
	Name         string      `json:"name"`
	Count        int64       `json:"count"`
	AvgElapsedMS float64     `json:"avg_elapsed_ms"`
	Actions      []GroupStat `json:"actions"`
}

// DomainStat Top 域名条目
type DomainStat struct {
	Domain       string  `json:"domain"`
	Count        int64   `json:"count"`
	AvgElapsedMS float64 `json:"avg_elapsed_ms"`
	Action       string  `json:"action"`    // 主导来源
	ListName     string  `json:"list_name"` // 主要命中的分流列表
}

// DayStat 本地自然日的查询量
type DayStat struct {
	Day   string `json:"day"` // 2006-01-02
	Count int64  `json:"count"`
}

// ClientStat Top 客户端来源条目
type ClientStat struct {
	Client       string  `json:"client"`      // 归一化客户端 IP
	ISP          string  `json:"isp"`         // 归属运营商（空为未识别）
	SourceKind   string  `json:"source_kind"` // 该客户端的主要来源类型
	Count        int64   `json:"count"`
	AvgElapsedMS float64 `json:"avg_elapsed_ms"`
	Action       string  `json:"action"` // 主要来源路径
}

// Summary 统计汇总：窗口由 Filter 决定，默认保留期内全部记录（不设条数上限）
type Summary struct {
	Total        int64        `json:"total"`
	FirstTS      int64        `json:"first_ts"`
	LastTS       int64        `json:"last_ts"`
	Domains      int64        `json:"domains"`
	AvgElapsedMS float64      `json:"avg_elapsed_ms"`
	ByAction     []GroupStat  `json:"by_action"`
	ByList       []ListStat   `json:"by_list"`
	ByQType      []GroupStat  `json:"by_qtype"`
	ByRcode      []GroupStat  `json:"by_rcode"`
	TopDomains   []DomainStat `json:"top_domains"`
	ByDay        []DayStat    `json:"by_day"`

	// 来源维度分布（来源类型 / 接入协议 / 接入方式）与 Top 客户端来源
	BySourceKind []GroupStat  `json:"by_source_kind"`
	ByProtocol   []GroupStat  `json:"by_protocol"`
	ByVia        []GroupStat  `json:"by_via"`
	TopClients   []ClientStat `json:"top_clients"`

	// 超时口径：elapsed_ms >= TimeoutMS 的记录视作超时，不计入任何平均耗时，
	// 单独汇总为 Timeouts / TimeoutAvgElapsedMS（TimeoutMS 为 0 表示未判定）
	TimeoutMS           int64   `json:"timeout_ms"`
	Timeouts            int64   `json:"timeouts"`
	TimeoutAvgElapsedMS float64 `json:"timeout_avg_elapsed_ms"`
}

// Options 存储选项（由配置热更新）
type Options struct {
	Enabled   bool
	Retention time.Duration
	MaxRows   int
}

// Filter 查询条件（零值表示不限）
type Filter struct {
	Keyword    string // 模糊匹配域名/应答/客户端/列表名/DNS
	Action     string
	QType      string
	Client     string // 精确客户端 IP 或 CIDR 网段
	Protocol   string // 接入协议 UDP/TCP/DoT/DoH/DoH3
	SourceKind string // 来源类型 outer/inner/unknown
	Via        string // 接入方式 proxy/direct
	ClientISP  string // 运营商归属 telecom/unicom/cmcc/...（空为不限）
	Start      int64  // Unix 秒
	End        int64
	Limit      int
	Offset     int
}

// Store 解析日志存储
type Store struct {
	db     *sql.DB
	logger *utils.EnhancedLogger

	ch        chan Entry
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once

	optMu sync.RWMutex
	opt   Options

	dropped atomic.Int64
	written atomic.Int64
}

// Open 打开（必要时创建）解析日志库并启动后台写入与清理任务
func Open(path string, logger *utils.EnhancedLogger, opt Options) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建解析日志目录失败: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开解析日志库失败: %w", err)
	}
	// 单写者模型：单连接避免 database is locked
	db.SetMaxOpenConns(1)

	s := &Store{
		db:     db,
		logger: logger,
		ch:     make(chan Entry, queueSize),
		done:   make(chan struct{}),
		opt:    normalizeOptions(opt),
	}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	s.wg.Add(2)
	go s.writeLoop()
	go s.pruneLoop()
	return s, nil
}

// initSchema 初始化表结构与索引，并开启 WAL
func (s *Store) initSchema() error {
	// WAL 降低写入对读取的阻塞；NORMAL 在 WAL 下已足够安全且写入更快
	pragmas := `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`
	if _, err := s.db.Exec(pragmas); err != nil {
		return fmt.Errorf("初始化解析日志库参数失败: %w", err)
	}

	schema := `
CREATE TABLE IF NOT EXISTS query_logs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	ts            INTEGER NOT NULL,
	domain        TEXT NOT NULL,
	qtype         TEXT NOT NULL,
	client        TEXT NOT NULL DEFAULT '',
	client_isp    TEXT NOT NULL DEFAULT '',
	protocol      TEXT NOT NULL DEFAULT '',
	source_kind   TEXT NOT NULL DEFAULT '',
	via           TEXT NOT NULL DEFAULT '',
	client_ip_num INTEGER NOT NULL DEFAULT 0,
	action        TEXT NOT NULL,
	list_name     TEXT NOT NULL DEFAULT '',
	dns           TEXT NOT NULL DEFAULT '',
	dns_mode      TEXT NOT NULL DEFAULT '',
	ecs           TEXT NOT NULL DEFAULT '',
	rcode         TEXT NOT NULL DEFAULT '',
	answers       TEXT NOT NULL DEFAULT '',
	elapsed_ms    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_query_logs_ts ON query_logs(ts);
CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("初始化解析日志表结构失败: %w", err)
	}

	// 兼容旧库：为缺失的来源维度列补列（已存在时忽略 duplicate column 错误）
	for _, ddl := range []string{
		`ALTER TABLE query_logs ADD COLUMN client_isp TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE query_logs ADD COLUMN protocol TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE query_logs ADD COLUMN source_kind TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE query_logs ADD COLUMN via TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE query_logs ADD COLUMN client_ip_num INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("迁移解析日志表结构失败: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_query_logs_ip ON query_logs(client_ip_num)`); err != nil {
		return fmt.Errorf("初始化解析日志索引失败: %w", err)
	}
	return nil
}

// normalizeOptions 补齐缺省保留策略
func normalizeOptions(opt Options) Options {
	if opt.Retention <= 0 {
		opt.Retention = DefaultRetention
	}
	if opt.MaxRows <= 0 {
		opt.MaxRows = DefaultMaxRows
	}
	return opt
}

// UpdateOptions 热更新选项（配置保存后调用）
func (s *Store) UpdateOptions(opt Options) {
	s.optMu.Lock()
	s.opt = normalizeOptions(opt)
	s.optMu.Unlock()
}

// Options 返回当前选项
func (s *Store) Options() Options {
	s.optMu.RLock()
	defer s.optMu.RUnlock()
	return s.opt
}

// Enabled 是否记录日志
func (s *Store) Enabled() bool {
	s.optMu.RLock()
	defer s.optMu.RUnlock()
	return s.opt.Enabled
}

// Append 异步追加一条日志（不阻塞调用方；关闭/打满时丢弃并计数）
func (s *Store) Append(e Entry) {
	if !s.Enabled() {
		return
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Stats 运行状态（供管理端展示）
func (s *Store) Stats() map[string]interface{} {
	opt := s.Options()
	return map[string]interface{}{
		"enabled":           opt.Enabled,
		"retention_seconds": int64(opt.Retention.Seconds()),
		"max_rows":          opt.MaxRows,
		"written":           s.written.Load(),
		"dropped":           s.dropped.Load(),
		"queued":            len(s.ch),
	}
}

// Query 按条件分页查询（按时间倒序），返回结果与命中总数
func (s *Store) Query(f Filter) ([]Entry, int64, error) {
	where, args := buildWhere(f)

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_logs`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计解析日志失败: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > maxLimit {
		limit = maxLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(`SELECT id, ts, domain, qtype, client, client_isp, protocol, source_kind, via, action, list_name, dns, dns_mode, ecs, rcode, answers, elapsed_ms
		FROM query_logs`+where+` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询解析日志失败: %w", err)
	}
	defer rows.Close()

	list := make([]Entry, 0, limit)
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Time, &e.Domain, &e.QType, &e.Client, &e.ClientISP,
			&e.Protocol, &e.SourceKind, &e.Via, &e.Action,
			&e.ListName, &e.DNS, &e.DNSMode, &e.ECS, &e.Rcode, &e.Answers, &e.ElapsedMS); err != nil {
			return nil, 0, fmt.Errorf("读取解析日志失败: %w", err)
		}
		list = append(list, e)
	}
	return list, total, rows.Err()
}

// buildWhere 拼接条件与参数
func buildWhere(f Filter) (string, []interface{}) {
	var conds []string
	var args []interface{}

	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		like := "%" + kw + "%"
		conds = append(conds, `(domain LIKE ? OR answers LIKE ? OR client LIKE ? OR list_name LIKE ? OR dns LIKE ?)`)
		args = append(args, like, like, like, like, like)
	}
	if f.Action != "" {
		conds = append(conds, `action = ?`)
		args = append(args, f.Action)
	}
	if f.QType != "" {
		conds = append(conds, `qtype = ?`)
		args = append(args, f.QType)
	}
	if f.Protocol != "" {
		conds = append(conds, `protocol = ?`)
		args = append(args, f.Protocol)
	}
	if f.SourceKind != "" {
		conds = append(conds, `source_kind = ?`)
		args = append(args, f.SourceKind)
	}
	if f.Via != "" {
		conds = append(conds, `via = ?`)
		args = append(args, f.Via)
	}
	if f.ClientISP != "" {
		conds = append(conds, `client_isp = ?`)
		args = append(args, f.ClientISP)
	}
	if c := strings.TrimSpace(f.Client); c != "" {
		if cond, cargs, ok := clientCond(c); ok {
			conds = append(conds, cond)
			args = append(args, cargs...)
		} else {
			// 非法 IP / CIDR：不匹配任何记录（上层已做校验并返回 400）
			conds = append(conds, `1 = 0`)
		}
	}
	if f.Start > 0 {
		conds = append(conds, `ts >= ?`)
		args = append(args, f.Start)
	}
	if f.End > 0 {
		conds = append(conds, `ts <= ?`)
		args = append(args, f.End)
	}

	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// clientCond 生成客户端筛选条件：精确 IP 用等值匹配；IPv4 CIDR 用整数区间（走索引）；
// IPv6 CIDR 退化为前缀 LIKE。返回值 ok=false 表示输入非法。
func clientCond(c string) (string, []interface{}, bool) {
	if !strings.Contains(c, "/") {
		if _, err := netip.ParseAddr(c); err != nil {
			return "", nil, false
		}
		return `client = ?`, []interface{}{c}, true
	}
	pfx, err := netip.ParsePrefix(c)
	if err != nil {
		return "", nil, false
	}
	pfx = pfx.Masked()
	if pfx.Addr().Is4() {
		lo := ipv4ToUint32(pfx.Addr())
		hi := lo | (^uint32(0) >> uint(pfx.Bits()))
		return `client_ip_num BETWEEN ? AND ?`, []interface{}{int64(lo), int64(hi)}, true
	}
	if like := ipv6PrefixLike(pfx); like != "" {
		return `client LIKE ?`, []interface{}{like + "%"}, true
	}
	return `1 = 0`, nil, true
}

// ipv4ToUint32 IPv4 地址转无符号整数（用于 CIDR 区间筛选）
func ipv4ToUint32(ip netip.Addr) uint32 {
	b := ip.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ipv6PrefixLike 生成 IPv6 CIDR 的字符串前缀（按完整 16 位片段向下取整），用于退化的前缀 LIKE 匹配
func ipv6PrefixLike(p netip.Prefix) string {
	hextets := p.Bits() / 16
	if hextets <= 0 {
		return ""
	}
	parts := strings.Split(p.Addr().String(), ":")
	if hextets > len(parts) {
		hextets = len(parts)
	}
	return strings.Join(parts[:hextets], ":") + ":"
}

// Summary 聚合统计（topN 为 Top 域名条数，<=0 用默认值，超过上限按上限截断；
// timeoutMS 为超时判定阈值（毫秒），elapsed_ms >= 该值的记录不计入任何平均耗时，
// 单独汇总到 Timeouts；<=0 表示不判定超时）
func (s *Store) Summary(f Filter, topN int, timeoutMS int64) (*Summary, error) {
	where, args := buildWhere(f)
	sum := &Summary{
		ByAction:     []GroupStat{},
		ByList:       []ListStat{},
		ByQType:      []GroupStat{},
		ByRcode:      []GroupStat{},
		TopDomains:   []DomainStat{},
		ByDay:        []DayStat{},
		BySourceKind: []GroupStat{},
		ByProtocol:   []GroupStat{},
		ByVia:        []GroupStat{},
		TopClients:   []ClientStat{},
	}
	// 归一化阈值：不判定时取最大值，使 SQL 中的 </>= 条件自然退化为「全部计入 / 无超时」
	thr := timeoutMS
	if thr <= 0 {
		thr = math.MaxInt64
	} else {
		sum.TimeoutMS = timeoutMS
	}
	bargs := append([]interface{}{thr, thr, thr}, args...)

	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0),
		COALESCE(AVG(CASE WHEN elapsed_ms < ? THEN elapsed_ms END),0), COUNT(DISTINCT domain),
		COALESCE(SUM(CASE WHEN elapsed_ms >= ? THEN 1 ELSE 0 END),0),
		COALESCE(AVG(CASE WHEN elapsed_ms >= ? THEN elapsed_ms END),0) FROM query_logs`+where, bargs...).
		Scan(&sum.Total, &sum.FirstTS, &sum.LastTS, &sum.AvgElapsedMS, &sum.Domains,
			&sum.Timeouts, &sum.TimeoutAvgElapsedMS); err != nil {
		return nil, fmt.Errorf("统计汇总失败: %w", err)
	}
	if sum.Total == 0 {
		return sum, nil
	}

	var err error
	if sum.ByAction, err = s.groupStats("action", where, args, thr); err != nil {
		return nil, err
	}
	if sum.ByQType, err = s.groupStats("qtype", where, args, thr); err != nil {
		return nil, err
	}
	if sum.ByRcode, err = s.groupStats("rcode", where, args, thr); err != nil {
		return nil, err
	}
	if sum.ByList, err = s.listStats(where, args, thr); err != nil {
		return nil, err
	}
	if sum.BySourceKind, err = s.groupStats("source_kind", where, args, thr); err != nil {
		return nil, err
	}
	if sum.ByProtocol, err = s.groupStats("protocol", where, args, thr); err != nil {
		return nil, err
	}
	if sum.ByVia, err = s.groupStats("via", where, args, thr); err != nil {
		return nil, err
	}
	if sum.TopClients, err = s.clientStats(where, args, topN, thr); err != nil {
		return nil, err
	}
	if sum.TopDomains, err = s.topDomains(where, args, topN, thr); err != nil {
		return nil, err
	}
	if sum.ByDay, err = s.dailyStats(where, args, sum.FirstTS, sum.LastTS); err != nil {
		return nil, err
	}
	return sum, nil
}

// groupStats 按列聚合次数与平均耗时（col 仅由内部常量传入，不存在注入）
// 次数为全量，平均耗时剔除超时记录（elapsed_ms >= thr）
func (s *Store) groupStats(col, where string, args []interface{}, thr int64) ([]GroupStat, error) {
	rows, err := s.db.Query(`SELECT `+col+`, COUNT(*), COALESCE(AVG(CASE WHEN elapsed_ms < ? THEN elapsed_ms END),0)
		FROM query_logs`+where+` GROUP BY `+col+` ORDER BY COUNT(*) DESC, `+col+` ASC`,
		append([]interface{}{thr}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("统计 %s 分布失败: %w", col, err)
	}
	defer rows.Close()

	out := []GroupStat{}
	for rows.Next() {
		var g GroupStat
		if err := rows.Scan(&g.Key, &g.Count, &g.AvgElapsedMS); err != nil {
			return nil, fmt.Errorf("读取 %s 分布失败: %w", col, err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// listStats 分流列表命中统计：按列表汇总，并保留该列表内的来源构成
// 命中次数为全量，平均耗时剔除超时记录
func (s *Store) listStats(where string, args []interface{}, thr int64) ([]ListStat, error) {
	if where == "" {
		where = " WHERE list_name <> ''"
	} else {
		where += " AND list_name <> ''"
	}
	rows, err := s.db.Query(`SELECT list_name, action, COUNT(*),
		COALESCE(SUM(CASE WHEN elapsed_ms < ? THEN elapsed_ms END),0),
		COALESCE(SUM(CASE WHEN elapsed_ms < ? THEN 1 ELSE 0 END),0)
		FROM query_logs`+where+` GROUP BY list_name, action`,
		append([]interface{}{thr, thr}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("统计分流列表命中失败: %w", err)
	}
	defer rows.Close()

	byName := map[string]*ListStat{}
	sumMS := map[string]int64{}
	okMS := map[string]int64{} // 各列表内参与平均的记录数（已剔除超时）
	for rows.Next() {
		var name, action string
		var count, total, ok int64
		if err := rows.Scan(&name, &action, &count, &total, &ok); err != nil {
			return nil, fmt.Errorf("读取分流列表命中失败: %w", err)
		}
		ls, okName := byName[name]
		if !okName {
			ls = &ListStat{Name: name, Actions: []GroupStat{}}
			byName[name] = ls
		}
		ls.Count += count
		sumMS[name] += total
		okMS[name] += ok
		ls.Actions = append(ls.Actions, GroupStat{Key: action, Count: count, AvgElapsedMS: avgMS(total, ok)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ListStat, 0, len(byName))
	for _, ls := range byName {
		ls.AvgElapsedMS = avgMS(sumMS[ls.Name], okMS[ls.Name])
		sort.Slice(ls.Actions, func(i, j int) bool {
			if ls.Actions[i].Count != ls.Actions[j].Count {
				return ls.Actions[i].Count > ls.Actions[j].Count
			}
			return ls.Actions[i].Key < ls.Actions[j].Key
		})
		out = append(out, *ls)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// topDomains 查询量最高的域名，并附带其主导来源与主要命中的分流列表。
// 两个相关子查询自带分组且不带参数，故不影响 buildWhere 参数与 LIMIT 参数的顺序。
// 次数为全量，平均耗时剔除超时记录。
func (s *Store) topDomains(where string, args []interface{}, topN int, thr int64) ([]DomainStat, error) {
	if topN <= 0 {
		topN = defaultTopDomains
	}
	if topN > maxTopDomains {
		topN = maxTopDomains
	}
	qargs := append(append([]interface{}{thr}, args...), topN)

	rows, err := s.db.Query(`SELECT q.domain, COUNT(*),
		COALESCE(AVG(CASE WHEN q.elapsed_ms < ? THEN q.elapsed_ms END),0),
		(SELECT action FROM query_logs x WHERE x.domain = q.domain
			GROUP BY action ORDER BY COUNT(*) DESC, action ASC LIMIT 1),
		(SELECT list_name FROM query_logs y WHERE y.domain = q.domain AND list_name <> ''
			GROUP BY list_name ORDER BY COUNT(*) DESC, list_name ASC LIMIT 1)
		FROM query_logs q`+where+` GROUP BY q.domain ORDER BY COUNT(*) DESC, q.domain ASC LIMIT ?`, qargs...)
	if err != nil {
		return nil, fmt.Errorf("统计 Top 域名失败: %w", err)
	}
	defer rows.Close()

	out := []DomainStat{}
	for rows.Next() {
		var d DomainStat
		var action, listName sql.NullString
		if err := rows.Scan(&d.Domain, &d.Count, &d.AvgElapsedMS, &action, &listName); err != nil {
			return nil, fmt.Errorf("读取 Top 域名失败: %w", err)
		}
		d.Action, d.ListName = action.String, listName.String
		out = append(out, d)
	}
	return out, rows.Err()
}

// clientStats Top 客户端来源：按客户端 IP 聚合次数、平均耗时与主要来源路径，
// 并附客户端归属运营商与主要来源类型。次数为全量，平均耗时剔除超时记录。
// 相关子查询自带分组且不带参数，故不影响 buildWhere 参数与 LIMIT 参数的顺序。
func (s *Store) clientStats(where string, args []interface{}, topN int, thr int64) ([]ClientStat, error) {
	if topN <= 0 {
		topN = defaultTopClients
	}
	if topN > maxTopClients {
		topN = maxTopClients
	}
	// 仅统计有客户端 IP 的记录
	if where == "" {
		where = " WHERE client <> ''"
	} else {
		where += " AND client <> ''"
	}
	qargs := append(append([]interface{}{thr}, args...), topN)

	rows, err := s.db.Query(`SELECT q.client, MAX(q.client_isp), MAX(q.source_kind), COUNT(*),
		COALESCE(AVG(CASE WHEN q.elapsed_ms < ? THEN q.elapsed_ms END),0),
		(SELECT action FROM query_logs x WHERE x.client = q.client
			GROUP BY action ORDER BY COUNT(*) DESC, action ASC LIMIT 1)
		FROM query_logs q`+where+` GROUP BY q.client ORDER BY COUNT(*) DESC, q.client ASC LIMIT ?`, qargs...)
	if err != nil {
		return nil, fmt.Errorf("统计 Top 客户端来源失败: %w", err)
	}
	defer rows.Close()

	out := []ClientStat{}
	for rows.Next() {
		var c ClientStat
		var isp, kind, action sql.NullString
		if err := rows.Scan(&c.Client, &isp, &kind, &c.Count, &c.AvgElapsedMS, &action); err != nil {
			return nil, fmt.Errorf("读取 Top 客户端来源失败: %w", err)
		}
		c.ISP, c.SourceKind, c.Action = isp.String, kind.String, action.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// dailyStats 按本地自然日统计：SQL 只做小时分桶，再由 Go 按本地时区归并并补零，
// 避免 SQLite 'localtime' 与 Go 侧时区不一致导致日期错位。
func (s *Store) dailyStats(where string, args []interface{}, firstTS, lastTS int64) ([]DayStat, error) {
	rows, err := s.db.Query(`SELECT (ts/3600)*3600 AS h, COUNT(*) FROM query_logs`+
		where+` GROUP BY h ORDER BY h`, args...)
	if err != nil {
		return nil, fmt.Errorf("统计按天趋势失败: %w", err)
	}
	defer rows.Close()

	byDay := map[string]int64{}
	for rows.Next() {
		var hour, count int64
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("读取按天趋势失败: %w", err)
		}
		byDay[time.Unix(hour, 0).In(time.Local).Format(dayLayout)] += count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	first := time.Unix(firstTS, 0).In(time.Local)
	last := time.Unix(lastTS, 0).In(time.Local)
	start := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.Local)
	end := time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, time.Local)

	out := []DayStat{}
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		key := d.Format(dayLayout)
		out = append(out, DayStat{Day: key, Count: byDay[key]})
	}
	return out, nil
}

// avgMS 平均耗时（毫秒），count 为 0 时返回 0
func avgMS(total, count int64) float64 {
	if count == 0 {
		return 0
	}
	return float64(total) / float64(count)
}

// writeLoop 批量落库：攒够 batchSize 或到达 flushEvery 即写入
func (s *Store) writeLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	batch := make([]Entry, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insertBatch(batch); err != nil {
			s.logger.Error("❌ [解析日志写入失败] ", map[string]interface{}{
				"rule":  "QUERY_LOG_INSERT_FAILED",
				"count": len(batch),
				"error": err.Error(),
			})
		} else {
			s.written.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-s.ch:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			// 退出前把队列里剩余的日志落库，避免丢失
			for {
				select {
				case e := <-s.ch:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// insertBatch 单事务写入一批日志
func (s *Store) insertBatch(batch []Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO query_logs(ts, domain, qtype, client, client_isp, protocol, source_kind, via, client_ip_num, action, list_name, dns, dns_mode, ecs, rcode, answers, elapsed_ms)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.Exec(e.Time, e.Domain, e.QType, e.Client, e.ClientISP,
			e.Protocol, e.SourceKind, e.Via, clientIPNum(e.Client), e.Action,
			e.ListName, e.DNS, e.DNSMode, e.ECS, e.Rcode, e.Answers, e.ElapsedMS); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// clientIPNum 归一化客户端 IP 的 IPv4 整数形式（IPv6 或非法值记 0），用于 CIDR 区间筛选
func clientIPNum(client string) int64 {
	ip, err := netip.ParseAddr(client)
	if err != nil || !ip.Is4() {
		return 0
	}
	return int64(ipv4ToUint32(ip))
}

// pruneLoop 周期性清理超期与超量日志
func (s *Store) pruneLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(pruneEvery)
	defer ticker.Stop()

	s.prune()
	for {
		select {
		case <-ticker.C:
			s.prune()
		case <-s.done:
			return
		}
	}
}

// prune 按保留时长删除超期记录，再按条数上限删除最旧记录
func (s *Store) prune() {
	opt := s.Options()

	if opt.Retention > 0 {
		cutoff := time.Now().Add(-opt.Retention).Unix()
		if res, err := s.db.Exec(`DELETE FROM query_logs WHERE ts < ?`, cutoff); err != nil {
			s.logger.Warn("⚠️ [解析日志超期清理失败] ", map[string]interface{}{
				"rule":  "QUERY_LOG_PRUNE_FAILED",
				"error": err.Error(),
			})
		} else if n, _ := res.RowsAffected(); n > 0 {
			s.logger.Info("🧹 [解析日志已按保留时长清理] ", map[string]interface{}{
				"rule":        "QUERY_LOG_PRUNED_BY_AGE",
				"deleted":     n,
				"retention_s": int64(opt.Retention.Seconds()),
			})
		}
	}

	if opt.MaxRows <= 0 {
		return
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_logs`).Scan(&total); err != nil {
		return
	}
	excess := total - int64(opt.MaxRows)
	if excess <= 0 {
		return
	}
	if excess > pruneLimit {
		excess = pruneLimit
	}
	if res, err := s.db.Exec(`DELETE FROM query_logs WHERE id IN (SELECT id FROM query_logs ORDER BY id ASC LIMIT ?)`, excess); err != nil {
		s.logger.Warn("⚠️ [解析日志超量清理失败] ", map[string]interface{}{
			"rule":  "QUERY_LOG_PRUNE_FAILED",
			"error": err.Error(),
		})
	} else if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("🧹 [解析日志已按条数上限清理] ", map[string]interface{}{
			"rule":     "QUERY_LOG_PRUNED_BY_ROWS",
			"deleted":  n,
			"max_rows": opt.MaxRows,
		})
	}
}

// Close 停止后台任务并落库剩余日志后关闭库
func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	s.wg.Wait()
	return s.db.Close()
}
