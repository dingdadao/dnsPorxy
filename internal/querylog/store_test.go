package querylog

import (
	"path/filepath"
	"testing"
	"time"

	"dnsPorxy/internal/utils"
)

func testLogger() *utils.EnhancedLogger {
	return utils.NewEnhancedLogger("error", "test", false)
}

// openTestStore 打开临时库并确保关闭
func openTestStore(t *testing.T, opt Options) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "query_log.db"), testLogger(), opt)
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// waitWritten 等待后台批量写入把指定条数落库
func waitWritten(t *testing.T, s *Store, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats()["written"].(int64) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待落库超时：期望 %d 条，实际 %v", want, s.Stats()["written"])
}

func sampleEntries() []Entry {
	now := time.Now().Unix()
	return []Entry{
		{Time: now - 300, Domain: "a.example.com", QType: "A", Client: "10.0.0.1:5353",
			Action: ActionSplit, ListName: "定向域名", DNS: "https://223.6.6.6/dns-query", DNSMode: "race",
			Rcode: "NOERROR", Answers: "A 1.1.1.1", ElapsedMS: 12},
		{Time: now - 200, Domain: "b.example.com", QType: "AAAA", Client: "10.0.0.2:5353",
			Action: ActionUpstream, DNS: "udp://8.8.8.8:53", Rcode: "NOERROR", Answers: "AAAA ::1", ElapsedMS: 30},
		{Time: now - 100, Domain: "c.example.com", QType: "A", Client: "10.0.0.3:5353",
			Action: ActionOverride, Rcode: "NOERROR", Answers: "A 127.0.0.1", ElapsedMS: 0},
	}
}

func TestAppendAndQuery(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	for _, e := range sampleEntries() {
		s.Append(e)
	}
	waitWritten(t, s, 3)

	all, total, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("期望 3 条，实际 total=%d len=%d", total, len(all))
	}
	// 默认按时间倒序
	if all[0].Domain != "c.example.com" {
		t.Errorf("应按时间倒序，首条为 %s", all[0].Domain)
	}
	// 字段完整性
	if all[0].Action != ActionOverride || all[0].Answers != "A 127.0.0.1" {
		t.Errorf("字段读取异常: %+v", all[0])
	}

	tests := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"关键字命中域名", Filter{Keyword: "b.example"}, 1},
		{"关键字命中应答", Filter{Keyword: "::1"}, 1},
		{"关键字命中列表名", Filter{Keyword: "定向域名"}, 1},
		{"关键字命中上游DNS", Filter{Keyword: "8.8.8.8"}, 1},
		{"按来源过滤", Filter{Action: ActionSplit}, 1},
		{"按类型过滤", Filter{QType: "A"}, 2},
		{"时间区间", Filter{Start: time.Now().Unix() - 250, End: time.Now().Unix()}, 2},
		{"组合无匹配", Filter{Action: ActionSplit, QType: "AAAA"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, n, err := s.Query(tc.filter)
			if err != nil {
				t.Fatalf("查询失败: %v", err)
			}
			if n != int64(tc.want) || len(rows) != tc.want {
				t.Errorf("期望 %d 条，实际 total=%d len=%d", tc.want, n, len(rows))
			}
		})
	}

	// 分页：limit/offset 与倒序保持一致
	page1, total1, err := s.Query(Filter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	page2, _, err := s.Query(Filter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if total1 != 3 || len(page1) != 2 || len(page2) != 1 {
		t.Fatalf("分页结果异常: total=%d page1=%d page2=%d", total1, len(page1), len(page2))
	}
	if page1[0].Domain == page2[0].Domain {
		t.Errorf("分页不应重复：%s", page1[0].Domain)
	}
}

func TestAppendDisabled(t *testing.T) {
	s := openTestStore(t, Options{Enabled: false})
	s.Append(Entry{Domain: "x.example.com", QType: "A", Action: ActionCache})
	time.Sleep(150 * time.Millisecond)

	if s.Enabled() {
		t.Fatal("应为关闭状态")
	}
	if n := s.Stats()["written"].(int64); n != 0 {
		t.Errorf("关闭时不应写入，实际 %d", n)
	}
	// 热开启后立即生效
	s.UpdateOptions(Options{Enabled: true})
	s.Append(Entry{Domain: "y.example.com", QType: "A", Action: ActionCache})
	waitWritten(t, s, 1)
}

func TestPruneByAgeAndRows(t *testing.T) {
	now := time.Now().Unix()

	t.Run("按保留时长清理", func(t *testing.T) {
		s := openTestStore(t, Options{Enabled: true, Retention: time.Hour, MaxRows: 1000})
		s.Append(Entry{Time: now - 7200, Domain: "old.example.com", QType: "A", Action: ActionCache})
		s.Append(Entry{Time: now - 60, Domain: "new.example.com", QType: "A", Action: ActionCache})
		waitWritten(t, s, 2)

		s.prune()
		rows, total, err := s.Query(Filter{})
		if err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Domain != "new.example.com" {
			t.Fatalf("超期记录应被清理，实际 %+v", rows)
		}
	})

	t.Run("按条数上限清理最旧", func(t *testing.T) {
		s := openTestStore(t, Options{Enabled: true, Retention: 100 * time.Hour, MaxRows: 2})
		for i, d := range []string{"d1", "d2", "d3", "d4"} {
			s.Append(Entry{Time: now - int64(400-i*100), Domain: d + ".example.com", QType: "A", Action: ActionCache})
		}
		waitWritten(t, s, 4)

		s.prune()
		rows, total, err := s.Query(Filter{})
		if err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("应保留 2 条，实际 %d", total)
		}
		// 保留的是最新的两条（d3/d4）
		if rows[0].Domain != "d4.example.com" || rows[1].Domain != "d3.example.com" {
			t.Errorf("应保留最新两条，实际 %s / %s", rows[0].Domain, rows[1].Domain)
		}
	})
}

func TestCloseFlushesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query_log.db")
	s, err := Open(path, testLogger(), Options{Enabled: true})
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	// 未等后台 flush 就关闭，Close 应把队列里剩余日志落库
	s.Append(Entry{Domain: "flush.example.com", QType: "A", Action: ActionError, Rcode: "SERVFAIL"})
	if err := s.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	s2, err := Open(path, testLogger(), Options{Enabled: true})
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	rows, total, err := s2.Query(Filter{Keyword: "flush.example.com"})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Rcode != "SERVFAIL" {
		t.Fatalf("关闭前应落库剩余日志，实际 total=%d rows=%+v", total, rows)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	opt := s.Options()
	if opt.Retention != DefaultRetention || opt.MaxRows != DefaultMaxRows {
		t.Errorf("缺省值应为 %v/%d，实际 %v/%d", DefaultRetention, DefaultMaxRows, opt.Retention, opt.MaxRows)
	}
}

// summaryEntries 跨两个本地自然日的样本：来源、列表、类型、结果均有区分度
func summaryEntries() ([]Entry, int64, int64, string, string) {
	today := time.Now()
	// 取本地正午构造，避免日界与夏令时导致的抖动
	d0 := time.Date(today.Year(), today.Month(), today.Day(), 12, 0, 0, 0, time.Local).AddDate(0, 0, -1).Unix()
	d1 := d0 + 86400
	day0 := time.Unix(d0, 0).In(time.Local).Format("2006-01-02")
	day1 := time.Unix(d1, 0).In(time.Local).Format("2006-01-02")
	return []Entry{
		{Time: d0, Domain: "a.example.com", QType: "A", Action: ActionSplit, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 10},
		{Time: d0 + 60, Domain: "a.example.com", QType: "A", Action: ActionFiltered, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 20},
		{Time: d1, Domain: "b.example.com", QType: "AAAA", Action: ActionSplit, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 30},
		{Time: d1 + 60, Domain: "b.example.com", QType: "A", Action: ActionCache, Rcode: "NOERROR", ElapsedMS: 1},
		{Time: d1 + 120, Domain: "c.example.com", QType: "A", Action: ActionUpstream, Rcode: "NXDOMAIN", ElapsedMS: 40},
	}, d0, d1 + 120, day0, day1
}

func TestSummary(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	entries, firstTS, lastTS, day0, day1 := summaryEntries()
	for _, e := range entries {
		s.Append(e)
	}
	waitWritten(t, s, int64(len(entries)))

	sum, err := s.Summary(Filter{}, 0, 0)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if sum.Total != 5 || sum.Domains != 3 {
		t.Fatalf("汇总错误: total=%d domains=%d", sum.Total, sum.Domains)
	}
	if sum.FirstTS != firstTS || sum.LastTS != lastTS {
		t.Errorf("统计窗口错误: %d~%d，期望 %d~%d", sum.FirstTS, sum.LastTS, firstTS, lastTS)
	}
	// 平均耗时 (10+20+30+1+40)/5 = 20.2
	if sum.AvgElapsedMS < 20.1 || sum.AvgElapsedMS > 20.3 {
		t.Errorf("平均耗时应约 20.2，实际 %v", sum.AvgElapsedMS)
	}

	// 来源分布：按次数降序
	if len(sum.ByAction) != 4 || sum.ByAction[0].Key != ActionSplit || sum.ByAction[0].Count != 2 {
		t.Errorf("来源分布错误: %+v", sum.ByAction)
	}

	// 分流列表命中：国外 3 次，来源构成 split 2 + filtered 1
	if len(sum.ByList) != 1 || sum.ByList[0].Name != "国外" || sum.ByList[0].Count != 3 {
		t.Fatalf("分流列表命中错误: %+v", sum.ByList)
	}
	if acts := sum.ByList[0].Actions; len(acts) != 2 ||
		acts[0].Key != ActionSplit || acts[0].Count != 2 || acts[0].AvgElapsedMS != 20 ||
		acts[1].Key != ActionFiltered || acts[1].Count != 1 {
		t.Errorf("列表来源构成错误: %+v", acts)
	}

	// Top 域名：a/b 各 2 次（并列按域名升序 → a 在前），c 1 次且无列表
	if len(sum.TopDomains) != 3 {
		t.Fatalf("Top 域名条数错误: %d", len(sum.TopDomains))
	}
	if sum.TopDomains[0].Domain != "a.example.com" || sum.TopDomains[0].Count != 2 || sum.TopDomains[0].ListName != "国外" {
		t.Errorf("Top 域名首条错误: %+v", sum.TopDomains[0])
	}
	if last := sum.TopDomains[2]; last.Domain != "c.example.com" || last.Action != ActionUpstream || last.ListName != "" {
		t.Errorf("Top 域名末条错误: %+v", last)
	}

	// 按天：本地自然日两天，缺口补零
	if len(sum.ByDay) != 2 || sum.ByDay[0].Day != day0 || sum.ByDay[1].Day != day1 ||
		sum.ByDay[0].Count != 2 || sum.ByDay[1].Count != 3 {
		t.Errorf("按天趋势错误: %+v", sum.ByDay)
	}

	// 结果与类型分布
	if len(sum.ByRcode) != 2 || sum.ByRcode[0].Key != "NOERROR" || sum.ByRcode[0].Count != 4 {
		t.Errorf("结果分布错误: %+v", sum.ByRcode)
	}
	if len(sum.ByQType) != 2 || sum.ByQType[0].Key != "A" || sum.ByQType[0].Count != 4 {
		t.Errorf("类型分布错误: %+v", sum.ByQType)
	}
}

func TestSummaryWithFilterAndTopLimit(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	entries, _, _, _, _ := summaryEntries()
	for _, e := range entries {
		s.Append(e)
	}
	waitWritten(t, s, int64(len(entries)))

	// 只看域名分流：total/列表命中/来源分布都应收窄
	sum, err := s.Summary(Filter{Action: ActionSplit}, 0, 0)
	if err != nil {
		t.Fatalf("按来源统计失败: %v", err)
	}
	if sum.Total != 2 || len(sum.ByAction) != 1 || sum.ByAction[0].Key != ActionSplit {
		t.Errorf("按来源过滤错误: total=%d by_action=%+v", sum.Total, sum.ByAction)
	}
	if len(sum.ByList) != 1 || sum.ByList[0].Count != 2 {
		t.Errorf("按来源过滤后列表命中错误: %+v", sum.ByList)
	}

	// Top 域名条数受 topN 限制
	limited, err := s.Summary(Filter{}, 1, 0)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if len(limited.TopDomains) != 1 {
		t.Errorf("topN=1 应只返回 1 条，实际 %d", len(limited.TopDomains))
	}
}

func TestSummaryEmpty(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	sum, err := s.Summary(Filter{}, 0, 0)
	if err != nil {
		t.Fatalf("空库统计不应报错: %v", err)
	}
	if sum.Total != 0 || sum.FirstTS != 0 || sum.LastTS != 0 || len(sum.ByDay) != 0 || len(sum.ByList) != 0 {
		t.Errorf("空库统计应全为空，实际 %+v", sum)
	}
}

// TestSummaryExcludesTimeout 超时记录（elapsed_ms >= 阈值）不计入任何平均耗时，单独汇总
func TestSummaryExcludesTimeout(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	now := time.Now().Unix()
	entries := []Entry{
		// 同列表下一条正常、一条超时，用于校验列表平均耗时只取正常那条
		{Time: now - 90, Domain: "fast.example.com", QType: "A", Action: ActionSplit, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 40},
		{Time: now - 80, Domain: "fast.example.com", QType: "A", Action: ActionSplit, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 60},
		{Time: now - 70, Domain: "slow.example.com", QType: "HTTPS", Action: ActionSplit, ListName: "国外", Rcode: "NOERROR", ElapsedMS: 2000},
		{Time: now - 60, Domain: "slow.example.com", QType: "PTR", Action: ActionError, Rcode: "SERVFAIL", ElapsedMS: 4000},
	}
	for _, e := range entries {
		s.Append(e)
	}
	waitWritten(t, s, int64(len(entries)))

	sum, err := s.Summary(Filter{}, 0, 1500)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if sum.TimeoutMS != 1500 {
		t.Errorf("阈值应为 1500，实际 %d", sum.TimeoutMS)
	}
	if sum.Timeouts != 2 || sum.TimeoutAvgElapsedMS != 3000 {
		t.Errorf("超时应为 2 条、平均 3000ms，实际 n=%d avg=%v", sum.Timeouts, sum.TimeoutAvgElapsedMS)
	}
	// 全量平均 (40+60+2000+4000)/4 = 1525 → 剔除超时后 (40+60)/2 = 50
	if sum.Total != 4 || sum.AvgElapsedMS != 50 {
		t.Errorf("平均耗时应剔除超时并为 50，实际 total=%d avg=%v", sum.Total, sum.AvgElapsedMS)
	}
	// 来源分布：次数仍为全量，平均耗时剔除超时后仅剩 0 条 → 0
	for _, g := range sum.ByAction {
		if g.Key == ActionSplit && (g.Count != 3 || g.AvgElapsedMS != 50) {
			t.Errorf("split 次数应为全量 3、平均应剔超时为 50，实际 %+v", g)
		}
		if g.Key == ActionError && (g.Count != 1 || g.AvgElapsedMS != 0) {
			t.Errorf("error 次数应为全量 1、平均应剔超时后为 0，实际 %+v", g)
		}
	}
	// 分流列表：命中 3 次，平均耗时只取两条正常记录的 50ms
	if len(sum.ByList) != 1 || sum.ByList[0].Count != 3 || sum.ByList[0].AvgElapsedMS != 50 {
		t.Errorf("列表命中应为 3 次、平均 50ms，实际 %+v", sum.ByList)
	}
	// Top 域名：按次数降序（fast 2 次在前），慢域名只保留其正常记录的耗时
	for _, d := range sum.TopDomains {
		if d.Domain == "slow.example.com" && d.Count != 2 {
			t.Errorf("slow 域名次数应为全量 2，实际 %+v", d)
		}
		if d.Domain == "fast.example.com" && d.AvgElapsedMS != 50 {
			t.Errorf("fast 域名平均应为 50ms，实际 %+v", d)
		}
	}
}

// TestSummaryNoTimeoutThreshold 校验不判定超时时（阈值 0）平均耗时保持全量口径
func TestSummaryNoTimeoutThreshold(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	s.Append(Entry{Time: time.Now().Unix(), Domain: "x.example.com", QType: "A", Action: ActionUpstream,
		Rcode: "NOERROR", ElapsedMS: 4000})
	waitWritten(t, s, 1)

	sum, err := s.Summary(Filter{}, 0, 0)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if sum.TimeoutMS != 0 || sum.Timeouts != 0 || sum.AvgElapsedMS != 4000 {
		t.Errorf("阈值 0 时不应判定超时且平均取全量，实际 %+v", sum)
	}
}
