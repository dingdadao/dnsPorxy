package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/dns"
	"dnsPorxy/internal/querylog"
	"dnsPorxy/internal/utils"
)

// newTestAPIServer 构造测试用API服务器（临时目录 + 临时数据库 + nil handler）
func newTestAPIServer(t *testing.T) *Server {
	t.Helper()
	origWd, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir失败: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origWd) })

	store, err := config.OpenStore("test.db")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	logger := utils.NewEnhancedLogger("error", "test", false)
	return NewServer(store, logger, func() *dns.RefactoredHandler { return nil }, func() *dns.CertStore { return nil }, nil, nil)
}

// doJSON 执行请求并返回记录器
func doJSON(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func TestGetConfigAPI(t *testing.T) {
	s := newTestAPIServer(t)
	rec := doJSON(s, "GET", "/api/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d, 期望200", rec.Code)
	}
	var resp struct {
		Config struct {
			ListenPort int    `json:"listen_port"`
			LogLevel   string `json:"log_level"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Config.ListenPort != 53 || resp.Config.LogLevel == "" {
		t.Errorf("配置内容错误: %+v", resp.Config)
	}
}

func TestIndexPage(t *testing.T) {
	s := newTestAPIServer(t)
	rec := doJSON(s, "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d, 期望200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type错误: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "域名篡改") {
		t.Error("页面缺少域名篡改入口")
	}
}

func TestPutConfigAPI(t *testing.T) {
	s := newTestAPIServer(t)

	// 合法保存（nil handler → restart_required=true 分支）
	rec := doJSON(s, "PUT", "/api/config", `{"listen_port":5354,"upstream":["udp://223.5.5.5:53"]}`)
	var resp struct {
		Ok              bool `json:"ok"`
		RestartRequired bool `json:"restart_required"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !resp.Ok || !resp.RestartRequired {
		t.Errorf("合法保存错误: code=%d resp=%s", rec.Code, rec.Body.String())
	}

	// 非法JSON → 400
	if rec := doJSON(s, "PUT", "/api/config", `{bad`); rec.Code != http.StatusBadRequest {
		t.Errorf("非法JSON: code=%d, 期望400", rec.Code)
	}
	// 非法时长 → 400
	if rec := doJSON(s, "PUT", "/api/config", `{"listen_port":5354,"upstream":["udp://1.1.1.1:53"],"timeout":"abc"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("非法时长: code=%d, 期望400", rec.Code)
	}
	// 空上游 → 400
	if rec := doJSON(s, "PUT", "/api/config", `{"listen_port":5354,"upstream":[]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("空上游: code=%d, 期望400", rec.Code)
	}
	// 非法端口 → 400
	if rec := doJSON(s, "PUT", "/api/config", `{"listen_port":70000,"upstream":["udp://1.1.1.1:53"]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("非法端口: code=%d, 期望400", rec.Code)
	}
}

func TestRestartAPI(t *testing.T) {
	// nil restart → 500
	s := newTestAPIServer(t)
	if rec := doJSON(s, "POST", "/api/restart", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("nil restart应500: code=%d", rec.Code)
	}

	// 注入重启回调 → 200 并带 process_restart / web_addr_changed / web_addr
	called := false
	s.restart = func() (RestartOutcome, error) {
		called = true
		return RestartOutcome{ProcessRestart: true, WebAddrChanged: true, WebAddr: ":80"}, nil
	}
	rec := doJSON(s, "POST", "/api/restart", "")
	var resp struct {
		Ok             bool   `json:"ok"`
		ProcessRestart bool   `json:"process_restart"`
		WebAddrChanged bool   `json:"web_addr_changed"`
		WebAddr        string `json:"web_addr"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !called || !resp.Ok || !resp.ProcessRestart || !resp.WebAddrChanged || resp.WebAddr != ":80" {
		t.Errorf("重启接口错误: code=%d called=%v resp=%s", rec.Code, called, rec.Body.String())
	}
}

func TestRefreshSplitListAPI(t *testing.T) {
	s := newTestAPIServer(t)

	// 非法序号 → 400
	if rec := doJSON(s, "POST", "/api/lists/abc/refresh", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("非法序号应400: code=%d", rec.Code)
	}
	// 越界序号 → 400
	if rec := doJSON(s, "POST", "/api/lists/99/refresh", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("越界序号应400: code=%d", rec.Code)
	}

	// 默认配置第 0 条列表已配置 URL，但 nil handler → 500
	if rec := doJSON(s, "POST", "/api/lists/0/refresh", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("nil handler应500: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 清空 URL 后 → 400（URL 校验先于 handler 调用）
	cfg, err := s.store.LoadConfig()
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if len(cfg.SplitLists) == 0 {
		t.Fatal("默认配置应含分流列表")
	}
	cfg.SplitLists[0].DomainURL = ""
	if err := s.store.SaveConfig(cfg); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	if rec := doJSON(s, "POST", "/api/lists/0/refresh", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("未配置URL应400: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOverridesAPI(t *testing.T) {
	s := newTestAPIServer(t)

	// 空列表
	rec := doJSON(s, "GET", "/api/overrides", "")
	var list struct {
		Overrides []*config.Override `json:"overrides"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != http.StatusOK || len(list.Overrides) != 0 {
		t.Errorf("空列表错误: code=%d n=%d", rec.Code, len(list.Overrides))
	}

	// 非法值先于handler校验 → 400
	cases := []string{
		`{"domain":"x.com","qtype":"A","value":"999.1.1.1","ttl":60,"enabled":true}`,
		`{"domain":"x.com","qtype":"AAAA","value":"1.2.3.4","ttl":60,"enabled":true}`,
		`{"domain":"x.com","qtype":"TXT","value":"v","ttl":60,"enabled":true}`,
		`{"domain":"","qtype":"A","value":"1.2.3.4","ttl":60,"enabled":true}`,
	}
	for _, body := range cases {
		if rec := doJSON(s, "POST", "/api/overrides", body); rec.Code != http.StatusBadRequest {
			t.Errorf("非法记录应400: body=%s code=%d", body, rec.Code)
		}
	}

	// 合法新增：nil handler下规则仍入库但热重载失败 → 500
	rec = doJSON(s, "POST", "/api/overrides", `{"domain":"a.com","qtype":"A","value":"1.2.3.4","ttl":60,"enabled":true}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("nil handler新增应500: code=%d", rec.Code)
	}
	// 但记录必须已持久化
	saved, _ := s.store.ListOverrides()
	if len(saved) != 1 || saved[0].Domain != "a.com" {
		t.Errorf("记录未持久化: %+v", saved)
	}

	// 更新/删除不存在的记录 → 500
	if rec := doJSON(s, "PUT", "/api/overrides/9999", `{"domain":"a.com","qtype":"A","value":"2.2.2.2","ttl":60,"enabled":true}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("更新不存在记录应500: code=%d", rec.Code)
	}
	if rec := doJSON(s, "DELETE", "/api/overrides/9999", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("删除不存在记录应500: code=%d", rec.Code)
	}
	// 非法ID → 400
	if rec := doJSON(s, "DELETE", "/api/overrides/abc", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("非法ID应400: code=%d", rec.Code)
	}
}

// logsResp 解析日志接口响应
type logsResp struct {
	Logs []struct {
		Domain   string `json:"domain"`
		Action   string `json:"action"`
		ListName string `json:"list_name"`
		DNSMode  string `json:"dns_mode"`
		Rcode    string `json:"rcode"`
	} `json:"logs"`
	Total  int64                  `json:"total"`
	Limit  int                    `json:"limit"`
	Offset int                    `json:"offset"`
	Stats  map[string]interface{} `json:"stats"`
}

func TestQueryLogsAPI(t *testing.T) {
	s := newTestAPIServer(t)

	// 未装配日志库 → 500
	if rec := doJSON(s, "GET", "/api/logs", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("日志库不可用应返回500，实际 %d", rec.Code)
	}

	qlog, err := querylog.Open(filepath.Join(t.TempDir(), "query_log.db"),
		utils.NewEnhancedLogger("error", "test", false), querylog.Options{Enabled: true})
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	t.Cleanup(func() { qlog.Close() })
	s.queryLog = qlog

	qlog.Append(querylog.Entry{Domain: "a.example.com", QType: "A", Action: querylog.ActionSplit,
		ListName: "定向域名", DNSMode: "race", Rcode: "NOERROR", Answers: "A 1.1.1.1"})
	qlog.Append(querylog.Entry{Domain: "b.example.com", QType: "AAAA", Action: querylog.ActionOverride,
		Rcode: "NOERROR", Answers: "AAAA ::1"})

	// 等待后台批量落库
	var first logsResp
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := doJSON(s, "GET", "/api/logs", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("查询失败: code=%d body=%s", rec.Code, rec.Body.String())
		}
		json.Unmarshal(rec.Body.Bytes(), &first)
		if first.Total == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if first.Total != 2 || len(first.Logs) != 2 {
		t.Fatalf("期望 2 条，实际 total=%d len=%d", first.Total, len(first.Logs))
	}
	// 时间倒序：后写入的在最前
	if first.Logs[0].Domain != "b.example.com" || first.Logs[0].Action != querylog.ActionOverride {
		t.Errorf("倒序或字段异常: %+v", first.Logs[0])
	}
	if first.Stats["enabled"] != true {
		t.Errorf("stats 应含 enabled=true，实际 %v", first.Stats)
	}

	// 关键字 / 来源筛选
	if rec := doJSON(s, "GET", "/api/logs?q=1.1.1.1", ""); rec.Code != http.StatusOK {
		t.Errorf("关键字查询失败: code=%d", rec.Code)
	} else {
		var r logsResp
		json.Unmarshal(rec.Body.Bytes(), &r)
		if r.Total != 1 || len(r.Logs) != 1 || r.Logs[0].ListName != "定向域名" {
			t.Errorf("关键字筛选异常: total=%d logs=%+v", r.Total, r.Logs)
		}
	}
	if rec := doJSON(s, "GET", "/api/logs?action=override", ""); rec.Code != http.StatusOK {
		t.Errorf("来源查询失败: code=%d", rec.Code)
	} else {
		var r logsResp
		json.Unmarshal(rec.Body.Bytes(), &r)
		if r.Total != 1 || r.Logs[0].Domain != "b.example.com" {
			t.Errorf("来源筛选异常: total=%d logs=%+v", r.Total, r.Logs)
		}
	}

	// 分页
	if rec := doJSON(s, "GET", "/api/logs?limit=1&offset=1", ""); rec.Code != http.StatusOK {
		t.Errorf("分页查询失败: code=%d", rec.Code)
	} else {
		var r logsResp
		json.Unmarshal(rec.Body.Bytes(), &r)
		if r.Total != 2 || len(r.Logs) != 1 || r.Logs[0].Domain != "a.example.com" {
			t.Errorf("分页异常: total=%d logs=%+v", r.Total, r.Logs)
		}
	}

	// 时间参数：Unix 秒与本地时间写法均可用，非法值 → 400
	if rec := doJSON(s, "GET", "/api/logs?start="+time.Now().Add(-time.Hour).Format("2006-01-02T15:04"), ""); rec.Code != http.StatusOK {
		t.Errorf("本地时间参数应可用: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(s, "GET", "/api/logs?start=not-a-time", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("非法时间应400: code=%d", rec.Code)
	}
}

func TestQueryLogStatsAPI(t *testing.T) {
	s := newTestAPIServer(t)

	// 未装配日志库 → 500
	if rec := doJSON(s, "GET", "/api/logs/stats", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("日志库不可用应返回500，实际 %d", rec.Code)
	}

	qlog, err := querylog.Open(filepath.Join(t.TempDir(), "query_log.db"),
		utils.NewEnhancedLogger("error", "test", false), querylog.Options{Enabled: true})
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	t.Cleanup(func() { qlog.Close() })
	s.queryLog = qlog

	// 非法时间 → 400（在装配日志库之后校验，否则先被 500 拦截）
	if rec := doJSON(s, "GET", "/api/logs/stats?start=not-a-time", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法时间应400，实际 %d", rec.Code)
	}

	qlog.Append(querylog.Entry{Domain: "a.example.com", QType: "A", Action: querylog.ActionSplit,
		ListName: "国外", Rcode: "NOERROR", ElapsedMS: 10})
	qlog.Append(querylog.Entry{Domain: "b.example.com", QType: "A", Action: querylog.ActionUpstream,
		Rcode: "NOERROR", ElapsedMS: 30})

	type statsResp struct {
		Summary struct {
			Total    int64 `json:"total"`
			Domains  int64 `json:"domains"`
			ByAction []struct {
				Key   string `json:"key"`
				Count int64  `json:"count"`
			} `json:"by_action"`
			ByList []struct {
				Name  string `json:"name"`
				Count int64  `json:"count"`
			} `json:"by_list"`
			TopDomains []struct {
				Domain string `json:"domain"`
			} `json:"top_domains"`
		} `json:"summary"`
		Stats map[string]interface{} `json:"stats"`
	}

	// 等待后台批量落库
	var got statsResp
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := doJSON(s, "GET", "/api/logs/stats", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("统计失败: code=%d body=%s", rec.Code, rec.Body.String())
		}
		json.Unmarshal(rec.Body.Bytes(), &got)
		if got.Summary.Total == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got.Summary.Total != 2 || got.Summary.Domains != 2 {
		t.Errorf("汇总错误: total=%d domains=%d", got.Summary.Total, got.Summary.Domains)
	}
	if len(got.Summary.ByAction) != 2 || len(got.Summary.ByList) != 1 || got.Summary.ByList[0].Name != "国外" {
		t.Errorf("分布错误: by_action=%+v by_list=%+v", got.Summary.ByAction, got.Summary.ByList)
	}
	if len(got.Summary.TopDomains) != 2 {
		t.Errorf("Top 域名条数错误: %d", len(got.Summary.TopDomains))
	}
	if got.Stats["enabled"] != true {
		t.Errorf("stats 应含 enabled=true，实际 %v", got.Stats)
	}

	// top 参数限制 Top 域名条数
	rec := doJSON(s, "GET", "/api/logs/stats?top=1", "")
	var one statsResp
	json.Unmarshal(rec.Body.Bytes(), &one)
	if rec.Code != http.StatusOK || len(one.Summary.TopDomains) != 1 {
		t.Errorf("top=1 应只返回 1 条: code=%d n=%d", rec.Code, len(one.Summary.TopDomains))
	}
}
