package config

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenStore失败: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreConfigRoundTrip(t *testing.T) {
	store := newTestStore(t)

	// 首次加载应返回默认值
	cfg, err := store.LoadConfig()
	if err != nil {
		t.Fatalf("首次LoadConfig失败: %v", err)
	}
	def := DefaultConfig()
	if cfg.ListenPort != def.ListenPort || cfg.Cache.TTL != def.Cache.TTL {
		t.Errorf("首次加载应返回默认配置: port=%d ttl=%v", cfg.ListenPort, cfg.Cache.TTL)
	}

	// 修改后保存再加载，验证round trip
	cfg.ReplaceCacheTime = 45 * time.Minute
	cfg.Upstream = []string{"udp://8.8.8.8:53", "https://dns.google/dns-query"}
	cfg.EnableAWSCheck = true
	cfg.Cache.MaxItems = 12345
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig失败: %v", err)
	}

	got, err := store.LoadConfig()
	if err != nil {
		t.Fatalf("二次LoadConfig失败: %v", err)
	}
	if got.ReplaceCacheTime != 45*time.Minute {
		t.Errorf("ReplaceCacheTime round trip失败: %v", got.ReplaceCacheTime)
	}
	if len(got.Upstream) != 2 || got.Upstream[0] != "udp://8.8.8.8:53" {
		t.Errorf("Upstream round trip失败: %v", got.Upstream)
	}
	if !got.EnableAWSCheck || got.Cache.MaxItems != 12345 {
		t.Errorf("标量字段round trip失败: aws=%v maxItems=%d", got.EnableAWSCheck, got.Cache.MaxItems)
	}
}

func TestStoreConfigJSONDuration(t *testing.T) {
	// 时长字符串解析与错误提示
	j := &ConfigJSON{Timeout: "abc"}
	if _, err := j.ToConfig(); err == nil {
		t.Error("非法时长字符串应报错")
	}
	// 空字符串回退默认值
	j = &ConfigJSON{Timeout: "", Cache: CacheJSON{TTL: ""}}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("空时长应回退默认: %v", err)
	}
	if cfg.Timeout != DefaultConfig().Timeout {
		t.Errorf("空Timeout应回退默认值: %v", cfg.Timeout)
	}
}

func TestStoreOverridesCRUD(t *testing.T) {
	store := newTestStore(t)

	// 新增
	id1, err := store.AddOverride(&Override{Domain: "a.com", QType: "A", Value: "1.1.1.1", TTL: 60, Enabled: true})
	if err != nil || id1 <= 0 {
		t.Fatalf("AddOverride失败: id=%d err=%v", id1, err)
	}
	id2, _ := store.AddOverride(&Override{Domain: ".b.com", QType: "CNAME", Value: "t.com", TTL: 0, Enabled: false})

	// 查询
	list, err := store.ListOverrides()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListOverride失败: n=%d err=%v", len(list), err)
	}
	if list[0].ID != id1 || !list[0].Enabled || list[1].ID != id2 || list[1].Enabled {
		t.Errorf("记录内容错误: %+v", list)
	}

	// 更新（含启用切换）
	if err := store.UpdateOverride(&Override{ID: id1, Domain: "a.com", QType: "A", Value: "2.2.2.2", TTL: 120, Enabled: false}); err != nil {
		t.Fatalf("UpdateOverride失败: %v", err)
	}
	list, _ = store.ListOverrides()
	if list[0].Value != "2.2.2.2" || list[0].TTL != 120 || list[0].Enabled {
		t.Errorf("更新未生效: %+v", list[0])
	}

	// 删除
	if err := store.DeleteOverride(id2); err != nil {
		t.Fatalf("DeleteOverride失败: %v", err)
	}
	list, _ = store.ListOverrides()
	if len(list) != 1 {
		t.Fatalf("删除后应剩1条: %d", len(list))
	}

	// 操作不存在的记录应报错
	if err := store.UpdateOverride(&Override{ID: 9999, Domain: "x", QType: "A", Value: "1.1.1.1", TTL: 60, Enabled: true}); err == nil {
		t.Error("更新不存在的记录应报错")
	}
	if err := store.DeleteOverride(9999); err == nil {
		t.Error("删除不存在的记录应报错")
	}
}

func TestValidateConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("默认配置应通过校验: %v", err)
	}
	cfg.ListenPort = 70000
	if err := ValidateConfig(cfg); err == nil {
		t.Error("非法端口应报错")
	}
	cfg = DefaultConfig()
	cfg.Upstream = nil
	if err := ValidateConfig(cfg); err == nil {
		t.Error("空上游应报错")
	}
	// 缺省值自动补齐
	cfg = &Config{ListenPort: 53, Upstream: []string{"udp://1.1.1.1:53"}}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("校验失败: %v", err)
	}
	// MaxItems 0 表示不设条数硬上限（容量交给 MemoryBudget 自适应），属合法值；
	// 需要校验的是 WebAddr 与内存预算这类真正有默认值的字段。
	if cfg.Cache.MaxItems != 0 || cfg.WebAddr != DefaultWebAddr {
		t.Errorf("缺省值未补齐: %+v", cfg.Cache)
	}
	if cfg.Cache.MemoryBudget != DefaultConfig().Cache.MemoryBudget {
		t.Errorf("内存预算未补默认值: %d", cfg.Cache.MemoryBudget)
	}
}
