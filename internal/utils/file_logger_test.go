package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CleanupOldLogs 应按日期删除过期日志、保留当天与保留期内日志、忽略非标准命名文件
func TestFileLoggerCleanupOldLogs(t *testing.T) {
	dir := t.TempDir()
	fl, err := NewFileLogger(dir)
	if err != nil {
		t.Fatalf("NewFileLogger 失败: %v", err)
	}
	defer fl.Close()

	today := time.Now().Format("2006-01-02")
	oldDay := time.Now().AddDate(0, 0, -10).Format("2006-01-02")
	files := map[string]bool{
		"dns-proxy-" + today + ".log":  true, // 当天文件
		"dns-proxy-" + oldDay + ".log": true, // 10 天前 → 应删除
		"dns-proxy-2026-10-01.log":     true, // 过期 → 应删除
		"dns-proxy-notadate.log":       true, // 非标准命名 → 保留
		"other-file.txt":               true, // 非 dns-proxy 前缀 → 保留
	}
	for name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatalf("写文件失败 %s: %v", name, err)
		}
	}

	if err := fl.CleanupOldLogs(7); err != nil {
		t.Fatalf("CleanupOldLogs 失败: %v", err)
	}

	remain, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatalf("Glob 失败: %v", err)
	}
	got := map[string]bool{}
	for _, p := range remain {
		got[filepath.Base(p)] = true
	}

	for _, want := range []string{
		"dns-proxy-" + today + ".log",
		"dns-proxy-notadate.log",
		"other-file.txt",
	} {
		if !got[want] {
			t.Errorf("应保留 %s，实际被删除", want)
		}
	}
	for _, gone := range []string{
		"dns-proxy-" + oldDay + ".log",
		"dns-proxy-2026-10-01.log",
	} {
		if got[gone] {
			t.Errorf("应删除 %s，实际仍存在", gone)
		}
	}
}
