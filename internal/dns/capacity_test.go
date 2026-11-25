package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCapacity_NoBudget 未启用预算时容量等于 hardMax
func TestCapacity_NoBudget(t *testing.T) {
	c := NewOptimizedDNSCache(5000, 5*time.Minute)
	c.SetMemoryBudget(0)
	if got := c.capacity(); got != 5000 {
		t.Fatalf("未启用预算时容量应为 hardMax=5000，实际 %d", got)
	}
}

// TestCapacity_Adaptive 启用预算后容量应由预算/平均条目大小决定（hardMax=0 表示不设条数上限）
func TestCapacity_Adaptive(t *testing.T) {
	c := NewOptimizedDNSCache(0, 5*time.Minute)

	// 先塞一些真实条目，让平均大小有意义
	for i := 0; i < 50; i++ {
		name := "fill" + itoa(uint32(i)) + ".example"
		c.Set("-", name, dns.TypeA, makeAResp(name, 300), false)
	}

	// 8MB 预算，单个 A 记录响应约 100~400 字节，容量应远超旧默认的 5000
	c.SetMemoryBudget(8 << 20)
	got := c.capacity()
	if got <= 5000 {
		t.Fatalf("预算自适应没有放大容量：%d（应远大于 5000）", got)
	}
	if got < minDynamicCapacity {
		t.Fatalf("容量不该低于下限 %d，实际 %d", minDynamicCapacity, got)
	}

	// 预算调到很小，容量应随之收缩
	c.SetMemoryBudget(64 << 10)
	if small := c.capacity(); small >= got {
		t.Fatalf("预算变小后容量应下降：%d -> %d", got, small)
	}
}

// TestCapacity_SmallBudget 预算很小时也应保留下限容量
func TestCapacity_SmallBudget(t *testing.T) {
	c := NewOptimizedDNSCache(5000, 5*time.Minute)
	c.SetMemoryBudget(64 << 10) // 64KB，极小
	if got := c.capacity(); got < minDynamicCapacity {
		t.Fatalf("小预算下容量应被兜到下限 %d，实际 %d", minDynamicCapacity, got)
	}
}

// TestCapacity_HardMaxWins hardMax 比预算反推值小时应以 hardMax 为准
func TestCapacity_HardMaxWins(t *testing.T) {
	c := NewOptimizedDNSCache(100, 5*time.Minute) // 硬上限只有 100
	c.SetMemoryBudget(64 << 20)
	if got := c.capacity(); got > 100 {
		t.Fatalf("hardMax=100 应当限制容量，实际 %d", got)
	}
}

// TestCapacity_DisabledNoHardLimit hardMax=0 且无预算时不崩
func TestCapacity_DisabledNoHardLimit(t *testing.T) {
	c := NewOptimizedDNSCache(0, 5*time.Minute)
	c.SetMemoryBudget(0)
	// 只要不出 panic / 除零即可
	_ = c.capacity()
}
