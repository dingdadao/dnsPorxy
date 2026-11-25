package dns

import (
	"testing"

	"dnsPorxy/internal/utils"
)

// loadMatcherForBench 加载仓库内的真实规则文件：data/china_domains.yaml 是 3691 条精确域名，
// data/designated.yaml 是 183 条 DOMAIN-SUFFIX（旧的逐条 ToLower+HasSuffix 实现就是被它拖慢的）。
// 仅 -bench 时执行，常规 go test 不读取大文件。
func loadMatcherForBench(tb testing.TB) *YAMLMatcher {
	logger := utils.NewEnhancedLogger("error", "bench", false)
	m := NewYAMLMatcher(logger)
	m.SetDefaultDNS([]string{"udp://1.1.1.1:53"})
	if err := m.LoadYAMLConfig("../../data/china_domains.yaml"); err != nil {
		tb.Fatalf("load china: %v", err)
	}
	if err := m.LoadYAMLConfig("../../data/designated.yaml"); err != nil {
		tb.Fatalf("load designated: %v", err)
	}
	return m
}

func BenchmarkMatchDomainHitExact(b *testing.B) {
	m := loadMatcherForBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchDomain("www.qq.com")
	}
}

func BenchmarkMatchDomainMiss(b *testing.B) {
	m := loadMatcherForBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchDomain("not-in-list-abcdef.example")
	}
}
