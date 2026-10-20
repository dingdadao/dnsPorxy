package dns

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"dnsPorxy/internal/utils"

	"gopkg.in/yaml.v3"
)

// YAMLMatcher YAML格式域名匹配器（支持mihomo风格规则）
// 每个域名分流列表对应一个实例，defaultDNS 即该列表配置的 DNS
type YAMLMatcher struct {
	logger *utils.EnhancedLogger
	mu     sync.RWMutex

	// 索引结构
	exactDomains map[string]string // 精确匹配：DOMAIN,example.com,dns
	suffixes     map[string]string // 后缀匹配：DOMAIN-SUFFIX,google.com,dns
	keywords     map[string]string // 关键字匹配：DOMAIN-KEYWORD,baidu,dns
	domains      map[string]string // 域名匹配：DOMAIN,example.com,dns
	regexRules   map[string]string // 正则匹配：DOMAIN-REGEX,pattern,dns
	defaultDNS   []string          // 本列表命中后使用的DNS服务器列表
}

// NewYAMLMatcher 创建YAML格式匹配器
func NewYAMLMatcher(logger *utils.EnhancedLogger) *YAMLMatcher {
	return &YAMLMatcher{
		logger:       logger,
		exactDomains: make(map[string]string),
		suffixes:     make(map[string]string),
		keywords:     make(map[string]string),
		domains:      make(map[string]string),
		regexRules:   make(map[string]string),
	}
}

// SetDefaultDNS 设置本列表命中后使用的DNS服务器列表
func (ym *YAMLMatcher) SetDefaultDNS(defaultDNS []string) {
	ym.mu.Lock()
	ym.defaultDNS = defaultDNS
	ym.mu.Unlock()
}

// RuleCount 返回本列表已加载的规则条数（用于取反列表的空清单保护）
func (ym *YAMLMatcher) RuleCount() int {
	ym.mu.RLock()
	defer ym.mu.RUnlock()
	return len(ym.exactDomains) + len(ym.domains) + len(ym.suffixes) +
		len(ym.keywords) + len(ym.regexRules)
}

// LoadYAMLConfig 从YAML配置加载域名规则
func (ym *YAMLMatcher) LoadYAMLConfig(configPath string) error {
	timer := ym.logger.StartTimer("load_yaml_config")
	defer timer.End()

	if configPath == "" {
		ym.logger.Warn("YAML配置文件路径为空")
		return nil
	}

	// 读取YAML文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取YAML配置文件失败: %w", err)
	}

	// 解析YAML
	var yamlConfig struct {
		Payload []string `yaml:"payload"`
	}

	err = yaml.Unmarshal(data, &yamlConfig)
	if err != nil {
		return fmt.Errorf("解析YAML配置失败: %w", err)
	}

	// 创建新的索引结构
	newExactDomains := make(map[string]string)
	newSuffixes := make(map[string]string)
	newKeywords := make(map[string]string)
	newDomains := make(map[string]string)
	newRegexRules := make(map[string]string) // 正则表达式规则

	var exactCount, suffixCount, keywordCount, domainCount, regexCount int

	// 批量解析和分类
	for _, rule := range yamlConfig.Payload {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}

		// 解析规则：空值表示沿用本列表的 DNS，匹配时再解析（保证改 DNS 可热更新）
		dnsServer := ""
		originalRulePattern := rule

		// 处理带有DNS指定的规则（格式：'DOMAIN,example.com,DNS' 或 'DOMAIN-SUFFIX,google.com,DNS'）
		if strings.Contains(rule, ",") {
			parts := strings.Split(rule, ",")
			if len(parts) >= 3 {
				dnsServer = strings.TrimSpace(parts[2])
				// default_dns 关键字等价于未指定，沿用本列表的 DNS
				if dnsServer == "default_dns" {
					dnsServer = ""
				}
			}
		}

		// rulePattern 用于类型识别，应该是规则类型+域名部分
		rulePattern := rule
		if strings.Contains(rule, ",") {
			parts := strings.Split(rule, ",")
			if len(parts) >= 2 {
				// 保留规则类型和域名部分，去掉DNS服务器部分
				rulePattern = strings.TrimSpace(parts[0] + "," + parts[1])
			}
		}

		// 根据规则类型分类
		switch {
		case strings.HasPrefix(originalRulePattern, "DOMAIN-SUFFIX,"):
			// DOMAIN-SUFFIX 规则：DOMAIN-SUFFIX,google.com
			pattern := strings.TrimPrefix(rulePattern, "DOMAIN-SUFFIX,")
			newSuffixes[pattern] = dnsServer
			suffixCount++
		case strings.HasPrefix(originalRulePattern, "DOMAIN-KEYWORD,"):
			// DOMAIN-KEYWORD 规则：DOMAIN-KEYWORD,baidu
			pattern := strings.TrimPrefix(rulePattern, "DOMAIN-KEYWORD,")
			newKeywords[pattern] = dnsServer
			keywordCount++
		case strings.HasPrefix(originalRulePattern, "DOMAIN-REGEX,"):
			// DOMAIN-REGEX 规则：DOMAIN-REGEX,pattern
			pattern := strings.TrimPrefix(rulePattern, "DOMAIN-REGEX,")
			newRegexRules[pattern] = dnsServer
			regexCount++
		case strings.HasPrefix(originalRulePattern, "DOMAIN,"):
			// DOMAIN 规则：DOMAIN,example.com
			pattern := strings.TrimPrefix(rulePattern, "DOMAIN,")
			newDomains[pattern] = dnsServer
			domainCount++
		case strings.HasPrefix(rule, "+."):
			// 通配符格式：+.example.com 等同于 DOMAIN-SUFFIX,example.com
			newSuffixes[strings.TrimPrefix(rule, "+.")] = dnsServer
			suffixCount++
		default:
			// 默认为精确匹配
			newExactDomains[rulePattern] = dnsServer
			exactCount++
		}
	}

	// 原子性更新索引结构
	ym.mu.Lock()
	ym.exactDomains = newExactDomains
	ym.suffixes = newSuffixes
	ym.keywords = newKeywords
	ym.domains = newDomains
	ym.regexRules = newRegexRules // 添加正则表达式规则
	ym.mu.Unlock()

	ym.logger.Info("🎯 YAML格式域名配置加载完成", map[string]interface{}{
		"file":          configPath,
		"total_count":   len(yamlConfig.Payload),
		"exact_count":   exactCount,
		"suffix_count":  suffixCount,
		"keyword_count": keywordCount,
		"domain_count":  domainCount,
		"regex_count":   regexCount,
	})

	return nil
}

// MatchDomain 判断域名是否命中本列表；命中则返回本条列表使用的DNS服务器列表
func (ym *YAMLMatcher) MatchDomain(domain string) ([]string, bool) {
	ym.mu.RLock()
	defer ym.mu.RUnlock()

	if len(ym.defaultDNS) == 0 {
		return nil, false
	}

	domainLower := strings.ToLower(domain)

	// 规则未显式指定 DNS 时沿用本列表的 DNS（延迟解析，便于热更新）
	resolve := func(dns string) []string {
		if dns == "" {
			return ym.defaultDNS
		}
		return []string{dns}
	}

	// 1. 精确匹配检查
	if dns, exists := ym.exactDomains[domainLower]; exists {
		return resolve(dns), true
	}

	// 2. DOMAIN 匹配检查
	if dns, exists := ym.domains[domainLower]; exists {
		return resolve(dns), true
	}

	// 3. 后缀匹配检查
	for suffix, dns := range ym.suffixes {
		if strings.HasSuffix(domainLower, "."+strings.ToLower(suffix)) || domainLower == strings.ToLower(suffix) {
			return resolve(dns), true
		}
	}

	// 4. 关键字匹配检查
	for keyword, dns := range ym.keywords {
		if strings.Contains(domainLower, strings.ToLower(keyword)) {
			return resolve(dns), true
		}
	}

	// 5. 正则表达式匹配检查
	for pattern, dns := range ym.regexRules {
		// 编译正则表达式
		regex, err := regexp.Compile(pattern)
		if err != nil {
			ym.logger.Warn("正则表达式编译失败", map[string]interface{}{
				"pattern": pattern,
				"error":   err.Error(),
			})
			continue
		}

		// 检查是否匹配
		if regex.MatchString(domainLower) {
			return resolve(dns), true
		}
	}

	return nil, false
}

// GetStats 获取YAML匹配器的性能统计
func (ym *YAMLMatcher) GetStats() map[string]interface{} {
	ym.mu.RLock()
	defer ym.mu.RUnlock()

	return map[string]interface{}{
		"exact_count":   len(ym.exactDomains),
		"suffix_count":  len(ym.suffixes),
		"keyword_count": len(ym.keywords),
		"domain_count":  len(ym.domains),
		"regex_count":   len(ym.regexRules),
		"matcher_type":  "yaml",
		"total_count":   len(ym.exactDomains) + len(ym.suffixes) + len(ym.keywords) + len(ym.domains) + len(ym.regexRules),
	}
}
