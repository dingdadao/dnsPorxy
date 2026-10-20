package dns

import (
	"net"
	"strings"
	"sync"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// overrideDefaultTTL 篡改记录的默认TTL（秒）
const overrideDefaultTTL = 60

// OverrideMatcher 本地域名篡改匹配器（最高优先级）
// 支持精确匹配（example.com）与后缀匹配（.example.com 匹配自身及所有子域名）
type OverrideMatcher struct {
	logger *utils.EnhancedLogger
	mu     sync.RWMutex
	// key为规范化模式：精确匹配存 "example.com"，后缀匹配存 ".example.com"
	index map[string]map[uint16][]*config.Override
}

// NewOverrideMatcher 创建域名篡改匹配器
func NewOverrideMatcher(logger *utils.EnhancedLogger) *OverrideMatcher {
	return &OverrideMatcher{
		logger: logger,
		index:  make(map[string]map[uint16][]*config.Override),
	}
}

// normalizePattern 规范化匹配模式：小写、去尾点、"*."前缀转为后缀匹配
func normalizePattern(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if strings.HasPrefix(d, "*.") {
		return "." + d[2:]
	}
	return d
}

// Reload 全量重建篡改索引（配置变更后调用）
func (m *OverrideMatcher) Reload(list []*config.Override) {
	newIndex := make(map[string]map[uint16][]*config.Override)
	for _, o := range list {
		if o == nil || !o.Enabled {
			continue
		}
		qtype, ok := overrideQType(o.QType)
		if !ok {
			continue
		}
		key := normalizePattern(o.Domain)
		if key == "" {
			continue
		}
		if newIndex[key] == nil {
			newIndex[key] = make(map[uint16][]*config.Override)
		}
		newIndex[key][qtype] = append(newIndex[key][qtype], o)
	}

	m.mu.Lock()
	m.index = newIndex
	m.mu.Unlock()

	m.logger.Info("🔀 [域名篡改规则已加载] ", map[string]interface{}{
		"rule":  "OVERRIDE_RELOADED",
		"count": len(list),
	})
}

// overrideQType 将记录类型字符串转换为dns常量
func overrideQType(s string) (uint16, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	case "CNAME":
		return dns.TypeCNAME, true
	}
	return 0, false
}

// Lookup 查询域名的篡改记录（先精确再后缀；A/AAAA未命中时回退CNAME记录）
func (m *OverrideMatcher) Lookup(domain string, qtype uint16) []*config.Override {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "" {
		return nil
	}

	// 1. 精确匹配
	if recs := lookupPattern(m.index, d, qtype); len(recs) > 0 {
		return recs
	}

	// 2. 后缀匹配：i=0 检查 ".自身" 模式（.ad.com 命中 ad.com 自身），逐层剥离左标签
	labels := strings.Split(d, ".")
	for i := 0; i < len(labels); i++ {
		parent := "." + strings.Join(labels[i:], ".")
		if recs := lookupPattern(m.index, parent, qtype); len(recs) > 0 {
			return recs
		}
	}

	// 3. A/AAAA查询回退CNAME篡改记录（CNAME重定向场景）
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		if recs := lookupPattern(m.index, d, dns.TypeCNAME); len(recs) > 0 {
			return recs
		}
		for i := 0; i < len(labels); i++ {
			parent := "." + strings.Join(labels[i:], ".")
			if recs := lookupPattern(m.index, parent, dns.TypeCNAME); len(recs) > 0 {
				return recs
			}
		}
	}

	return nil
}

// Match 判断域名是否命中任一篡改规则（不限记录类型）
// 用于「已篡改域名一律本地作答」：未配置的记录类型回NODATA，不让上游数据外泄
func (m *OverrideMatcher) Match(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "" {
		return false
	}
	if _, ok := m.index[d]; ok {
		return true
	}
	labels := strings.Split(d, ".")
	for i := 0; i < len(labels); i++ {
		if _, ok := m.index["."+strings.Join(labels[i:], ".")]; ok {
			return true
		}
	}
	return false
}

func lookupPattern(index map[string]map[uint16][]*config.Override, pattern string, qtype uint16) []*config.Override {
	if byType, ok := index[pattern]; ok {
		return byType[qtype]
	}
	return nil
}

// buildOverrideResponse 根据篡改记录构造DNS响应（owner保留客户端原始QNAME大小写）
// 所有记录值均非法时返回nil
func buildOverrideResponse(req *dns.Msg, qtype uint16, records []*config.Override) *dns.Msg {
	owner := req.Question[0].Name

	resp := new(dns.Msg)
	resp.SetReply(req)

	for _, rec := range records {
		ttl := rec.TTL
		if ttl == 0 {
			ttl = overrideDefaultTTL
		}

		switch strings.ToUpper(rec.QType) {
		case "A":
			ip := net.ParseIP(strings.TrimSpace(rec.Value)).To4()
			if ip == nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip,
			})
		case "AAAA":
			ip := net.ParseIP(strings.TrimSpace(rec.Value)).To16()
			if ip == nil || ip.To4() != nil {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		case "CNAME":
			target := strings.TrimSpace(rec.Value)
			if target == "" {
				continue
			}
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(target),
			})
		}
	}

	if len(resp.Answer) == 0 {
		return nil
	}
	return resp
}

// buildNODATAResponse 构造空应答（NOERROR + 0 Answer）
// 已篡改域名未配置该记录类型时使用，避免上游真数据（如CNAME）外泄
func buildNODATAResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	return resp
}
