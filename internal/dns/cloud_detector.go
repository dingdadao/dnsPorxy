package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"dnsPorxy/internal/utils"

	"github.com/miekg/dns"
)

// SafeNetSet 线程安全的网络段集合
type SafeNetSet struct {
	mu      sync.RWMutex
	prefixs []netip.Prefix
}

// NewSafeNetSet 创建新的SafeNetSet
func NewSafeNetSet() *SafeNetSet {
	return &SafeNetSet{}
}

// Contains 检查IP是否在网段中
func (s *SafeNetSet) Contains(ip netip.Addr) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.prefixs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// LoadPrefixes 加载网段前缀
func (s *SafeNetSet) LoadPrefixes(prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefixs = append([]netip.Prefix{}, prefixes...)
}

// List 获取所有前缀列表
func (s *SafeNetSet) List() []netip.Prefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]netip.Prefix{}, s.prefixs...)
}

// CloudDetector 云服务检测器
type CloudDetector struct {
	logger *utils.EnhancedLogger

	// 云服务网段集合
	cloudflareV4 *SafeNetSet
	cloudflareV6 *SafeNetSet
	awsV4        *SafeNetSet
	awsV6        *SafeNetSet

	// 替换域名配置
	cfReplaceDomain  string
	awsReplaceDomain string
	// replaceDomains 全部替换域名集合（全局 + 各分组覆写），用于跳过替换域名自身的云检测
	replaceDomains map[string]struct{}

	mu sync.RWMutex
}

// CloudType 云服务类型
type CloudType int

const (
	CloudTypeNone CloudType = iota
	CloudTypeCloudflare
	CloudTypeAWS
)

// CloudDetectionResult 云服务检测结果
type CloudDetectionResult struct {
	Type          CloudType
	DetectedIPs   []netip.Addr
	ReplaceDomain string
}

// NewCloudDetector 创建云服务检测器
func NewCloudDetector(logger *utils.EnhancedLogger, metrics interface{}) *CloudDetector {
	return &CloudDetector{
		logger:       logger,
		cloudflareV4: NewSafeNetSet(),
		cloudflareV6: NewSafeNetSet(),
		awsV4:        NewSafeNetSet(),
		awsV6:        NewSafeNetSet(),
	}
}

// LoadNetworkRanges 加载云服务网段
func (cd *CloudDetector) LoadNetworkRanges(cfFile4, cfFile6, awsFile string) error {
	// 注意：这里不检查配置开关，因为开关检查应该在调用方完成

	timer := cd.logger.StartTimer("load_network_ranges")
	defer timer.End()

	var wg sync.WaitGroup
	errorCh := make(chan error, 3)

	// 并发加载Cloudflare IPv4网段
	if cfFile4 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cd.loadCloudflareIPv4(cfFile4); err != nil {
				errorCh <- fmt.Errorf("加载Cloudflare IPv4失败: %w", err)
			}
		}()
	}

	// 并发加载Cloudflare IPv6网段
	if cfFile6 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cd.loadCloudflareIPv6(cfFile6); err != nil {
				errorCh <- fmt.Errorf("加载Cloudflare IPv6失败: %w", err)
			}
		}()
	}

	// 并发加载AWS网段
	if awsFile != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cd.loadAWSRanges(awsFile); err != nil {
				errorCh <- fmt.Errorf("加载AWS网段失败: %w", err)
			}
		}()
	}

	wg.Wait()
	close(errorCh)

	// 检查是否有错误
	for err := range errorCh {
		cd.logger.Error("网段加载错误", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	cd.logger.Info("🌐 云服务网段加载完成", map[string]interface{}{
		"cloudflare_v4_count": len(cd.cloudflareV4.List()),
		"cloudflare_v6_count": len(cd.cloudflareV6.List()),
		"aws_v4_count":        len(cd.awsV4.List()),
		"aws_v6_count":        len(cd.awsV6.List()),
	})

	return nil
}

// loadCloudflareIPv4 加载Cloudflare IPv4网段
func (cd *CloudDetector) loadCloudflareIPv4(filePath string) error {
	data, err := cd.downloadOrReadFile("https://www.cloudflare.com/ips-v4", filePath)
	if err != nil {
		return err
	}

	prefixes, err := cd.parseNetworkList(data)
	if err != nil {
		return err
	}

	var ipv4Prefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is4() {
			ipv4Prefixes = append(ipv4Prefixes, p)
		}
	}

	cd.cloudflareV4.LoadPrefixes(ipv4Prefixes)
	cd.logger.Debug("Cloudflare IPv4网段加载完成", map[string]interface{}{
		"count": len(ipv4Prefixes),
	})

	return nil
}

// loadCloudflareIPv6 加载Cloudflare IPv6网段
func (cd *CloudDetector) loadCloudflareIPv6(filePath string) error {
	data, err := cd.downloadOrReadFile("https://www.cloudflare.com/ips-v6", filePath)
	if err != nil {
		return err
	}

	prefixes, err := cd.parseNetworkList(data)
	if err != nil {
		return err
	}

	var ipv6Prefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is6() {
			ipv6Prefixes = append(ipv6Prefixes, p)
		}
	}

	cd.cloudflareV6.LoadPrefixes(ipv6Prefixes)
	cd.logger.Debug("Cloudflare IPv6网段加载完成", map[string]interface{}{
		"count": len(ipv6Prefixes),
	})

	return nil
}

// loadAWSRanges 加载AWS网段
func (cd *CloudDetector) loadAWSRanges(filePath string) error {
	data, err := cd.downloadOrReadFile("https://ip-ranges.amazonaws.com/ip-ranges.json", filePath)
	if err != nil {
		return err
	}

	ipv4Prefixes, ipv6Prefixes, err := cd.parseAWSJSON(data)
	if err != nil {
		return err
	}

	cd.awsV4.LoadPrefixes(ipv4Prefixes)
	cd.awsV6.LoadPrefixes(ipv6Prefixes)

	cd.logger.Debug("AWS网段加载完成", map[string]interface{}{
		"ipv4_count": len(ipv4Prefixes),
		"ipv6_count": len(ipv6Prefixes),
	})

	return nil
}

// IsReplaceDomain 检查域名是否为替换域名
func (cd *CloudDetector) IsReplaceDomain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	cd.mu.RLock()
	defer cd.mu.RUnlock()
	if _, ok := cd.replaceDomains[domain]; ok {
		return true
	}
	return domain == cd.cfReplaceDomain || domain == cd.awsReplaceDomain
}

// SetReplaceDomains 设置全局替换域名配置
func (cd *CloudDetector) SetReplaceDomains(cfReplaceDomain, awsReplaceDomain string) {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.cfReplaceDomain = cfReplaceDomain
	cd.awsReplaceDomain = awsReplaceDomain
}

// SetReplaceDomainsAll 登记全部替换域名（全局 + 各分组覆写），供跳过替换域名自检使用
func (cd *CloudDetector) SetReplaceDomainsAll(domains []string) {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.TrimSuffix(strings.TrimSpace(d), ".")
		if d != "" {
			set[d] = struct{}{}
		}
	}
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.replaceDomains = set
}

// DetectCloudService 检测DNS响应中的云服务IP
func (cd *CloudDetector) DetectCloudService(msg *dns.Msg, domain string) *CloudDetectionResult {
	// 如果是替换域名，直接返回无云服务检测结果
	if cd.IsReplaceDomain(domain) {
		cd.logger.Debug("⏭️ 跳过云服务检测（替换域名）", map[string]interface{}{
			"domain": domain,
		})
		return &CloudDetectionResult{Type: CloudTypeNone}
	}

	if msg == nil || len(msg.Answer) == 0 {
		return &CloudDetectionResult{Type: CloudTypeNone}
	}

	timer := cd.logger.StartTimer("cloud_detection")
	defer timer.End()

	var detectedIPs []netip.Addr
	cloudType := CloudTypeNone

	for _, rr := range msg.Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.ParseAddr(v.A.String())
		case *dns.AAAA:
			ip, _ = netip.ParseAddr(v.AAAA.String())
		default:
			continue
		}

		if !ip.IsValid() {
			continue
		}

		// 检测Cloudflare
		if cd.isCloudflareIP(ip) {
			cloudType = CloudTypeCloudflare
			detectedIPs = append(detectedIPs, ip)
			// 记录检测日志（替代指标系统）
			continue
		}

		// 检测AWS
		if cd.isAWSIP(ip) {
			cloudType = CloudTypeAWS
			detectedIPs = append(detectedIPs, ip)
			// 记录检测日志（替代指标系统）
			continue
		}
	}

	result := &CloudDetectionResult{
		Type:        cloudType,
		DetectedIPs: detectedIPs,
	}

	switch cloudType {
	case CloudTypeCloudflare:
		result.ReplaceDomain = cd.cfReplaceDomain
		cd.logger.Debug("🔍 检测到Cloudflare IP", map[string]interface{}{
			"ips":            detectedIPs,
			"replace_domain": cd.cfReplaceDomain,
		})
	case CloudTypeAWS:
		result.ReplaceDomain = cd.awsReplaceDomain
		cd.logger.Debug("🔍 检测到AWS IP", map[string]interface{}{
			"ips":            detectedIPs,
			"replace_domain": cd.awsReplaceDomain,
		})
	}

	return result
}

// isCloudflareIP 检查是否为Cloudflare IP
func (cd *CloudDetector) isCloudflareIP(ip netip.Addr) bool {
	if ip.Is4() {
		return cd.cloudflareV4.Contains(ip)
	}
	return cd.cloudflareV6.Contains(ip)
}

// isAWSIP 检查是否为AWS IP
func (cd *CloudDetector) isAWSIP(ip netip.Addr) bool {
	if ip.Is4() {
		return cd.awsV4.Contains(ip)
	}
	return cd.awsV6.Contains(ip)
}

// DetectCloudflareService 检测DNS响应中的Cloudflare服务IP
func (cd *CloudDetector) DetectCloudflareService(msg *dns.Msg) *CloudDetectionResult {
	if msg == nil || len(msg.Answer) == 0 {
		return &CloudDetectionResult{Type: CloudTypeNone}
	}

	var detectedIPs []netip.Addr

	for _, rr := range msg.Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.ParseAddr(v.A.String())
		case *dns.AAAA:
			ip, _ = netip.ParseAddr(v.AAAA.String())
		default:
			continue
		}

		if !ip.IsValid() {
			continue
		}

		// 检测Cloudflare
		if cd.isCloudflareIP(ip) {
			cd.logger.Debug("🔍 检测到Cloudflare IP", map[string]interface{}{
				"ip":             ip.String(),
				"replace_domain": cd.cfReplaceDomain,
			})
			return &CloudDetectionResult{
				Type:          CloudTypeCloudflare,
				DetectedIPs:   append(detectedIPs, ip),
				ReplaceDomain: cd.cfReplaceDomain,
			}
		}
	}

	return &CloudDetectionResult{Type: CloudTypeNone}
}

// DetectAWSService 检测DNS响应中的AWS服务IP
func (cd *CloudDetector) DetectAWSService(msg *dns.Msg) *CloudDetectionResult {
	if msg == nil || len(msg.Answer) == 0 {
		return &CloudDetectionResult{Type: CloudTypeNone}
	}

	var detectedIPs []netip.Addr

	for _, rr := range msg.Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.ParseAddr(v.A.String())
		case *dns.AAAA:
			ip, _ = netip.ParseAddr(v.AAAA.String())
		default:
			continue
		}

		if !ip.IsValid() {
			continue
		}

		// 检测AWS
		if cd.isAWSIP(ip) {
			cd.logger.Debug("🔍 检测到AWS IP", map[string]interface{}{
				"ip":             ip.String(),
				"replace_domain": cd.awsReplaceDomain,
			})
			return &CloudDetectionResult{
				Type:          CloudTypeAWS,
				DetectedIPs:   append(detectedIPs, ip),
				ReplaceDomain: cd.awsReplaceDomain,
			}
		}
	}

	return &CloudDetectionResult{Type: CloudTypeNone}
}

// downloadOrReadFile 下载或读取文件
func (cd *CloudDetector) downloadOrReadFile(url, filePath string) ([]byte, error) {
	// 先尝试下载最新版本
	if data, err := cd.downloadFile(url); err == nil {
		// 保存到本地文件
		if writeErr := os.WriteFile(filePath, data, 0644); writeErr != nil {
			cd.logger.Warn("保存网段文件失败", map[string]interface{}{
				"file":  filePath,
				"error": writeErr.Error(),
			})
		}
		return data, nil
	}

	// 下载失败，使用本地文件
	cd.logger.Warn("下载失败，使用本地文件", map[string]interface{}{
		"url":  url,
		"file": filePath,
	})

	return os.ReadFile(filePath)
}

// downloadFile 下载文件
func (cd *CloudDetector) downloadFile(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// parseNetworkList 解析网络列表
func (cd *CloudDetector) parseNetworkList(data []byte) ([]netip.Prefix, error) {
	lines := cd.splitLines(data)
	var prefixes []netip.Prefix

	for _, line := range lines {
		if line == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			cd.logger.Warn("解析网段失败", map[string]interface{}{
				"line":  line,
				"error": err.Error(),
			})
			continue
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

// parseAWSJSON 解析AWS IP范围JSON
func (cd *CloudDetector) parseAWSJSON(data []byte) ([]netip.Prefix, []netip.Prefix, error) {
	var awsData struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}

	if err := json.Unmarshal(data, &awsData); err != nil {
		cd.logger.Error("❗ AWS JSON解析失败", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, nil, err
	}

	var ipv4Prefixes, ipv6Prefixes []netip.Prefix

	// 解析IPv4前缀
	for _, p := range awsData.Prefixes {
		if prefix, err := netip.ParsePrefix(p.IPPrefix); err == nil {
			ipv4Prefixes = append(ipv4Prefixes, prefix)
		} else {
			cd.logger.Debug("❗ AWS IPv4前缀解析失败", map[string]interface{}{
				"prefix": p.IPPrefix,
				"error":  err.Error(),
			})
		}
	}

	// 解析IPv6前缀
	for _, p := range awsData.IPv6Prefixes {
		if prefix, err := netip.ParsePrefix(p.IPv6Prefix); err == nil {
			ipv6Prefixes = append(ipv6Prefixes, prefix)
		} else {
			cd.logger.Debug("❗ AWS IPv6前缀解析失败", map[string]interface{}{
				"prefix": p.IPv6Prefix,
				"error":  err.Error(),
			})
		}
	}

	cd.logger.Debug("📊 AWS JSON解析统计", map[string]interface{}{
		"total_prefixes":      len(awsData.Prefixes),
		"total_ipv6_prefixes": len(awsData.IPv6Prefixes),
		"parsed_ipv4":         len(ipv4Prefixes),
		"parsed_ipv6":         len(ipv6Prefixes),
	})

	return ipv4Prefixes, ipv6Prefixes, nil
}

// splitLines 分割行
func (cd *CloudDetector) splitLines(data []byte) []string {
	content := string(data)
	lines := make([]string, 0)

	start := 0
	for i, b := range data {
		if b == '\n' || b == '\r' {
			if i > start {
				line := content[start:i]
				if len(line) > 0 && line[0] != '#' {
					lines = append(lines, line)
				}
			}
			start = i + 1
		}
	}

	// 处理最后一行
	if start < len(data) {
		line := content[start:]
		if len(line) > 0 && line[0] != '#' {
			lines = append(lines, line)
		}
	}

	return lines
}
