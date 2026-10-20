package dns

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"dnsPorxy/internal/config"
	"dnsPorxy/internal/querylog"

	"github.com/miekg/dns"
)

// logSource 派生日志来源维度：归一化客户端 IP、来源类型、接入方式与运营商归属。
//   - 客户端 IP：统一取 IP 主机部分（经代理为公网 IP，直连剥离端口）
//   - 来源类型：IP 为公网地址记外网，否则记内网（含固定内网段 10.0.0.0/24、回环、
//     其它私网、链路本地、未指定等非公网地址）；IP 缺失记未知
//   - 接入方式：IP 取自请求头记经代理，取自连接对端/静态映射记直连
//   - 运营商：按运营商段库匹配，未命中或未启用记空串
func (h *RefactoredHandler) logSource(w dns.ResponseWriter) (clientIP, kind, via, isp string) {
	ip, source := h.ResolveClientIP(w)
	via = querylog.ViaDirect
	if source == "header" {
		via = querylog.ViaProxy
	}
	if !ip.IsValid() {
		return "", querylog.SourceUnknown, via, ""
	}
	clientIP = ip.String()
	if isPublicIP(ip) {
		kind = querylog.SourceOuter
	} else {
		kind = querylog.SourceInner
	}
	if h.ispDB != nil {
		if v, ok := h.ispDB.Lookup(ip); ok {
			isp = string(v)
		}
	}
	return clientIP, kind, via, isp
}

// isPublicIP 判定客户端地址是否为公网可路由地址。
// 回环、私网（含 10/8、172.16/12、192.168/16、fc00::/7）、链路本地、组播与未指定
// 均视为非公网，归入内网，避免 127.0.0.1 之类被误判为外网。
func isPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

// clientInfo 包装 ResponseWriter 携带已解析的客户端信息
type clientInfo struct {
	ip     netip.Addr
	source string
}

// clientAwareWriter 在 dns.ResponseWriter 上附加解析出的客户端 IP
type clientAwareWriter struct {
	dns.ResponseWriter
	info clientInfo
}

// newClientAwareWriter 构造携带客户端信息的包装 writer
func newClientAwareWriter(w dns.ResponseWriter, info clientInfo) *clientAwareWriter {
	return &clientAwareWriter{ResponseWriter: w, info: info}
}

// ResolveClientIP 按配置优先级链解析客户端公网 IP
// 返回地址与命中的来源名（用于日志与排障）
func (h *RefactoredHandler) ResolveClientIP(w dns.ResponseWriter) (netip.Addr, string) {
	// 优先读取 DoH/DoH3 包装 writer 中已解析的信息
	if dw, ok := w.(*dohResponseWriter); ok {
		return dw.info.ip, dw.info.source
	}

	cfg := h.getConfig()
	remote := w.RemoteAddr()
	if remote == nil {
		return netip.Addr{}, ""
	}
	connIP := parseAddr(remote.String())

	for _, src := range cfg.ClientIPSources {
		switch strings.ToLower(src) {
		case "static":
			if ip, ok := resolveStaticClientIP(cfg, connIP); ok {
				return ip, "static"
			}
		case "header":
			// DoT/明文路径没有 http.Request，无法读取 header
			continue
		case "socket":
			return connIP, "socket"
		}
	}
	return connIP, "socket"
}

// resolveStaticClientIP 从配置中的静态映射查找
func resolveStaticClientIP(cfg *config.Config, connIP netip.Addr) (netip.Addr, bool) {
	if cfg.ClientIPStatic == nil {
		return netip.Addr{}, false
	}
	s := connIP.String()
	if v, ok := cfg.ClientIPStatic[s]; ok {
		if ip, err := netip.ParseAddr(v); err == nil {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// ResolveClientIPFromRequest 从 http.Request 中按配置链解析客户端 IP
// DoH/DoH3 路径使用：先 static，再 header（受 trusted_proxies 约束），最后 socket
func (h *RefactoredHandler) ResolveClientIPFromRequest(r *http.Request) (netip.Addr, string) {
	cfg := h.getConfig()
	connIP := parseAddr(r.RemoteAddr)

	for _, src := range cfg.ClientIPSources {
		switch strings.ToLower(src) {
		case "static":
			if ip, ok := resolveStaticClientIP(cfg, connIP); ok {
				return ip, "static"
			}
		case "header":
			if ip, ok := resolveHeaderClientIP(r, cfg.TrustedProxies, cfg.ClientIPHeaders, connIP); ok {
				return ip, "header"
			}
		case "socket":
			return connIP, "socket"
		}
	}
	return connIP, "socket"
}

// resolveHeaderClientIP 按可信代理规则从 header 中解析客户端 IP
func resolveHeaderClientIP(r *http.Request, trustedProxies, headers []string, connIP netip.Addr) (netip.Addr, bool) {
	// 连接对端必须命中可信代理，否则忽略 header 防止伪造
	if !addrInPrefixes(connIP, trustedProxies) {
		return netip.Addr{}, false
	}

	for _, name := range headers {
		name = strings.ToLower(name)
		var value string
		switch name {
		case "x-forwarded-for":
			value = r.Header.Get("X-Forwarded-For")
		case "x-real-ip":
			value = r.Header.Get("X-Real-Ip")
		case "cf-connecting-ip":
			value = r.Header.Get("Cf-Connecting-Ip")
		case "true-client-ip":
			value = r.Header.Get("True-Client-Ip")
		default:
			value = r.Header.Get(name)
		}
		if value == "" {
			continue
		}

		// XFF 可能包含多个代理，从右向左找第一个不在 trusted_proxies 内的地址
		if name == "x-forwarded-for" {
			parts := strings.Split(value, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				s := strings.TrimSpace(parts[i])
				if s == "" {
					continue
				}
				ip, err := netip.ParseAddr(s)
				if err != nil {
					continue
				}
				if !addrInPrefixes(ip, trustedProxies) {
					return normalizeAddr(ip), true
				}
			}
		} else {
			ip, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				continue
			}
			return normalizeAddr(ip), true
		}
	}
	return netip.Addr{}, false
}

// parseAddr 从 "host:port" 或 IP 字符串解析 netip.Addr
func parseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	// 先尝试 netip.ParseAddr
	if ip, err := netip.ParseAddr(s); err == nil {
		return normalizeAddr(ip)
	}
	// 尝试 net.SplitHostPort
	if host, _, err := net.SplitHostPort(s); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return normalizeAddr(ip)
		}
	}
	return netip.Addr{}
}

// normalizeAddr IPv4-mapped IPv6 折叠为 IPv4，剥离 zone
func normalizeAddr(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	ip = ip.WithZone("")
	return ip
}

// addrInPrefixes 判断地址是否命中任意 CIDR 前缀
func addrInPrefixes(ip netip.Addr, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
