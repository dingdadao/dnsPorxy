package dns

import (
	"strings"
	"time"

	"dnsPorxy/internal/querylog"

	"github.com/miekg/dns"
)

// maxLoggedAnswers 单条日志最多记录的应答记录数（避免超长文本）
const maxLoggedAnswers = 8

// maxLoggedTextLen 应答摘要最大长度
const maxLoggedTextLen = 400

// recordQuery 记录一条解析日志并补齐来源维度（未启用或未初始化时直接跳过）
func (h *RefactoredHandler) recordQuery(w dns.ResponseWriter, e querylog.Entry) {
	if h.queryLog == nil || !h.queryLog.Enabled() {
		return
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	e.Client, e.SourceKind, e.Via, e.ClientISP = h.logSource(w)
	e.Protocol = protocolOf(w)
	h.queryLog.Append(e)
}

// protocolProvider 携带接入协议标记的 writer（DoH/DoH3 与直连协议包装）
type protocolProvider interface {
	protocol() string
}

// protocolOf 取响应对应的接入协议（无法识别时返回空串）
func protocolOf(w dns.ResponseWriter) string {
	if w == nil {
		return ""
	}
	if p, ok := w.(protocolProvider); ok {
		return p.protocol()
	}
	return ""
}

// protocolTagWriter 为直连协议（UDP/TCP/DoT）的库 writer 标注接入协议
type protocolTagWriter struct {
	dns.ResponseWriter
	proto string
}

func (w *protocolTagWriter) protocol() string { return w.proto }

// protocolTagHandler 包装 dns.Handler，为直连协议（UDP/TCP/DoT）的每次查询标注接入协议
type protocolTagHandler struct {
	proto string
	next  dns.Handler
}

// ServeDNS 在调用下游处理器前，为 writer 附加协议标记
func (h protocolTagHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	h.next.ServeDNS(&protocolTagWriter{ResponseWriter: w, proto: h.proto}, req)
}

// clientInfoProvider 携带已解析客户端信息的 writer（DoH/DoH3 经代理透传 header）
type clientInfoProvider interface {
	clientInfo() clientInfo
}

// clientAddr 解析日志中的客户端地址。
// 经代理的 DoH/DoH3 优先记录已解析出的真实客户端 IP（来自 header），避免只记录到前置代理地址；
// 直连 UDP/TCP/DoT 无代理层，socket 对端地址即真实 IP，保持原样（含端口）。
func clientAddr(w dns.ResponseWriter) string {
	if w == nil {
		return ""
	}
	if p, ok := w.(clientInfoProvider); ok {
		if info := p.clientInfo(); info.ip.IsValid() && info.source == "header" {
			return info.ip.String()
		}
	}
	if w.RemoteAddr() == nil {
		return ""
	}
	return w.RemoteAddr().String()
}

// rcodeName 响应码名称（nil 响应按 SERVFAIL 记，避免空指针）
func rcodeName(resp *dns.Msg) string {
	if resp == nil {
		return dns.RcodeToString[dns.RcodeServerFailure]
	}
	return dns.RcodeToString[resp.Rcode]
}

// answersSummary 把应答记录压缩为可读文本（如 "A 1.2.3.4; CNAME foo.example.com"）
func answersSummary(resp *dns.Msg) string {
	if resp == nil || len(resp.Answer) == 0 {
		return ""
	}
	parts := make([]string, 0, len(resp.Answer))
	for i, rr := range resp.Answer {
		if i >= maxLoggedAnswers {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, rrSummary(rr))
	}
	return truncateText(strings.Join(parts, "; "))
}

// rrSummary 单条应答记录的文本形式
func rrSummary(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return "A " + v.A.String()
	case *dns.AAAA:
		return "AAAA " + v.AAAA.String()
	case *dns.CNAME:
		return "CNAME " + v.Target
	case *dns.NS:
		return "NS " + v.Ns
	case *dns.MX:
		return "MX " + v.Mx
	case *dns.TXT:
		return "TXT " + strings.Join(v.Txt, " ")
	case *dns.PTR:
		return "PTR " + v.Ptr
	case *dns.SOA:
		return "SOA " + v.Ns
	case *dns.SRV:
		return "SRV " + v.Target
	case *dns.CAA:
		return "CAA " + v.Value
	default:
		return dns.TypeToString[rr.Header().Rrtype]
	}
}

// truncateText 超长文本截断
func truncateText(s string) string {
	if len(s) <= maxLoggedTextLen {
		return s
	}
	return s[:maxLoggedTextLen] + "…"
}

// ecsSummary 描述本次发往上游的 ECS 处理结果（未命中分流列表时不干预上游请求）
func ecsSummary(req *dns.Msg, d SplitDecision) string {
	if !d.Matched {
		return ""
	}
	if p, ok := d.ECS.Resolve(); ok {
		return "注入 " + p.String()
	}
	// 未开启注入：客户端自带的 ECS 会被剥离
	if req != nil {
		if opt := req.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_SUBNET); ok {
					return "剥离客户端 ECS"
				}
			}
		}
	}
	return ""
}

// splitLogFields 分流决策对应的日志字段（命中列表时才有列表名与解析模式）
func splitLogFields(d SplitDecision) (action, listName, mode string) {
	if d.Matched {
		return querylog.ActionSplit, d.ListName, d.DNSMode
	}
	return querylog.ActionUpstream, "", ""
}
