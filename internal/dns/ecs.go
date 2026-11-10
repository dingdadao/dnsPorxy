package dns

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// ecsDefaultUDPSize 客户端未带 OPT 而又需注入 ECS 时，新建 OPT 使用的 UDP payload size
// （RFC 6891 推荐的 1232，避免响应在常见 MTU 下发生分片）
const ecsDefaultUDPSize = 1232

// applySplitECS 准备发往上游的请求：命中分流列表时按该列表的 ECS 策略处理，
// 未命中列表时不干预（沿用既有转发行为）。
// 需要改动时在 req 的副本上操作——req 会被 single-flight 与缓存复用，原地修改会并发污染。
func applySplitECS(req *dns.Msg, d SplitDecision) *dns.Msg {
	if !d.Matched {
		return req
	}
	var inject *netip.Prefix
	if p, ok := d.ECS.Resolve(); ok {
		inject = &p
	}
	out := req.Copy()
	applyECS(out, inject)
	return out
}

// applyECS 装卸请求中的 EDNS Client Subnet：
// inject == nil 时只剥离客户端自带的 ECS（开关未打开＝不传，且避免上游按客户端网段返回而污染共享缓存）；
// inject != nil 时先剥离客户端的、再注入本地的。
// 只增删 EDNS0_SUBNET 这一个 option，保留 OPT 本身：客户端通告的 UDP payload size 与 DO 位
// 直接影响上游的响应截断与 DNSSEC 处理，不能丢。
func applyECS(msg *dns.Msg, inject *netip.Prefix) {
	if msg == nil {
		return
	}

	opt := msg.IsEdns0()
	if opt == nil {
		if inject == nil {
			return // 客户端本就没带 OPT，也无需注入
		}
		msg.SetEdns0(ecsDefaultUDPSize, false)
		if opt = msg.IsEdns0(); opt == nil {
			return
		}
	}

	// 剥离已有 ECS，其余 option 原样保留
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isSubnet := o.(*dns.EDNS0_SUBNET); !isSubnet {
			kept = append(kept, o)
		}
	}
	opt.Option = kept

	if inject == nil {
		return
	}

	family := uint16(1) // RFC 7871：1=IPv4，2=IPv6
	if inject.Addr().Is6() {
		family = 2
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(inject.Bits()),
		Address:       inject.Addr().AsSlice(),
	})
}

// findSubnet 取出报文 OPT 中的 ECS option（无 OPT 或无 ECS 时返回 nil）
func findSubnet(msg *dns.Msg) *dns.EDNS0_SUBNET {
	if msg == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if s, ok := o.(*dns.EDNS0_SUBNET); ok {
			return s
		}
	}
	return nil
}

// cloneSubnet 深拷贝 ECS option：Address 是切片，直接共享会随原报文被改写而串味
func cloneSubnet(s *dns.EDNS0_SUBNET) *dns.EDNS0_SUBNET {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Address = append(net.IP(nil), s.Address...)
	return &cp
}

// ecsDesc 描述报文实际携带的 ECS（供日志排查线路问题），未携带时返回 "none"
func ecsDesc(msg *dns.Msg) string {
	s := findSubnet(msg)
	if s == nil {
		return "none"
	}
	return fmt.Sprintf("%s/%d", s.Address.String(), s.SourceNetmask)
}

// buildReplaceQuery 构造云替换的第二跳回源请求（替换域名 / 其 CNAME 目标）。
//
// 该请求必须与主查询用同一套 ECS 语义，否则替换域名会按代理出口位置解析，
// 拿到与客户端线路不匹配的 IP——这正是「替换后线路不对」的根因。
// 做法：先继承客户端 OPT（UDP payload size / DO）与自带 ECS，再交给 applySplitECS 统一裁决：
//   - 命中分流列表且开启 ECS → 剥离客户端 ECS，注入列表预设线路
//   - 命中分流列表但未开 ECS → 剥离客户端 ECS（不打开不传）
//   - 未命中分流列表 → 原样透传客户端自带 ECS
func buildReplaceQuery(reqID uint16, name string, qtype uint16, clientReq *dns.Msg, d SplitDecision) *dns.Msg {
	out := new(dns.Msg)
	out.SetQuestion(dns.Fqdn(name), qtype)
	out.Id = reqID

	if clientReq != nil {
		if opt := clientReq.IsEdns0(); opt != nil {
			out.SetEdns0(opt.UDPSize(), opt.Do())
			if subnet := findSubnet(clientReq); subnet != nil {
				if outOpt := out.IsEdns0(); outOpt != nil {
					outOpt.Option = append(outOpt.Option, cloneSubnet(subnet))
				}
			}
		}
	}

	return applySplitECS(out, d)
}
