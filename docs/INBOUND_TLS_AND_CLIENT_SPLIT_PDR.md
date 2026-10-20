# 入站 DoH/DoT/DoH3 · 客户端 IP 分流 · 证书托管 · PDR（产品设计需求文档）

- 项目：dnsPorxy DNS 代理
- 日期：2026-10-05
- 状态：**已确认，已完成**（阶段 1–8 全部落地并验证；回归 56/56 通过，`go test ./...` 全绿，真实 DoH/DoT/DoH3 与证书签发链路已冒烟）
- 边界：新增「入站加密解析服务（DoT / DoH / DoH3）」「按客户端 IP 的分流能力」「证书托管与热加载」三块；**不改动现有域名分流的语义与字段**

> 用户已确认的决策：管理端本轮**不加鉴权**（管理端口不映射公网，仅 853/443/443-udp 对外，走反代只需常规路径安全）；证书过期后 API 仍可更新，DoH 握手报错；本机仅有 IPv6 公网，后续可能走 CDN 回源；quic-go 采用**路径甲**（锁 v0.53.0，Go 1.23 零工具链变更）。

---

## 1. 背景与需求拆解

当前 dnsPorxy 是**明文入站、域名维度分流**的 DNS 代理：对客户端只开 UDP/TCP `:53`，分流只按 QNAME 匹配。本次希望让它同时成为一个**可对外提供加密解析（DoH/DoT/DoH3）**、并且**能按来源用户公网 IP 决定走哪条线路**的服务，配套要有可持续的证书供给方式。

原始诉求逐条拆解：

| 编号 | 需求原文 | 归属特性 | 备注 |
|---|---|---|---|
| R1 | 支持 DoH | A · 入站加密服务 | RFC 8484 |
| R2 | 支持 TLS（DoT） | A · 入站加密服务 | RFC 7858 |
| R3 | **支持 DoH3 / HTTP3 以减少连接开销** | A · 入站加密服务 | RFC 9114，本次新增纳入范围 |
| R4 | 根据用户的公共 IP 进行分流 | B · 客户端维度分流 | 与现有域名分流正交 |
| R5 | 支持配置（指定 IP） | B · 客户端 IP 来源 1 | 静态映射 |
| R6 | 支持根据用户连接的 IP 获取 | B · 客户端 IP 来源 2 | socket 对端地址 |
| R7 | 支持请求头获取 | B · 客户端 IP 来源 3 | XFF / CF-Connecting-IP 等 |
| R8 | 支持优先级 | B · 来源优先级 + 规则优先级 | 两处都需要 |
| R9 | 证书支持上传 | C · 证书来源 1 | Web 管理端 |
| R10 | 支持用户手动 SSH 更新 | C · 证书来源 2 | 目录约定 + 热加载 |
| R11 | 支持 webhook 部署证书 | C · 证书来源 3 | 对接 certd 类平台（见附图） |

> 附图为 certd（证书自动化平台）的「webhook 方式部署证书」步骤：变量 `${domain}` `${domains}` `${crt}` `${key}` `${ic}` `${one}` `${der}` `${pfx}` `${jks}`，请求方式 POST、ContentType `application/json`、可用「成功判定」字符串。**据此确定 webhook 方向是「外部平台 → 本服务」的入站调用**，不是本服务主动外呼。

### 1.1 为什么 DoH3 值得做（收益定性）

DoH3 把 DoH 跑在 QUIC（UDP）上，相比 HTTP/2 over TLS over TCP：

| 开销项 | DoH（h2/TCP） | DoH3（QUIC） |
|---|---|---|
| 首次建连 | TCP 三次握手 + TLS 握手（**串行两段延迟**） | QUIC 把传输与加密握手合并，**1-RTT 一次完成** |
| 再次建连 | 同样需要 TCP + TLS | 会话票据可 **0-RTT**（需显式开启） |
| 连接复用 | 依赖 TCP keep-alive | 连接 ID 与地址解耦，**网络切换（4G↔WiFi）不断连** |
| 丢包影响 | TCP 头阻塞：一个包丢，后续全等 | 各 stream 独立，**互不阻塞** |
| 首部压缩 | HPACK | QPACK |

对 DNS 这种「小报文、高频、短往返」的负载，**收益主要来自建连成本的下降**；网络质量差（移动端、跨境）时，抗头阻塞的收益更明显。

**但必须承认一个前提**：DoH3 的收益只有在「客户端复用同一条 QUIC 连接」时才成立。若客户端每次查询都新建连接，收益会大幅缩水甚至为负（UDP 建连比 TCP 更贵）。因此 §4.1.2 里的 **keep-alive / 空闲超时调优与 `Alt-Svc` 通告是必需项，不是可选项**。

---

## 2. 现状审计

### 2.1 可直接复用的资产（不推倒重来）

| 能力 | 位置 | 复用方式 |
|---|---|---|
| 协议守卫 / 缓存 / 统一响应出口 | `handler.go` `ServeDNS`、`processQuery`、`writeResponse` | DoT/DoH/DoH3 复用**同一个 handler 实例**，全部语义（FORMERR、AD 清理、EDNS 回带、TC 截断）自动继承 |
| 出站多协议 + 连接池 | `pool.go`、`simple_modern_optimizer.go` | 无需改动 |
| 域名分流（顺序匹配 + 取反） | `matcher_handler.go` `MatchDomain` → `SplitDecision` | 新客户端分组的匹配逻辑与热更新范式**照抄这一套** |
| ECS 策略 | `config.go` `ECSPolicy`、`ecs.go` `applyECS` | 分组复用现成结构，扩一个「自动取客户端 IP」模式即可 |
| A/AAAA 偏好 | `ip_prefer.go`、`effectiveIPPrefer` | 分组继承同名语义 |
| 数据文件下载 / 定时刷新 | `file_loader.go`、`task_scheduler.go`、`POST /api/lists/{i}/refresh` | 可用于按需下载 IP 段库 |
| 配置存储 | `store.go`：`settings` 单行 JSON + `overrides` 表 | `client_groups` 走 JSON（同 `split_lists`），`certs` 走新表 |
| 配置热更新 + 重启判定 | `handler.go` `ApplyConfig` | 新字段按「是否需重启」分两类接入 |
| 管理端 Schema 驱动渲染 | `admin.html`：`SECTIONS` → `cards` → 字段元数据 | 新增分区成本低 |
| 部署通道 | `scripts/service/*`、`deploy_remote.sh`（scp + systemctl） | 证书的「手动 SSH」路径与之一致 |

### 2.2 缺口（必须新增）

| # | 缺口 | 说明 | 严重度 |
|---|---|---|---|
| G1 | 入站无 TLS 能力 | 只监听 UDP/TCP `:53`；miekg/dns 支持 `tcp-tls`，但**没有任何证书来源**（历史字段 `tls_cert_file`/`tls_key_file` 已在早期重构中删除） | 高 |
| G2 | 无证书存储与生命周期 | 无 cert 表、无目录约定、无 SNI 选择、无热加载、无过期监控 | 高 |
| G3 | 客户端 IP 不参与路由 | 仅 `w.RemoteAddr()` 用于日志；**无 XFF 解析、无可信代理概念、无 header 取值** | 高 |
| G4 | 无 IP 维度分流 | `MatchDomain(domain)` 只吃域名，`SplitDecision` 无来源维度 | 高 |
| G5 | 缓存键无来源维度 | `optimized_cache.go` `key() = domain + "\|" + TYPE`；**客户端分组若不隔离会跨组串味** | 高 |
| G6 | 无公网暴露防护 | 无 ACL、无限速；开放递归解析器会被扫描与放大滥用 | 高 |
| G7 | 管理端无鉴权 | `:5380` 明文、无认证；一旦和证书一起对外则私钥可被下载 | 中 |
| G8 | 请求上下文传递受限 | `dns.Handler` 接口只有 `(w, req)`，DoH 的 `http.Request`（含 header）需要额外通道才能到 handler | 中 |
| G9 | **依赖 `quic-go`，且有 Go 工具链门槛** | 引入 QUIC/HTTP3 必须新增该依赖；其版本对 Go 有硬性要求，当前 `go.mod` 的 `go 1.23.0` 需做取舍（详见 §4.1.3） | 中 |

### 2.3 ⚠️ 顺带发现：出站 `h3://` 目前是假的

审计中发现一处**文档与实现不符**，建议在本轮一并处理（否则「支持 DoH3」的说法站不住）：

- 配置与 UI 均宣称支持 `h3://`（DoH3）上游：`internal/web/admin.html:418,770,911,968`、`internal/dns/simple_modern_optimizer.go:601`、`handler.go:27,46`、`query.go:259`。
- 但实际实现是**静默降级为 DoH**：

```go
// internal/dns/simple_modern_optimizer.go:796
// queryDoH3 DNS over HTTP/3查询（简化版本，如果不支持HTTP/3则降级到HTTPS）
func (qo *SimpleModernOptimizer) queryDoH3(req *dns.Msg, serverURL string) (*dns.Msg, error) {
    // 将h3://转换为https://，因为大多数Go HTTP客户端会自动协商HTTP/3
    httpsURL := strings.Replace(serverURL, "h3://", "https://", 1)
    qo.logger.Debug("🔄 DoH3降级为DoH", ...)
    return qo.queryDoH(req, httpsURL)   // ← 注释是错的：标准库 net/http 不会协商 HTTP/3
}
```

  注释里「大多数 Go HTTP 客户端会自动协商 HTTP/3」是**错误认知**：Go 标准库 `net/http` 至今（Go 1.26）仍不支持 HTTP/3，必须依赖 `quic-go` 的 `http3.RoundTripper`。

- 佐证：`go.sum` 中无任何 `quic` 相关条目（`grep -c quic go.sum` → `0`）。
- **影响**：用户配置 `h3://` 上游时以为走了 HTTP/3，实际走的是 HTTPS/2，且**经了一次无从察觉的重写**——比沉默更糟的是它留下排查误导。

**处置建议**（三选一，见 §9 决策 12）：真实现 / 移除声明并明确报错 / 保留降级但日志提级为 `Warn` 并在 UI 标注「实验性·降级」。

---

## 3. 需求定性：三个必须先厘清的模糊点

这三处语义不定，代码就没法定型。本节给出推荐答案，供评审拍板（汇总见 §9）。

### 3.1 「按公共 IP 分流」到底指什么

存在三种常见解读，彼此并不互斥：

- **(a) 地域 / 运营商维度**：国内来源走国内 DNS，海外来源走海外 DNS；或按电信/联通/移动选线路。
  *需要* IP → 归属 的判定能力（IP 段库或 GeoIP）。
- **(b) CIDR 精确维度**：某段地址 → 指定上游（如某客户专线走自建 DNS、某机房出口走特定解析）。
  *只需要* CIDR 匹配，零外部依赖。
- **(c) 准入维度**：内网来源直连、未知来源 REFUSED（白名单/黑名单）。

**推荐**：统一抽象为一种规则 —— **客户端分组 `ClientGroup` = 匹配条件（IP/CIDR）+ 动作（上游/ECS/云检测/偏好）**。
(b)(c) 用同一结构天然覆盖；(a) 只需额外支持「Match 里可写国家/运营商 code」，由可选 IP 段库驱动，不引入 cgo。**不把三种做成三套机制。**

### 3.2 客户端分组 与 域名分流 的优先级

两方案：

| | 方案 X · 两段正交（推荐） | 方案 Y · 单链有序 |
|---|---|---|
| 模型 | Stage1 客户端分组决定**候选上游集合 + 基础 ECS + 是否允许域名细化**；Stage2 现有域名分流在此集合内匹配 | 客户端分组与域名分流放进**同一条有序规则链**，谁在前谁生效 |
| 表达力 | 强：「华东来源 + 苹果域名 → 特定上游」可表达 | 中：跨维度组合需要穷举规则 |
| 心智 | 符合「先定人、再定域名」的运维直觉 | 更简单，但顺序敏感易错 |
| 改动 | `SplitDecision` 增加来源维度，匹配入口改两级 | 只加一条链，改动更小 |

**推荐 X**，但为控制首版复杂度，X 落地时给一条降级开关：`ClientGroup.AllowDomainSplit`（关闭时直接使用分组 DNS，跳过域名阶段），使配置可以「只用一层」。

### 3.3 客户端 IP 的取值优先级

推荐**链式解析 + 可信边界**，顺序可配：

```
1. static   —— 配置显式映射（最高，用于覆盖/纠错）
2. header   —— X-Forwarded-For / X-Real-IP / CF-Connecting-IP / True-Client-IP
               ⚠️ 仅当「连接 IP ∈ trusted_proxies」时才采信，否则一律忽略
3. socket   —— 连接对端地址（w.RemoteAddr()），永远可用的兜底
```

默认顺序：`static > header > socket`。
待确认的第四来源：**DoH 路径/SNI 携带 token 区分设备实例**（如 `https://dns.example.com/dns-query/<token>`），对无法固定 IP 的移动端有用，但会让 URL 变长且与 RFC 8484 缓存语义有冲突 —— 建议列为后续。

---

## 4. 设计详稿

### 4.1 特性 A · 入站加密服务（DoT / DoH / DoH3）

#### 4.1.1 协议与监听

| 项 | DoT | DoH | **DoH3** |
|---|---|---|---|
| 传输 | TLS over **TCP** | HTTPS over **TCP**（HTTP/2 优先，兼容 1.1） | HTTPS over **QUIC/UDP**（HTTP/3） |
| 默认端口 | `:853`（可配） | `:443`（可配） | `:443`（**UDP**，与 DoH 同端口号、不同传输层，可共存） |
| 实现 | `dns.Server{Net:"tcp-tls", TLSConfig:...}` | `net/http` + `h2`，自定义 `http.Handler` 适配到 `dns.Handler` | `quic-go` 的 `http3.Server` |
| 请求 | 标准 DNS 报文 | RFC 8484：`GET /dns-query?dns=<base64url>`、`POST /dns-query`（`application/dns-message`），路径可配 | **同 DoH**（RFC 8484 语义不变，仅传输层换成 QUIC） |
| 响应 | 标准 DNS 报文 | `application/dns-message`；建议带 `Cache-Control: max-age=<响应最小TTL>` | 同 DoH |

**三者的共同点（设计上最省事的地方）**：

- **复用同一 handler**：全部与明文 `:53` 共用 `RefactoredHandler`，协议守卫/缓存/篡改规则/分流/解析日志一致，避免多套逻辑漂移。
- **复用同一 cert store**：证书热加载用的 `tls.Config{GetCertificate: ...}` 是普通回调，TLS/QUIC 通吃。**注意** QUIC 要求 `NextProtos` 含 `"h3"`，若自行提供 `tls.Config` 需留意（`http3.Server` 未显式设置时会补上）。

#### 4.1.2 DoH3 的专门设计

**a) `Alt-Svc` 通告 —— 决定收益能否落地的关键**

HTTP/3 无法在「客户端只知 TCP」的情况下被自动发现。标准做法是让 TCP 上的 DoH（h2）响应带上：

```
Alt-Svc: h3=":443"; ma=86400
```

客户端（浏览器、AdGuardHome、支持 h3 的 DNS 客户端）看到后缓存该通告，**后续请求自动切到 QUIC**；若 UDP 被网络阻断，客户端按 `Alt-Svc` 语义**自动回退到 TCP DoH**，服务不中断。

→ **设计结论**：`Alt-Svc` 必须由 DoH（h2）端点主动返回，`ma` 与端口可配。**没有这一步，DoH3 只是「手动指定才生效」的摆设。**

**b) 连接复用调优（收益的实际来源）**

必须显式配置 QUIC 空闲与保活参数，让客户端能复用同一条连接：

| 参数 | 建议值 | 理由 |
|---|---|---|
| `MaxIdleTimeout` | 3–5 分钟 | 太短则客户端频繁重握手，反而更慢 |
| `KeepAlivePeriod` | 30–60 秒 | 维持 NAT 映射，避免中间设备静默回收 |
| `MaxIncomingStreams` | 100+ | 单连接承载并发查询 |
| `InitialMaxStreamsBidi` | 100 | 避免客户端过早受限 |

**c) 0-RTT 是否开启**

`http3.Server` 支持 0-RTT。DNS 查询幂等，重放风险低，但 0-RTT 数据缺乏前向保密且有重放放大面。**建议默认关闭，提供开关**（§9 决策 13）。

**d) 客户端 IP 获取**

DoH3 侧同样拿到 `*http.Request`，因此 §4.2 的 `clientAwareWriter` 包装方案**三协议通用**，无需为 h3 另写一套。QUIC 对端地址即 `r.RemoteAddr`；处于反代后时走 header 分支。

#### 4.1.3 依赖与工具链约束（G9）

引入 `quic-go` 是本 PDR 唯一的新增重量级依赖。**实测各版本 `go.mod` 的 `go` 指令**（读自模块代理）：

| quic-go 版本 | 要求 Go | 与当前工程（`go 1.23.0` / toolchain `go1.23.9`） |
|---|---|---|
| v0.62.0 – v0.63.0（最新） | **go 1.26.0** | ✗ 不兼容 |
| v0.60.0 – v0.61.0 | go 1.25.0 | ✗ 不兼容 |
| v0.55.0 – v0.59.1 | go 1.24 | ✗ 不兼容 |
| **v0.50.0 – v0.53.0** | **go 1.23** | **✓ 兼容，零工具链变更** |
| v0.48.2 | go 1.22 | ✓ 兼容（更旧） |

> quic-go 的发布策略是**只支持最近两个 Go 大版本**，其最新版会持续向前跑，锁版本后需定期跟进。

**两条路径二选一**（§9 决策 14）：

- **路径甲（推荐先落地）**：锁 `quic-go v0.53.0`（最后一个 `go 1.23` 版本），**不改工具链**，改动面最小、可快速验证；代价是落后约 10 个 minor，缺少后续修复。
- **路径乙（后续排期）**：升级 `go.mod` 的 `go` 指令与构建机 toolchain 到 Go 1.26，用 v0.63.0。收益是最新协议实现与修复；代价是需同步改 CI、`Makefile` 交叉编译与构建机（`deploy_remote.sh` 部署的是交叉编译产物、运行时无 Go，风险主要在构建机）。

**依赖重量实测**（v0.53.0 直接 require）：真正会编入本项目二进制的是 `github.com/quic-go/qpack`、`golang.org/x/crypto`、`golang.org/x/net`、`golang.org/x/sys`、`github.com/francoispqt/gojay`（qlog）。其中的 `prometheus/client_golang`、`testify`、`go.uber.org/mock` 是 quic-go 自身的测试依赖，**Go 的模块图裁剪不会把它们编入本项目二进制** —— 即本项目「已移除 Prometheus 指标」的现状不会被破坏。**纯 Go 实现，无 cgo**，交叉编译不受影响。

#### 4.1.4 其余工程要点

- **新增代码**：`internal/dns/doh_server.go`（HTTP → `dns.Handler` 适配 + 报文编解码 + `Content-Type` 校验 + 体积上限 + 方法/路径校验，**DoH 与 DoH3 共用这一份 handler**）、`internal/dns/dot_server.go`（或扩展 `server.go` 的 `netType` 为 `tcp-tls`）、`internal/dns/doh3_server.go`（`http3.Server` 生命周期 + QUIC 参数）。
- **启动编排**：`recovery.startDNSService()` 中与现有 `udpServer`/`tcpServer` 并列创建；`stopDNSService()`、`gracefulShutdown()` 一并关闭（`http3.Server` 需显式 `Close()`，否则 QUIC socket 泄漏、UDP 端口不释放）。端口可用性预检查沿用现有写法。
- **重启判定**：`ApplyConfig` 返回条件新增 `EnableDoH/EnableDoT/EnableDoH3/DoHAddr/DoTAddr/DoH3Addr/DoHPath`（监听类，与 `listen_port` 同类）；**证书与 `Alt-Svc` 可热更新**，QUIC 参数变更需重连生效。
- **前置反代模式**：若 `:443` 已被 nginx/caddy 占用，支持只监听 `127.0.0.1`。⚠️ **反代场景下 DoH3 需要反代自身端到端支持 QUIC**，否则 h3 必须由本服务直接监听公网 UDP 端口 —— 这是部署形态上的硬约束，需在决策 11 一并确认。

### 4.2 特性 B-1 · 客户端 IP 解析链

新增 `internal/dns/client_ip.go`：

```go
// ResolveClientIP 按配置优先级链解析客户端公网 IP，返回地址与命中的来源名（用于日志与排障）
func (h *RefactoredHandler) ResolveClientIP(w dns.ResponseWriter, req *dns.Msg) (netip.Addr, string)
```

- **G8 的解法**：`dns.Handler` 接口拿不到 `http.Request`，采用**包装 ResponseWriter** 而非 context 传值（req 会被 singleflight/缓存复用，塞 context 不安全且不可行）：

```go
type clientAwareWriter struct {
    dns.ResponseWriter
    ip     netip.Addr
    source string
}
```

  DoH/DoH3 适配器构造该包装（携带 `RemoteAddr` 与 header 解析结果），`ResolveClientIP` 优先读取包装携带的信息；读不到则回退 `w.RemoteAddr()`。DoT/明文路径无包装，自然回退到 socket。

- **可信代理**：`TrustedProxies []string`（CIDR 列表）。仅当连接 IP 命中时才解析 header，否则**忽略并记 debug 日志**（防止 XFF 伪造绕过分流）。
- **XFF 取值规则**：从右向左找第一个「不在 trusted_proxies 内」的地址（RFC 7239 语义），而非简单取第一个。
- **归一化**：IPv4-mapped IPv6 折叠为 IPv4、剥离 zone id、统一小写。

### 4.3 特性 B-2 · 客户端分组 ClientGroup

结构**对齐现有 `SplitList`**，以便复用匹配范式、热更新与 Web 渲染：

```go
// ClientGroup 客户端分组：按来源 IP 决定上游、ECS、云检测与 A/AAAA 偏好
// 数组顺序 + Priority 共同决定匹配优先级（Priority 大者先匹配，同值按数组顺序）
type ClientGroup struct {
    Name             string
    Enabled          bool
    Priority         int           // 显式优先级（需求 R8）
    Match            []string      // IP / CIDR / 可选「国家或运营商 code」（如 cn / telecom）
    Invert           bool          // 取反：来源不在清单内时命中
    DNS              []string      // 命中后使用的上游列表
    DNSMode          string        // race / failover（沿用现有常量）
    ECS              ECSPolicy     // 复用现有结构；Subnet 为空 + Enabled=true 表示「用客户端真实 IP 派生」
    EnableCloudCheck bool
    IPPrefer         string
    AllowDomainSplit bool          // 是否继续进入域名分流阶段（方案 X 的降级开关）
}
```

- **ECS 自动模式**：`ECSPolicy.Subnet == "" && Enabled` 时，用解析出的客户端 IP 派生前缀（IPv4 补 `/24`、IPv6 补 `/56`），补齐逻辑直接复用 `ECSPolicy.Resolve` 的分支。
- **匹配入口**：`processQuery` 中现有第 649 行 `decision := h.matcherHandler.MatchDomain(domain)` 之前插入一级客户端分组匹配，得到 `ClientDecision`；再由 `upstreamsFor(...)`、`applySplitECS(...)`、`effectiveIPPrefer(...)` 消费（这三个函数需扩展为同时接收两个 decision，或内部先合并成一个统一的路由决策结构）。

**⚠️ 缓存隔离（G5，本设计最关键的技术点）**

- 现状 key：`domain|TYPE`。客户端分组一旦影响上游选择，**同一域名在不同分组下必须存两份**，否则 A 组的结果会被 B 组命中（串味，属于正确性缺陷而非性能问题）。
- 推荐：key 扩展为 `scope|domain|TYPE`，`scope` = 命中的分组的稳定标识（未命中分组为 `-`）。
  影响面清单（需逐一改）：`optimized_cache.go` `key()` / 分片哈希、`GetWithFlight` 的 singleflight 组、`SetCloudResponse` / `GetCloudResponse` 的云响应缓存、`MarkDomainAsCloud` 标记、`cache_manager.go` 的三处异步刷新 key（`submitAsyncRefresh`/`submitOnDemandRefresh`/`processAsyncTask`）、`GetStats` 的 IP 统计口径。
- 备选（更简单）：命中客户端分组的请求**跳过共享缓存**。代价是分流流量全部回源，推荐仅作为紧急降级开关，不做主方案。
- **必须写进文档的取舍**：按 IP 分组会降低缓存命中率（同域名 × 分组数份）。因此**建议分组粒度取粗**（按大段/按线路，而非精细 IP），并在管理端展示「分组缓存条目占比」以便观察。

### 4.4 特性 C · 证书托管

**存储**

- 私钥落盘 `./data/certs/<name>.crt|.key`，权限 `0600`，目录 `0700`。
- SQLite 新增 `certs` 表（只存元数据，**私钥不入库**）：

```sql
CREATE TABLE IF NOT EXISTS certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,   -- 文件名标识
    domains     TEXT NOT NULL,          -- 覆盖的域名（含泛域名），JSON 数组
    cert_path   TEXT NOT NULL,
    key_path    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,          -- SHA256(cert)，用于幂等
    not_before  INTEGER NOT NULL,
    not_after   INTEGER NOT NULL,
    source      TEXT NOT NULL,          -- upload / webhook / ssh
    updated_at  INTEGER NOT NULL
);
```

**三条来源**

1. **Web 上传**
   `POST /api/certs`（multipart 或 PEM 文本）。服务端必须做：`tls.X509KeyPair` 配对校验 → 有效期校验 → 原子落盘（临时文件 → rename）→ 入库 → 热加载。**配对失败一律拒绝，不落半成品。**

2. **手动 SSH 更新**
   约定目录 + 命名规则（`<name>.crt` / `<name>.key` 成对）。触发方式三选一或并存：启动时扫描、定时扫描（按 mtime 变化）、管理端「重新加载证书」按钮 / `SIGHUP`。
   此路径与现有 `deploy_remote.sh`（scp + systemctl）的运维习惯一致，**不引入命令行参数**（项目约束：程序不接受任何命令行参数）。

3. **Webhook 自动部署（对接 certd 类平台）**
   - 端点：`POST /api/certs/deploy`，token 走 URL query（`?token=xxx`）
   - 鉴权：URL token（管理端可轮换、可复制）+ 可选 IP 白名单 + 可选 HMAC 签名
   - 请求：`Content-Type: application/json`（默认），兼容 `form-data`
   - **字段映射可配**：默认识别 `domain` / `crt` / `key` / `ic`（中间证书），并提供 certd 变量名（`${domain}` `${crt}` `${key}` `${ic}`）的映射预设
   - 响应：**默认返回体包含 `"status":"success"`**，以匹配 certd 的「成功判定」配置；失败返回 4xx + `{"status":"error","message":...}`
   - 幂等：相同 `fingerprint` 重复推送直接返回成功（不重复写盘）
   - 审计：记录来源 IP、指纹、覆盖域名、时间

**热加载与 SNI**

- `tls.Config{ GetCertificate: func(hello) { 按 SNI 查表 → 未命中用默认证书 } }`，证书表用 `atomic.Pointer` 整体替换，**零重启生效**；旧连接不受影响。
- **TLS 与 QUIC 共享该回调**，DoT / DoH / DoH3 三处证书来源唯一。
- 泛域名 `*.example.com` 支持；SNI 未命中时的行为（用默认证书 / 拒绝握手）作为可配项。
- 管理端自身是否启用 HTTPS（`web_tls`）单独开关。

**过期监控**

- 管理端证书页展示：覆盖域名、来源、签发/到期时间、**剩余天数**、指纹。
- 剩余 < 14 天输出 `WARN` 日志。
- 已过期时的策略（拒绝新连接 / 继续用旧证书换取续签窗口）**待确认**。

### 4.5 配置模型与 API 变更

**`Config` / `ConfigJSON` 新增字段**

| 字段 | 类型 | 默认 | 生效方式 |
|---|---|---|---|
| `enable_dot` | bool | false | 需重启 |
| `dot_addr` | string | `:853` | 需重启 |
| `enable_doh` | bool | false | 需重启 |
| `doh_addr` | string | `:443` | 需重启 |
| `doh_path` | string | `/dns-query` | 需重启 |
| **`enable_doh3`** | bool | false | 需重启 |
| **`doh3_addr`** | string | `""`（空 = 复用 `doh_addr` 的端口号、UDP） | 需重启 |
| **`doh_alt_svc`** | string | `h3=":443"; ma=86400` | 热更新 |
| **`doh3_quic_max_idle`** | duration | `3m` | 重连生效 |
| **`doh3_quic_keepalive`** | duration | `30s` | 重连生效 |
| **`doh3_allow_0rtt`** | bool | false | 需重启 |
| `cert_store_dir` | string | `./data/certs` | 需重启 |
| `cert_default` | string | `""` | 热更新 |
| `web_tls` | bool | false | 需重启（可选） |
| `webhook_token` | string | 随机生成 | 热更新 |
| `trusted_proxies` | []string | `["127.0.0.1/32","::1/128"]` | 热更新 |
| `client_ip_sources` | []string | `["static","header","socket"]` | 热更新 |
| `client_ip_headers` | []string | `["cf-connecting-ip","x-forwarded-for","x-real-ip"]` | 热更新 |
| `client_groups` | []ClientGroup | 空 | 热更新 |
| `allow_acls` | []string | 空（不限） | 热更新 |

**SQLite**：`client_groups` 与 `trusted_proxies` 随 `settings` 单行 JSON 存（与 `split_lists` 同法，零表结构改动）；`certs` 走新表。

**新增 API**

| 方法 | 路径 | 用途 | 鉴权 |
|---|---|---|---|
| GET/POST | `/api/certs` | 列表 / 上传 | 管理端 |
| DELETE | `/api/certs/{id}` | 删除 | 管理端 |
| POST | `/api/certs/reload` | 重扫目录并热加载（SSH 路径用） | 管理端 |
| GET | `/api/certs/download-config` | 返回可复制的 webhook URL + 字段映射模板 | 管理端 |
| POST | `/api/certs/deploy` | **对外 webhook 入口** | token |

**热更新接线**：`ApplyConfig` 中把证书 store 与客户端分组路由注册进热更新链；客户端分组变更需与 `splitListsRoutingChanged` 同理**清空缓存**（分组变更后旧缓存不再适用）。

### 4.6 安全与滥用防护（公网暴露前提）

| 面 | 措施 |
|---|---|
| 开放解析器 | `allow_acls` 来源白名单；每 IP QPS 限速（超出 REFUSED 或静默丢弃）；未授权来源的 `RD=1` 直接 REFUSED（可扩展现有 RD 处理分支） |
| 放大攻击 | 响应截断已实现（`writeResponse` 的 TC 位）；**明文 `:53` 不宜暴露公网**；DoH3 走 UDP 放大面低于明文 DNS 但仍需限速 |
| QUIC 特有 | 限制并发连接数（防 QUIC 握手风暴）；0-RTT 默认关闭 |
| 私钥保护 | `0600` 权限、日志脱敏、API 响应**永不返回私钥内容** |
| 管理端 | 强烈建议本轮加 Token/Basic 鉴权（G7），否则证书一旦对外，`/api/certs` 会泄漏私钥 |
| Webhook | token 强度要求 + 可轮换 + 可选 IP 白名单 + 请求体大小上限 |
| XFF 伪造 | 仅信任 `trusted_proxies` 的 header |

---

## 5. 风险与取舍

| 风险 | 影响 | 缓解 |
|---|---|---|
| 缓存跨组串味 | **错答**（正确性） | §4.3 的 `scope` 化 key；改前先补缓存隔离的回归用例 |
| 缓存命中率下降 | 性能 | 分组粒度取粗、组内共享；管理端暴露分组缓存占比 |
| XFF 伪造绕过分流 | 策略失效 | trusted_proxies 白名单 + XFF 从右向左取值 |
| **UDP/443 被网络阻断**（企业网、部分运营商） | DoH3 不可用 | `Alt-Svc` 让客户端自动回退 TCP DoH；文档明确「h3 是优化项而非必选」；保证纯 DoH 可用 |
| **防火墙/安全组未放通 UDP** | DoH3 静默失败、排查困难 | 部署清单显式加「UDP 端口放通」检查；启动日志打印实际监听协议与端口；`deploy_remote.sh` 自检增加 UDP 断言 |
| **quic-go 版本与 Go 工具链绑定** | 需升 Go 才能跟进新版 | §4.1.3 选路径甲（锁 v0.53.0）或乙（升 Go 1.26）；文档记录锁定版本与升级路径 |
| 走反代则 h3 无法端到端 | DoH3 形同虚设 | 决策 11 明确部署形态：h3 直连公网 or 反代支持 QUIC |
| QUIC socket 未显式关闭 | UDP 端口不释放、重启失败 | 启动/停止/优雅退出三处统一收口，`http3.Server.Close()` 必须调用 |
| 证书热加载并发 | 新连接用到坏证书 | 先校验后原子替换，失败保留旧证书 |
| 管理端无鉴权 | 私钥泄漏 | 本轮加鉴权，或强制管理端只监听 127.0.0.1 |
| 出站 `h3://` 是降级 shim（§2.3） | 误导排障 | 决策 12 三选一处置 |

---

## 6. 实施阶段（每阶段独立可验证、可回退）

| 阶段 | 内容 | 验证方式 |
|---|---|---|
| 1 | **证书托管基础设施**：目录约定 + `certs` 表 + 校验 + SNI 热加载 + 上传 API + 目录扫描 | 上传后列表可见；伪造证书被拒；换证书不用重启 |
| 2 | **DoT 入站** | `kdig +tls @host -p 853 example.com`；错误 SNI 行为符合配置 |
| 3 | **DoH 入站**（RFC 8484 GET/POST + HTTP/2）+ ACL/限速 + **`Alt-Svc` 响应头** | `curl 'https://host/dns-query?dns=<b64url>'`；非匹配路径 404、错误 Content-Type 415；响应含 `Alt-Svc` |
| 4 | **DoH3 入站**（`quic-go` 接入 + QUIC 参数 + 与 DoH 同端口共存） | `curl --http3 'https://host/dns-query?dns=<b64url>'`；`curl -v` 观察 `Alt-Svc` 后自动升级；UDP 端口在停止/重启后正确释放 |
| 5 | **客户端 IP 解析链 + ClientGroup + 缓存 scope 化** | 伪造 XFF 在非可信来源下不生效；不同来源 IP 得到不同上游结果；同域名不同分组缓存互不干扰 |
| 6 | **Webhook 证书部署** | `curl` 模拟 certd body（`{"domain","crt","key"}`）→ 落盘 + 热加载；重复推送幂等；错 token 401 |
| 7 | **（依决策 12）出站 `h3://` 真实现或声明清理** | `h3://` 上游确认走 QUIC；或配置 `h3://` 时明确报错 |
| 8 | **Web 管理端**：入站服务 / 客户端分组 / 证书 三个分区 + 回归 | 页面渲染与现有分区一致；`scripts/test_web_config.sh` 25 项全绿 |

> 阶段 3 与 4 建议**同一轮做完再合并交付**：只上 DoH3 而不发 `Alt-Svc` 等于白做（见 §4.1.2a）。

---

## 7. 验收标准

- [ ] DoT：`kdig +tls` 可解析；证书 SNI 选择正确；端口变更返回 `restart_required=true`
- [ ] DoH：`GET/POST` 均可用；`Content-Type` 与方法校验；路径可配；响应带合理 `Cache-Control`
- [ ] **DoH3：`curl --http3` 可解析；`Alt-Svc` 由 h2 端点下发且端口正确；UDP 被阻断时客户端能自动回退 TCP DoH 且服务不中断**
- [ ] **DoH3：UDP 端口在停止/重启/优雅退出后正确释放（无 socket 泄漏）**
- [ ] 证书三来源（上传 / SSH 目录 / webhook）均能在列表看到；配对校验与幂等生效；**热加载不需要重启**；**TLS 与 QUIC 共用同一证书来源**
- [ ] 客户端 IP 三来源 + 优先级可配；非可信来源的伪造 header 被忽略
- [ ] 客户端分组生效：不同来源 IP 命中不同上游；`Priority` 与顺序语义符合文档描述
- [ ] 缓存隔离：同域名在不同分组下分别命中，**不串味**
- [ ] 防护：ACL 拒绝非白名单来源；限速触发后返回符合预期；QUIC 并发连接数受限
- [ ] 现有 `go test ./...` 与 E2E 25 项全绿；**现有 API 字段与响应结构零破坏**
- [ ] 依赖：锁定的 `quic-go` 版本在本机构建与 `make build-linux` 交叉编译下均通过

---

## 8. 明确不做（Out of Scope）

- 不做 ACME 自动申请与续签（证书由外部平台申请后推送；如需内置 ACME 另立需求）
- 不做 WebTransport / MASQUE（CONNECT-UDP）/ CONNECT-IP —— 仅用 QUIC 承载 HTTP/3
- 不做多用户 / 多租户 / 审计日志系统
- 不改动现有域名分流的语义、字段名与匹配顺序
- 不做精细 GeoIP 定位（如需地域维度，用可下载的 IP 段库做国内外/运营商粗判，零 cgo 依赖）
- 不重构 Web 管理端整体 UI（沿用 `WEB_UI_REDESIGN_PDR.md` 的进度，本 PDR 只新增分区）

> 注：DoH3 **已从上一版的「不做」移入正式范围**（R3）。

---

## 9. 待确认决策

| # | 决策点 | 选项 | 推荐 |
|---|---|---|---|
| 1 | 「按公共 IP 分流」的语义 | (a) 地域/运营商 (b) CIDR→上游 (c) 准入白名单 | **统一为 ClientGroup 抽象，(b)(c) 零依赖先做，(a) 可选 IP 段库** |
| 2 | 客户端分组 与 域名分流 的关系 | X 两段正交 / Y 单链有序 | **X**（附 `AllowDomainSplit` 降级开关） |
| 3 | 客户端 IP 来源与默认优先级 | 顺序可配 / 固定 | **static > header > socket**，header 仅信 trusted_proxies |
| 4 | 是否需要「token/SNI 维度」识别设备 | 做 / 不做 | **本轮不做**，列为后续 |
| 5 | DoH/DoT/DoH3 是否公网暴露 | 公网 / 仅内网 / 仅反代后端 | 决定 ACL、限速、管理端鉴权是否本轮必做 |
| 6 | 管理端是否本轮加鉴权 | 加 / 不加 | **建议加**（否则 `/api/certs` 泄漏私钥） |
| 7 | 证书存储位置 | 文件系统 + 元数据表 / 全量入库 | **私钥只落文件系统**，不入库 |
| 8 | Webhook 鉴权方式 | URL token / HMAC / IP 白名单 | **URL token 起步**，预留 HMAC |
| 9 | 缓存隔离策略 | `scope` 化 key / 分组跳过缓存 | **`scope` 化**，跳过缓存仅作降级开关 |
| 10 | 证书过期后的降级策略 | 拒绝新连接 / 继续用旧证书 | 待定（影响可用性 vs 安全性） |
| 11 | **部署形态**：h3 直连还是反代 | 本服务直连公网 UDP / 反代需支持 QUIC | **h3 直连公网 UDP**，反代仅代理 TCP 侧 —— 否则 h3 无法端到端 |
| 12 | **出站 `h3://` 的处置**（§2.3） | 真实现 / 移除声明并报错 / 降级改 Warn + UI 标注 | **真实现**（与入站共用依赖，顺带兑现「减少连接开销」） |
| 13 | **0-RTT 是否开启** | 开 / 关 | **默认关**，提供开关 |
| 14 | **quic-go 版本与工具链** | 甲：锁 v0.53.0（Go 1.23，零工具链变更） / 乙：升 Go 1.26 + v0.63.0 | **甲先落地**（快速验证），后续排期走乙 |

---

## 10. 附：与现有 `WEB_UI_REDESIGN_PDR.md` 的关系

两份 PDR 互不冲突：UI 重设计负责**外壳与信息架构**（侧栏 / 分区 / 脏状态 / 校验），本 PDR 只**新增三个分区与字段**。建议顺序：先落本 PDR 的后端能力（阶段 1–6），再做 UI 重设计时把「入站服务 / 客户端分组 / 证书」三个分区一并纳入同一套外壳，避免 UI 返工。
