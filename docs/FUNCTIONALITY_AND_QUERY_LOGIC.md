# dnsPorxy 功能说明与查询业务逻辑

> 本文档总结系统功能、查询业务逻辑（重构后），以及本次协议修复与配置简化的修改流程。
> 问题清单依据见 [DNS_STANDARDS_ANALYSIS.md](DNS_STANDARDS_ANALYSIS.md)。

## 一、功能总览

dnsPorxy 是一个 DNS 代理服务器（默认监听 UDP/TCP `:53`），核心能力：

| 功能 | 说明 | 主要实现 |
|---|---|---|
| 上游并发查询 | 多上游 fastest-wins，首个成功响应胜出 | `query.go` / `fast_query_optimizer.go` / `modern_query.go` |
| 分片 LRU 缓存 | 16 分片 + singleflight 防穿透 + 对象池复用 | `optimized_cache.go` |
| 缓存 TTL 递减 | 命中返回副本并按缓存时长递减 TTL（RFC 1035 §4.3.1） | `optimized_cache.go` `decrementTTLs` |
| 负缓存 | NXDOMAIN 等失败响应按 RFC 2308 取 SOA.MINIMUM 缓存 | `cache_manager.go` `soaNegativeTTL` |
| 云 IP 检测与替换 | 识别 Cloudflare / AWS 域名，用替换域名 IP 顶替 | `cloud_detector.go` / `cloud_handler.go` |
| 中国域名分流 | 中国域名走 `china_dns`（如 223.5.5.5） | `handler.go` `determineUpstreamsForDomain` |
| 定向域名分流 | 指定域名走其专属 DNS | `matcher_handler.go` + `data/designated.yaml` |
| 异步刷新 | 缓存过期后后台回源刷新，失败时延长 TTL 防雪崩 | `refresh_handler.go` |
| serve-stale | 过期缓存兜底返回 5s TTL，后台触发刷新 | `optimized_cache.go` |

## 二、查询业务逻辑（重构后）

### 2.1 主流程

```
客户端请求
  │
  ▼
ServeDNS（handler.go）
  │  协议守卫（不合法直接回错误，不再静默丢弃）：
  │   • QR=1 → 忽略          • Opcode≠QUERY → NOTIMP
  │   • 空Question/QDCOUNT>1/非法域名 → FORMERR
  │   • RD=0 → 仅用缓存，未命中回 REFUSED
  ▼
缓存查询（cache_manager.Get / GetWithFlight / GetCloudResponse）
  │  命中：返回副本 + TTL 递减；云域名返回替换响应缓存
  │  过期：serve-stale 兜底（5s TTL）+ 触发异步刷新
  ▼
未命中 ────────────────────────────────────────────────┐
  │                                                     │
  ▼                                                     │
processQuery（仅 A/AAAA）                               │
  │  1. proxyQueryWithCaching 查询上游并缓存【原始响应】  │
  │  2. CollectChainIPs 沿 CNAME 链（仅查缓存）收集 IP   │
  │  3. cloudDetector.DetectCloudService 做一次云检测     │
  │                                                     │
  ├─ 云域名 → HandleCloudReplacement                    │
  │     ResolveReplaceIPs（查替换域名，含缓存）           │
  │     buildCloudResponse：保持上游结构，仅替换 IP 值    │
  │     SetCloudResponse（customTTL = ReplaceCacheTime） │
  │                                                     │
  └─ 非云 → 原样透传                                    │
  │                                                     │
processNonIPQuery（其他 qtype）→ 透传 + rcode 校验       │
  │                                                     │
  ▼                                                     ▼
writeResponse（统一响应出口）◄──────────────────────────┘
  • 回写原始 Id / Question（保留 QNAME 大小写）
  • 清 AD 位（响应被修改后不得保留认证数据）
  • 去重 OPT 并按客户端声明回带 EDNS
  • UDP 按 512 / 客户端 bufsize 截断（TC=1）
```

### 2.2 关键设计原则

1. **响应结构不被改写**：缓存与透传全程保存上游原始响应；CNAME 链的 owner、TTL、RRset 原子性完整保留（原"owner 重写为查询域名 + A/AAAA 裁剪到 2 条"逻辑已全部移除）。
2. **云检测只做一次**：统一在 `processQuery` 执行；缓存写入路径（`CacheManager.Set/SetWithTTL`）和查询路径（`proxyQueryWithCaching`）不再重复检测（原三重检测已消除）。
3. **云替换不改变响应形状**：`buildCloudResponse` 复制上游响应，仅将 Answer 中 A/AAAA 记录的 IP 值轮询替换为替换域名 IP；上游响应无 IP 记录时才回退为 `owner=查询域名` 的仅 IP 形状。
4. **所有响应走同一出口**：`writeResponse` 保证 EDNS/TC/AD 处理一致，云路径错误响应也经此出口。
5. **异步刷新与查询路径一致**：云域名刷新通过 `rebuildCloud` 回调（内部即 `ResolveReplaceIPs` + `buildCloudResponse`）重建替换响应，避免刷新缓存与查询结果形状不一致。

### 2.3 缓存行为

- 写入：遵循上游最小 TTL（原"配置 TTL 作为最小值抬高"逻辑已删除）；无有效 TTL 时用 `cache.ttl` 兜底。
- 命中：返回副本并按 `now - storedAt` 递减 TTL，下限 0，跳过 OPT。
- 失败响应（rcode≠Success）：按 SOA.MINIMUM 负缓存（原固定 5s 已修正）。
- 云替换响应：`SetCloudResponse` 使用 `cloud.replace_cache_time`。

## 三、本次修改流程

### 3.1 修改顺序（按 docs 落地计划 1-5，跳过 6）

1. **修死锁**（server.go）：`Start()` 锁内只做状态检查 + listener 创建，解锁后再 `ActivateAndServe()`。
2. **TTL 递减**（optimized_cache.go）：`CacheEntry` 增加 `StoredAt`，新增 `decrementTTLs`，命中统一返回副本。
3. **去 CNAME 重写**（cname_processor.go / cloud_handler.go）：四个处理入口改透传；云替换改为结构保持的 IP 替换。
4. **FORMERR**（handler.go）：ServeDNS 增加协议守卫。
5. **EDNS + Truncate**（handler.go）：新增 `writeResponse` 统一出口。

### 3.2 配套改动

- **query.go**：`proxyQueryWithCaching` 删除 `skipCloudDetection` 参数与内部云检测/CNAME 处理，简化为"查询 + 缓存原始响应"。
- **refresh_handler.go**：`NewRefreshHandler` 增加 `rebuildCloud` 回调；5 处 `processDNSResponseWithCNAME + ensureMinimumTTL` 改为直接缓存原始响应；删除包级死代码 `processDNSResponseWithCNAME` / `processCloudResponse` / `ensureMinimumTTL`。
- **cache_manager.go**：删除 `cloudDetector` 字段（检测上移）与孤立的 `calculateTTL`；失败响应改用 `soaNegativeTTL`。
- **config.go / config.yaml**：删除 11 个死字段（`upstream_servers`、`cf_mrs_file_*`、`aws_mrs_file46`、`whitelist_file`、`tls_cert_file`/`tls_key_file`、`no_answer_cache_time` 等）；`ReplaceCacheTime` 改为 `time.Duration`；补齐默认值。（该轮之后配置已整体迁到 SQLite `data/config.db`，`config.yaml` 与 `DefaultConfigPath` 均已不存在。）

### 3.3 验证记录（全部通过）

| 验证项 | 结果 |
|---|---|
| `go build ./...` / `go vet ./...` | 通过 |
| TTL 递减 | 231 → 221 → 219 |
| CNAME owner 保持（www.bing.com） | 链式 owner 完整保留 |
| 畸形包（QDCOUNT=0） | 回 FORMERR，不再静默丢弃 |
| 大响应（microsoft.com TXT） | UDP 置 TC=1，TCP 取回 1194 字节完整响应 |
| SIGTERM 退出 | 2 秒（原永久死锁） |
| RD=0 | 未命中 REFUSED，命中返回缓存 |
| AD 位 | +adflag 请求响应中 AD 已清除 |

### 3.4 遗留事项

1. **priority_test.go 编译失败**（预存在）：引用从未实现的 `NewDesignatedMatcher` / `DesignatedDomain`，导致 `go test ./internal/dns` 无法构建，需另行修复。
2. **data/designated.yaml 数据问题**（预存在）：`udp://58.20.127.170` 缺端口号，导致定向域名 SERVFAIL。
3. **P2 结构性问题**未动：`queryOptimizer interface{}` 类型断言、`cloud_processor.go` / `cloud_handler.go` 中预存在死代码（`replaceCloudIPs`、`processDNSResponseWithCNAMERFC`、`processCNAMEChainWithFullPath` 等），建议后续清理。
4. serve-stale 保留现有"过期即返回 5s TTL"行为，未改为仅上游失败时兜底。
