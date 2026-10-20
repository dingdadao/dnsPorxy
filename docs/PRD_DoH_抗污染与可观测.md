# PRD · DoH 抗污染 + 解析日志 / 统计报表增强

> 版本：v1　状态：评审中　作者：DnsProxy 产品

---

## 1. 定位澄清（最重要）

**核心是「本地代理 DNS 服务」**：统一加密出口（UDP/TCP/DoH/DoT/DoH3），对客户端提供干净的解析。本 PRD 不扩大成一个大分流引擎。

本次需求聚焦两点：

- **A｜DoH 抗污染**：公网的公共 DoH（如 8.8.8.8、1.1.1.1）在部分网络被污染 → 移动设备拿到错误/慢的 IP。解决方式是**移动设备把 DNS 指到本服务**，本服务做干净解析，并保证自身出口不被污染。
- **B｜可观测**：在解析日志与统计报表上做增强，支持按来源筛选、标记污染/异常、分协议统计，服务态可视化与污染复盘。

> **明确不做**：运营商自动分组、省市区地理定位、CDN 就近优选、离线 IP 库下载等「智能分流 v2」整套体系。若后续要做，另行立 PRD。本次复用现有「客户端 IP 分流」能力即可。

---

## 2. 背景与目标

### 2.1 场景
- 公网公共 DoH/DNS 被污染，移动设备解析出错。
- 移动设备无法依赖公共 DoH；需要一个**可信、不被污染的本服务出口**。

### 2.2 业务目标
| # | 目标 |
|---|---|
| G1 | 移动设备可安全地把 DNS 指向本服务（DoH3/DoT/DoH），获得干净解析 |
| G2 | 本服务自身出口不被公共 DoH 污染拖累：为不同来源复用现有分组选安全上游 + 污染检测回退 |
| G3 | 解析日志可按「来源维度」筛选，并能标记「污染/异常」 |
| G4 | 统计报表补充：协议占比、来源分布、污染/回退统计（TOP/QPS 趋势已具备） |

---

## 3. 需求 A：DoH 抗污染

### 3.1 设计原则
> 「就是目前的客户端 IP 分流功能，复用现在的 DNS 逻辑，只是处理一些配置上的差异。」——用户定调

不新建路由引擎。在现有 `ClientGroup`（[client_group.go](file:///Users/dension/GolandProjects/dnsPorxy/internal/dns/client_group.go#L136-L148)：按来源 IP → 上游/DNSMode/ECS/IPPrefer/AllowDomainSplit）+ 现有 [query.go](file:///Users/dension/GolandProjects/dnsPorxy/internal/dns/query.go)（上游竞速/failover + BackupDNS 回退）之上，做**配置面增强**。

### 3.2 配置差异点（新增/扩展）
对现有 `ClientGroup` 增加「加密出口 + 污染防护」相关字段：

| 字段 | 说明 |
|---|---|
| `dns`（扩展现有） | 允许每组写 DoH/DoT/DoH3 上游（统一 URL scheme，已有能力） |
| `pollution_check` | 是否对该来源组的应答做污染检测（默认对移动组开） |
| `pollution_action` | 检测命中后的动作：`fallback`（回退备份出口）/ `mark`（仅标记日志，仍返回） |
| `fallback_dns` | 专属回退出口（缺省用全局 BackupDNS） |
| `precision` | 出口竞速策略复用现有 `race/failover` |

> 复用：来源组由移动端 IP/CIDR 命中，直接决定走哪个(组)加密上游；污染命中即回退。改动集中在 `config.go`/`json.go` + 查询收尾逻辑，不动主机执行骨架。

### 3.3 污染检测（轻量版，M2）
判定依据（任一命中即标记为 `polluted`）：
- 应答 IP 命中内置/可配污染 IP 集合（GFW/劫持 IP 段）。
- 应答重定向异常（如 CNAME 链指向已知污染域名/保留段）。
- 明显慢解析（`elapsed_ms` 超阈值）或返回空/NODATA 但期望有 A 记录。

> 检测只在 `pollution_check=true` 的来源组启用，尽量低成本、不影响主链路。

### 3.4 对外接入（复用现有加密端点）
移动设备接入三种方式（证书复用现有 DoH 证书）：
- **DoH**: `https://dns.niao.fun/dns-query`
- **DoT**: `tls://dns.niao.fun`
- **DoH3**: `h3://dns.niao.fun`（UDP 443，现有）

---

## 4. 需求 B-1：解析日志增强

### 4.1 现状（基线）
[store.go](file:///Users/dension/GolandProjects/dnsPorxy/internal/querylog/store.go#L56-L70)：`Entry` 已含 client(IP)、qtype、action、dns_mode、rcode、elapsed_ms；表 [query_logs](file:///Users/dension/GolandProjects/dnsPorxy/internal/querylog/store.go#L199-L217) 已有对应列。`Filter` 仅支持 keyword/action/qtype/时间；**client 只能靠 keyword 模糊搜，无独立来源筛选，无 protocol、无污染标记**。

### 4.2 变更
1. **新增列 `protocol`**：`udp/tcp/doh/dot/doh3`（写入口 [insertBatch](file:///Users/dension/GolandProjects/dnsPorxy/internal/querylog/store.go#L626-L647) 对应补一列；旧库 `ALTER TABLE` 兼容，历史默认空）。
2. **新增列 `anomaly`**：空 / `polluted` / `slow` / `refused` 等标记（G2 检测结果落到这里）。
3. **`Filter` 新增**独立字段：`client`（精确 IP 或 CIDR）、`protocol`、`anomaly`；并加 `buildWhere` 对应分支。
4. **UI 日志页**：筛选栏增加 协议下拉、来源输入、异常下拉；污染行高亮。

---

## 5. 需求 B-2：统计报表增强

### 5.1 现状（基线）
`Summary`（[store.go](file:///Users/dension/GolandProjects/dnsPorxy/internal/querylog/store.go#L103-L121)）已有 **TopDomains、ByDay(QPS 趋势)、ByAction、ByQType、ByRcode、ByList**。

### 5.2 新增（补齐 4 类）
| 维度 | 说明 |
|---|---|
| **协议占比 ByProtocol** | 按 `protocol` 列 GROUP BY，饼图/占比卡 |
| **来源分布 ByClient** | 按 `client` GROUP BY，TOP 来源；可选叠加 ISP/地域标注（见「待确认」） |
| **污染/回退统计** | `polluted` 命中总数、回退次数、污染率（`polluted/total`） |
| **TOP/QPS 趋势** | 已有，仅统一 UI 展示与维度切换即可，无需新聚合 |

---

## 6. 数据与 schema 变更（增量汇总）

- `query_logs`：`ALTER TABLE ADD COLUMN protocol TEXT`、`ADD COLUMN anomaly TEXT`（[initSchema](file:///Users/dension/GolandProjects/dnsPorxy/internal/querylog/store.go#L192-L222)）。
- `Entry` / `insertBatch` / `Query` SELECT 列新增对应字段。
- `Filter`：新增 `client / protocol / anomaly`；`buildWhere` 扩展。
- `Summary`：新增 `ByProtocol`、`ByClient`、（`Polluted/Recount` 计数）。
- `config`：`ClientGroup` 加 `pollution_check / pollution_action / fallback_dns`（见 §3.2）。

> 兼容：新增列均可为空/默认，不影响旧数据与旧查询；写入异步、`ActionError/Filtered` 等既有枚举不变。

---

## 7. 里程碑

| M | 内容 | 交付 |
|---|---|---|
| M1 | 日志加 `protocol` 列 + 来源/协议筛选（Filter+UI） | G3 基础 |
| M2 | 污染检测与 `anomaly` 标记 + 回退动作 | G2 |
| M3 | 统计新增 协议占比 / 来源分布 / 污染回退卡 | G4 |
| M4 | 配置面：来源分组加密出口 + 污染防护参数（复用现有分流） | G1/G2 配置闭环 |
| M5 | 移动端对外接入（DoH3/DoT/DoH）验证 | G1 落地 |

> M1→M3 均为增量、向后兼容，可独立灰度；M4 是本次主线，M5 为收尾验证。

---

## 8. 待确认问题（评审）

1. 污染判定采用**固定 IP 列表**还是**行为判定**（慢解析/重定向）为主？我先按「列表为主 + 慢解析为辅」设计，是否需要可配列表来源？
2. `pollution_action=fallback` 时，回退出口是**每组专属**还是**全局 BackupDNS** 即可？倾向「缺省全局、可覆盖」。
3. 历史 `protocol` 是否需要回填？建议不回填（新列默认空，仅新记录生效）——是否可接受？
4. 来源分布是否要标注 ISP/地域？目前不建议（避免引 IP 库依赖），后续有需要再立 PRD。
5. `anomaly` 标记是否需要在查询过滤时即可见（是）且导出 CSV？（可选）