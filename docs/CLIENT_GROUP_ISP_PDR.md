# 客户端分组（按运营商）重构 · PDR（产品设计需求文档）

- 项目：dnsPorxy DNS 代理
- 日期：2026-10-10
- 状态：**待评审**（需求已澄清，设计待拍板；本文件为方案稿，未开工）
- 定位：**修订**《INBOUND_TLS_AND_CLIENT_SPLIT_PDR.md》§4.3「特性 B-2 · 客户端分组 ClientGroup」。入站加密服务（DoT/DoH/DoH3）与证书托管部分**不受影响**。
- 边界：本轮**只重做客户端分组的语义与 UI**；不动域名分流列表（`split_lists`）的匹配语义，不动出站协议与缓存结构。

> **一句话目标**：客户端分组不再由用户"起名字 + 手填 IP/CIDR + 取反"决定，而是**程序按运营商（电信/移动/联通/其他）固定分组**；每个分组只需回答两件事——「**引用哪些域名分流规则**」和「**兜底 DNS 是什么**」。

---

## 1. 背景与需求拆解

现网反馈：客户端分组"不符合预期"——配了不生效、甚至把域名分流整个带偏。原始诉求逐条拆解：

| 编号 | 需求原文                              | 归属    | 备注                     |
| -- | --------------------------------- | ----- | ---------------------- |
| R1 | 分组应按 **电信 / 移动 / 联通 / 其他**，不是"名称" | 分组模型  | 分组标识固定，不可自定义           |
| R2 | 应该**程序固定进行匹配分流**                  | 匹配机制  | 用运营商段库自动判定来源，无需用户填 IP  |
| R3 | 看来源是电信/移动/联通，**IPv4/IPv6 都要匹配**   | 数据源   | 段库需 v4+v6 双栈           |
| R4 | 匹配可以更详细点，**铁通**什么的                | 细分运营商 | 细分是否单列待定（见决策 2、3）      |
| R5 | **取反匹配逻辑完全冲突**，应复用"上游与域名分流"的规则    | 语义清理  | 移除客户端分组级 invert        |
| R6 | 给一个**下拉框**来进行匹配                   | UI    | 下拉引用 `split_lists`     |
| R7 | 看看走哪些分流规则，**有一个兜底 DNS**           | 路由    | 组内兜底上游                 |
| R8 | 分流都不是才走这个 DNS，**相当于覆写上游 DNS**     | 路由    | 兜底 DNS 覆盖全局 `upstream` |

**核心心智**：`先定人（运营商）→ 再定域名（分流规则）→ 都不中走兜底`。

---

## 2. 现状审计

### 2.1 现有实现（事实）

| 层    | 位置                                            | 现状                                                                                                                      |
| ---- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 结构体  | `internal/config/config.go:136` `ClientGroup` | `Name / Enabled / Priority / Match[] / Invert / DNS[] / DNSMode / ECS / EnableCloudCheck / IPPrefer / AllowDomainSplit` |
| 匹配器  | `internal/dns/client_group.go`                | 按 `Priority` 降序；`Match` 逐项判 `isp:<name>`、CIDR、裸 IP；最后按 `Invert` 翻转                                                      |
| 运营商库 | `internal/source/isp.go`                      | 二进制前缀树 + 最长前缀匹配；枚举 `telecom/unicom/cmcc/cernet/chinabtn/gwbn/other`                                                     |
| 数据下载 | `internal/source/update.go`                   | 仅下载 6 个文件（无 `othernet`、无 `hk/mo/tw`）                                                                                    |
| 落库   | `internal/config/json.go`                     | `client_groups` 随 `settings` 单行 JSON 存                                                                                  |
| 路由接线 | `internal/dns/handler.go:748-763`、`945-987`   | `scope = 分组名`；命中组 + `AllowDomainSplit=false` → 直接用组 DNS；否则继续域名分流                                                        |
| 管理端  | `internal/web/admin.html:950-1083`            | 自由分组卡片：名称 / 优先级 / 匹配 IP·CIDR / 取反 / DNS / 继续域名分流 / ECS                                                                  |

### 2.2 问题清单（按严重度）

| #       | 问题                                                                                                   | 证据                                                                                                                                                                       | 严重度    |
| ------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| **P1**  | **管理端没有「运营商识别」的任何开关**                                                                                | `admin.html` 全文检索 `source_enabled` / `source_db_dir` / `运营商` 均无结果；`ConfigJSON` 里字段存在但前端不渲染                                                                               | **致命** |
| **P2**  | 因此 `SourceEnabled` 默认 `false`、`SourceDBDir` 默认 `""` → `SetISPLookup` 从不调用 → **`isp:xxx` 匹配项永远静默不命中** | `handler.go:215` `if cfg.SourceEnabled && cfg.SourceDBDir != ""`；本机 `data/config.db` 的 `client_groups:[]` 且无 `source_*` 键                                                | **致命** |
| **P3**  | 用户只能手填 IP/CIDR 来表达"电信/移动/联通"，**没有"程序自动按运营商分组"这条路**                                                   | 需求 R1/R2 完全未被满足                                                                                                                                                          | 高      |
| **P4**  | **分组级的 ECS / A·AAAA 偏好 / 云检测 三项配置全部不生效**                                                             | `handler.go:759-762` 只重算了一遍日志字段，未注入；`handler.go:756` 构造 `SplitDecision` 时**未拷贝** ECS/IPPrefer/EnableCloudCheck；`ip_prefer.go:13`、`handler.go:829` 只读 `decision`（=域名分流决策） | 高      |
| **P5**  | `AllowDomainSplit=false` 时**强制跳过云检测**                                                                | 该分支 `decision.EnableCloudCheck` 为零值 `false` → `handler.go:796` 命中"跳过云检测"                                                                                                 | 高      |
| **P6**  | `Invert` 与域名分流列表的 `Invert` **同名不同义，UI 都叫"取反匹配"**                                                     | `admin.html:906`（分流列表）vs `admin.html:1033`（客户端分组）；`matcher_handler.go:156`（域名）vs `client_group.go:139`（IP）                                                               | 高      |
| **P7**  | 取反组会"命中一切非清单来源"，配合 `AllowDomainSplit` 默认语义可**整体吞掉域名分流**                                              | 取反组几乎必中 → 若该组 `allow_domain_split=false`，所有域名都不再走分流                                                                                                                      | 高      |
| **P8**  | `scope = 分组名` → **改名即缓存全失效；重名即跨组串味**                                                                 | `handler.go:964`、`968-987`                                                                                                                                               | 中      |
| **P9**  | `othernet`（中国其他 ISP，2887 条）**未下载、未识别** → "其他"组只能靠"未命中"兜底，无法真正识别                                      | `update.go:22` `fileNameFor` 无 othernet；`loader.go:47` `filenameISP` 无 othernet                                                                                          | 中      |
| **P10** | 分组需要用户手工维护 `priority`，但运营商本身是**互斥且唯一**的，优先级是多余概念                                                     | `config.go:139`                                                                                                                                                          | 低      |

### 2.3 数据源实况（`https://ispip.clang.cn`，2026-10-10 实测）

| 文件                       | 描述            | 条数            | 本项目当前        |
| ------------------------ | ------------- | ------------- | ------------ |
| `chinatelecom_ipv46.txt` | 中国电信          | 1946          | ✅ 已用         |
| `unicom_cnc_ipv46.txt`   | 中国联通          | 1970          | ✅ 已用         |
| `cmcc_ipv46.txt`         | **中国移动（含铁通）** | 386           | ✅ 已用         |
| `cernet_ipv46.txt`       | 中国教育网         | 127           | ✅ 已用         |
| `chinabtn_ipv46.txt`     | 中国广电          | 43            | ✅ 已用         |
| `gwbn_ipv46.txt`         | 电信通/长城宽带/鹏博士  | 70            | ✅ 已用         |
| `othernet_ipv46.txt`     | **中国其他 ISP**  | **2887**      | ❌ **缺失（P9）** |
| `hk/mo/tw_ipv46.txt`     | 中国香港/澳门/台湾    | 8261/101/1454 | ❌ 缺失（未分类）    |
| `all_cn_ipv46.txt`       | 中国大陆汇总        | 5953          | ❌ 未用         |

> ⚠️ **关键发现（R4 铁通）**：上游数据源把铁通**并入 `cmcc`**（文件名即"中国移动(含铁通)"），**没有独立的铁通段文件**。因此"铁通单列一组"**无法仅靠当前数据源实现**——要么自备一份铁通段表，要么放弃单列。见决策 2。
>
> ⚠️ 站点自述："数据可用于大多数应用程序，但请勿用于关键任务或需要绝对准确性的系统。" → 运营商判定必须允许"判不出"，并落到"其他"组兜底。

---

## 3. 需求定性：三个必须先厘清的语义点

### 3.1 "分组"的粒度：主组 + 可细分

推荐**两层枚举**，UI 上主组常显、细分收起：

- **主组（固定 4 个）**：`电信 telecom` / `联通 unicom` / `移动 cmcc` / `其他 other`
- **可细分（默认并入主组，可单独拆出）**：`铁通` / `教育网 cernet` / `广电 chinabtn` / `长城宽带·鹏博士 gwbn` / `境外（港澳台及海外）`

细分项"不拆出"时归属其母组（如教育网未拆 → 计入"其他"；铁通未拆 → 已在 `cmcc` 内）。这样既满足 R1（4 主组），又满足 R4（可更细）。

### 3.2 分组与域名分流的关系：**由"两段正交"改为"分组引用分流规则"**

现状是两段正交：Stage1 分组给"候选上游"，Stage2 域名分流再细化。结果是两处都要写 DNS，**重复且互相打架**。

新模型（对应 R5–R8）：

```
命中分组 G（由运营商唯一确定）
   └─ 按 G.split_refs 顺序，用【上游与域名分流】里已定义的规则逐条匹配域名
         ├─ 命中第 k 条规则 → 用该规则的 DNS / 模式 / ECS / 偏好 / 云检测（语义不变）
         └─ 全部未命中     → 用 G.fallback_dns（为空则回退全局 upstream）
```

**要点**：

- 分组**不再自带一套域名规则**，规则只有一份，定义在「上游与域名分流」，分组通过**下拉框引用**（R6）。
- `fallback_dns` 就是 R8 说的"兜底 DNS，相当于覆写上游"。
- 取反（域名维度）仍保留在**分流列表**里，客户端分组**不再有取反**（R5）。
- 删除 `AllowDomainSplit`：**`split_refs` 为空 ⇔ 只走兜底 DNS**，正好等价于原 `allow_domain_split=false`，且没有"强制跳过云检测"的副作用（P5）。

### 3.3 用户填的自由字段：尽量归零

| 原字段                                        | 处置                                          | 理由                      |
| ------------------------------------------ | ------------------------------------------- | ----------------------- |
| `name`（分组名）                                | **删除**，标识固定为 ISP key                        | R1；同时修掉 P8（缓存 scope 漂移） |
| `priority`                                 | **删除**                                      | 运营商互斥唯一，无优先级可言（P10）     |
| `match`（IP/CIDR/`isp:`）                    | **删除**                                      | R2：程序自动判定               |
| `invert`                                   | **删除**                                      | R5 / P6 / P7            |
| `dns`（组级上游列表）                              | **拆为** `fallback_dns`（兜底）+ `split_refs`（引用） | R7/R8                   |
| `dns_mode`                                 | 保留，仅作用于 `fallback_dns`                      | —                       |
| `allow_domain_split`                       | **删除**，语义由 `split_refs` 是否为空表达              | 3.2                     |
| `ecs` / `ip_prefer` / `enable_cloud_check` | **默认删除**（交给分流列表），或降级为组级"默认值"（见决策 5）         | P4 —— 反正现在不生效           |
| `enabled`                                  | 保留                                          | 未启用 = 该运营商不干预，走全局默认     |

---

## 4. 设计详稿

### 4.1 配置模型

```go
// ISPKey 运营商固定分组标识（内置枚举，不可自定义）
type ISPKey string

const (
    ISPGroupTelecom ISPKey = "telecom" // 中国电信
    ISPGroupUnicom  ISPKey = "unicom"  // 中国联通
    ISPGroupCMCC    ISPKey = "cmcc"    // 中国移动（含铁通）
    ISPGroupOther   ISPKey = "other"   // 其他（未识别 / 境外 / 教育网 / 广电 / 长宽）
)

// KnownISPGroups 返回全部固定分组，顺序即 UI 展示顺序
func KnownISPGroups() []ISPKey {
    return []ISPKey{ISPGroupTelecom, ISPGroupUnicom, ISPGroupCMCC, ISPGroupOther}
}

// GroupForISP 把段库识别出的运营商收敛到 4 个固定分组（source.ISP → ISPKey）
func GroupForISP(isp source.ISP, ok bool) ISPKey {
    if !ok {
        return ISPGroupOther // 判不出 → 其他
    }
    switch isp {
    case source.ISPTelecom:
        return ISPGroupTelecom
    case source.ISPUnicom:
        return ISPGroupUnicom
    case source.ISPCMCC:
        return ISPGroupCMCC
    default: // cernet / chinabtn / gwbn / othernet / 未识别
        return ISPGroupOther
    }
}

// ClientGroup 客户端分组（按运营商固定分组）
type ClientGroup struct {
    ISP              ISPKey        // 固定标识（分组唯一键，决定缓存 scope）
    Enabled          bool          // 未启用 = 不干预，走全局默认
    SplitRefs        []string      // 引用「上游与域名分流」里的列表（按 name 引用，顺序即匹配顺序）
    FallbackDNS      []string      // 兜底上游：分流规则全部未命中时使用；为空则回退全局 upstream
    DNSMode          string        // race / failover，仅作用于 FallbackDNS
    // —— 以下为可选"组级默认"，默认留空表示不干预（见决策 5）
    ECS              ECSPolicy
    IPPrefer         string
    EnableCloudCheck bool
}
```


- 数组 **不再需要优先级**：一个运营商只对应一个分组；配置里按内置顺序存即可。
- `SplitRefs` 引用的是 **`SplitList.Name`**。名字可改 → 悬空引用风险，故校验必须拦住（§4.5），并把"被引用"状态回显到分流列表 UI。若嫌 name 不稳，可改为引入稳定的 `id`（见决策 9）。

### 4.2 匹配与路由流程

**匹配阶段**（`resolveClientAndScope`，每次查询一次）：

```
1. 解析客户端 IP（现有 static > header > socket 链，不变）
2. isp, ok := ispDB.Lookup(ip)          // O(位长) 最长前缀匹配，v4/v6 双栈
3. key := ok ? isp : ISPGroupOther        // 判不出 → 其他
4. key = 细分归并(key)                    // 未单独启用的细分归入母组
5. scope = string(key)                    // 缓存隔离标识，固定不可变
6. group := groups[key]（未配置/未启用 → 走全局默认，scope = "-"）
```

**路由阶段**（`processQuery`）：

```
if group 命中:
    对 group.SplitRefs 逐条（按引用顺序）→ 若该 SplitList 命中域名：
        用该 SplitList 的 DNS/Mode/ECS/IPPrefer/EnableCloudCheck（沿用现有 SplitDecision，语义零改动）
    else:
        upstreams = group.FallbackDNS 非空 ? group.FallbackDNS : cfg.Upstream
```

**关键收益**：

- 分组不再"自带 DNS 列表"，`upstreamsFor` 只需一处兜底分支；
- 三项组级配置的"死代码"问题（P4）随字段删除自然消失；
- `AllowDomainSplit` 删除后 P5 消失。

### 4.3 数据源改造

| 改动                       | 位置                               | 说明                                                                |
| ------------------------ | -------------------------------- | ----------------------------------------------------------------- |
| 补下载 `othernet_ipv46.txt` | `source/update.go` `fileNameFor` | 让"其他"组可被真正识别（P9）                                                  |
| 识别 othernet 文件           | `source/loader.go` `filenameISP` | 同上                                                                |
| 可选下载 `hk/mo/tw`          | 同上                               | 支撑"境外"单列（决策 1）                                                    |
| ISP 枚举扩展                 | `source/isp.go`                  | 新增 `othernet` / `oversea`；`tietong` 视决策 2                         |
| **默认开启识别**               | `DefaultConfig()`                | `SourceEnabled=true`、`SourceDBDir=./data/ispdb`；否则 R2 无从谈起（P1/P2） |
| 补管理端分区                   | `admin.html`                     | 「客户端 IP 分流」分区内新增"运营商识别"卡片（开关/目录/更新间隔/立即更新）                        |

> 铁通、境外的段表来源需单独确认，见决策 1、2。

### 4.4 缓存

- `scope` 由"分组名"改为 **ISP key**（`telecom`/`unicom`/…/`other`），**不随任何用户编辑漂移**（修 P8）。
- 未命中分组 / 分组未启用 → `scope = "-"`（沿用现状）。
- 缓存键仍为 `scope|domain|qtype`，结构不变。
- **取舍照旧**：按运营商分组 → 同域名最多存 4 份（主组）。建议 UI 标注"分组数 = 缓存条目放大倍数"，并在「解析日志」页按 scope 统计占比。

### 4.5 管理与校验

**Web 管理端**（改造 `admin.html` 的 `clientgroups` 编辑器）：

- 结构：**固定分组表格**（每行一个运营商），不再是"可增删的自由卡片"。
  | 启用 | 分组 | 引用分流规则（下拉多选/有序） | 兜底 DNS                        | 高级 |
  | -- | -- | --------------- | ----------------------------- | -- |
  | ☑  | 电信 | `定向域名` `中国域名` ＋ | `https://223.6.6.6/dns-query` | ▾  |
- 下拉选项来源 = 当前 `CFG.split_lists[].name`；已停用/未加载的列表标注状态。
- 每个分组行右侧显示"引用它的分组"角标（反向提示），便于判断能否删除某条分流列表。
- 移除：分组名称输入框、优先级输入框、匹配 IP/CIDR 行编辑器、取反开关、"继续进入域名分流"开关。

**校验（`ValidateConfig` + 前端 `validateClientGroups`）**：

1. `ISP` 必须是内置枚举；
2. `SplitRefs` 里每个 name 必须在 `split_lists` 中存在且 `enabled`（否则 400 + 明确报错；悬空引用会导致"静默兜底"，很难排查）；
3. `FallbackDNS` 走现有 `normalizeUpstreamList`（补默认端口）；
4. 同一 `ISP` 不允许重复；
5. 分组启用但 `SplitRefs` 为空且 `FallbackDNS` 为空 → 允许（= 完全走全局默认），但前端给提示。

**热更新**：

- `ISP 启用状态 / SplitRefs / FallbackDNS` 均可热更新，变更后**清缓存**（复用现有 `clientGroupsRoutingChanged` → 改为新字段比对）。
- **"运营商识别"开关与目录**改动需重启（与 `EnableDoT` 同类）；段库**内容刷新**热加载（现有 `ReloadFromDir` 原子换快照，零重启）。

### 4.6 旧配置迁移

启动/保存时按下列规则迁移（一次性，幂等）：

| 旧                                         | 新                                                     |
| ----------------------------------------- | ----------------------------------------------------- |
| `match: ["isp:telecom"]`                  | `ISP = telecom`                                       |
| `match: ["1.2.3.0/24"]`（无法映射运营商）          | **保留为"自定义组"**&#x6216;提示人工处理（见决策 10）                   |
| `invert: true`                            | 丢弃，UI 提示"取反已移除"                                       |
| `allow_domain_split: false`               | 映射为 `SplitRefs = []` + `FallbackDNS = 原 DNS`          |
| `dns: [...]` + `allow_domain_split: true` | `FallbackDNS = 原 DNS`；`SplitRefs = 原全局 all`（或空，见决策 6） |
| `priority` / `name`                       | 丢弃（name 用于日志的历史字段可保留展示）                               |

---

## 5. 风险与取舍

| 风险                         | 影响           | 缓解                                           |
| -------------------------- | ------------ | -------------------------------------------- |
| 段库准确率有限（站点自述不保证）           | 判错运营商 → 走错上游 | 允许判不出 → "其他"兜底；UI 可查某 IP 的判定结果               |
| 缓存命中率下降                    | 性能           | 主组收敛到 4 个；UI 展示分组缓存占比                        |
| 悬空引用（删了被引用的分流列表）           | 静默兜底，难排查     | 保存时强校验 + 反向角标                                |
| `SplitRefs` 用 name 引用，改名即断 | 配置脆弱         | 强校验；或改 ID 引用（决策 9）                           |
| "其他/境外"边界模糊                | 策略误伤         | 决策 1 明确；默认不拆境外                               |
| 铁通无独立数据源                   | R4 部分落空      | 决策 2：自备段表 / 放弃单列 / 换数据源                      |
| 默认开启运营商识别会引入启动期下载          | 首启慢/无网       | 内置 `data/ispdb` 随包；下载失败降级为"全部其他"并 Warn，不阻塞启动 |

## 7. 验收标准

- [ ] 客户端为**电信**来源（v4 与 v6 各测一次）时，自动命中"电信"组，**无需用户填任何 IP**
- [ ] 未配置/未启用该组时，行为与"没有客户端分组"时完全一致（走全局默认）
- [ ] 组内 `SplitRefs` 命中 → 使用该分流列表的 DNS；全部未命中 → 使用 `FallbackDNS`；`FallbackDNS` 为空 → 全局 `upstream`
- [ ] "其他"组可被真实识别（`othernet` 段命中），而非只靠"未命中"兜底
- [ ] `scope` 为 ISP key；**重命名/编辑任何展示字段都不会改变 scope**
- [ ] 客户端分组**不再出现** `name / priority / match / invert / allow_domain_split`
- [ ] 悬空 `SplitRefs` 保存被拒并给出可读错误
- [ ] 分组级 ECS / 偏好 / 云检测**或生效、或字段已删除**（不允许"配了不生效"）
- [ ] 运营商识别可在管理端开关/更新；关闭时一切退化为"无分组"
- [ ] `go test ./...` 全绿；`scripts/test_web_config.sh` 全绿；`gofmt -l internal/` 与 `go vet ./...` 干净
- [ ] 现网配置可平滑迁移，**上游/域名分流语义零破坏**

---

## 8. 明确不做（Out of Scope）

- 不改「上游与域名分流」`split_lists` 的匹配语义、字段与顺序（只被引用）
- 不做 GeoIP 国家级定位（只在段库层面区分国内运营商 + 可选的港澳台/境外）
- 不做运营商级"自动选线"（如电信出口自动挑最优电信 DNS）——本轮仍是静态配置
- 不做 ACME / 证书 / 入站加密相关改动
- 不做多租户、审计系统

---

## 9. 待确认决策

| #  | 决策点                      | 选项                                       | 建议                         |
| -- | ------------------------ | ---------------------------------------- | -------------------------- |
| 1  | "其他"是否包含境外？境外是否单列        | (a) 其他=含境外，不单列 (b) 拆出"境外"组（需下载 hk/mo/tw） | **(a) 起步**，预留 (b)          |
| 2  | **铁通是否单列**（数据源无独立铁通文件）   | (a) 不单列，并入移动 (b) 自备铁通段表 (c) 换数据源         | **(a)**，除非确有必要             |
| 3  | 教育网/广电/长宽是否默认单列          | (a) 默认并入"其他"，可手动拆 (b) 默认单列               | **(a)**                    |
| 4  | 分组是否保留"展示名"              | (a) 完全内置（电信/联通/移动/其他） (b) 标识固定 + 展示名可改   | **(b)** 兼顾可读性              |
| 5  | 组级 ECS / A·AAAA 偏好 / 云检测 | (a) 删除，全部交给分流列表 (b) 保留为"组级默认"，未命中分流规则时生效 | **(a) 先删**，需要再加            |
| 6  | `split_refs` 为空时的语义      | (a) 只走 `FallbackDNS`（推荐） (b) 继承全局全部分流列表  | **(a)**，语义清晰               |
| 7  | `FallbackDNS` 为空时        | (a) 回退全局 `upstream` (b) 视为"不覆盖"，等价于 (a)  | **(a)**                    |
| 8  | 客户端 IP 判不出运营商时           | (a) 落"其他"组 (b) 视为未分组，走全局默认               | **取决于 1**；若"其他"组启用则 (a)    |
| 9  | `SplitRefs` 引用方式         | (a) 按 `name` (b) 给分流列表加稳定 `id`           | **(a) 起步**，改名场景多则转 (b)     |
| 10 | 旧配置里的纯 CIDR 分组（无法映射运营商）  | (a) 直接丢弃 (b) 保留为"自定义组"（保留 IP 匹配能力）       | 需拍板——关系到是否**完全**放弃 IP 维度匹配 |

> 决策 10 是最容易被忽略但影响最大的一条：如果现网确实有"某机房出口走指定上游"这类**非运营商**需求，纯 ISP 分组会覆盖不到，需要保留一条"自定义/IP 组"的后门。请确认是否还有此类用法。

---

## 10. 附：与现有文档的关系

- 本 PDR **修订**《INBOUND_TLS_AND_CLIENT_SPLIT_PDR.md》§4.3；该文档其余部分（入站加密服务、证书托管、客户端 IP 解析链）**继续有效**。
- §2.2 的 P1–P5 属**存量缺陷**（`isp:` 永不命中 / 组级三项配置不生效 / 强制跳过云检测），与本次重构同批修复即可，无需单独立项。
- UI 形态建议与《WEB_UI_REDESIGN_PDR.md》的"固定行 + 下拉引用"风格保持一致。
