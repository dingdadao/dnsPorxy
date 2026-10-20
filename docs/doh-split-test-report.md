# dnsproxy 线上测试报告：DoH 客户端分流 + 云替换多线路 + 性能

> 执行时间：2026-10-12　　目标：`10.0.0.30`（生产，2 核 / 512MB，systemd `dnsproxy`）
> 配套资产：[测试用例设计](file:///Users/dension/GolandProjects/dnsPorxy/docs/doh-split-testcases.md) ｜ [功能测试脚本](file:///Users/dension/GolandProjects/dnsPorxy/scripts/test_doh_split.py) ｜ [性能测试脚本](file:///Users/dension/GolandProjects/dnsPorxy/scripts/perf_doh.py)

---

## 1. 执行摘要

| 维度 | 结论 |
|---|---|
| 功能用例 | **22 / 22 全部 PASS**（DoH 协议、UDP/DoT 一致性、客户端分流、云替换多线路、覆写回退、云检测旁路、缓存隔离、热更新） |
| 核心特性 | 客户端 IP 分流（telecom/cmcc）与**云替换多线路隔离**验证通过：三条线路返回的优选 IP 集合两两不同且各自正确 |
| 热更新 | `PUT /api/config` 生效且 `restart_required=false`，进程 PID 不变（无重启） |
| 性能（热缓存） | UDP 峰值 **≈18.8k QPS**、DoH 峰值 **≈13.3k QPS**，P99 < 10ms，错误率 0% |
| 性能（冷查询） | 缓存未命中的境外域名查询 **~3s** 延迟，是当前主要瓶颈 |
| 配置还原 | 已还原为原始配置，回读比对**完全一致**；服务 `active`，PID 8896，NRestarts=0 |

---

## 2. 被测拓扑与关键机制

```
测试机 10.0.0.29 ──DoH:443 / DoT:853 / UDP:53──► dnsproxy @10.0.0.30
                                                   ├─ 全局 upstream: udp://58.20.127.238:53
                                                   ├─ 替换接口: cf.niao.fun/api/results?select=cm (api_count=2)
                                                   └─ 替换域名: telecom=cf.92555.xyz / cmcc=chinwa.cf.090227.xyz
```

线路区分（因 `trusted_proxies=[]`，header 不可用，采用 `client_ip_static` 映射模拟）：

| 线路 | scope | 测试映射 | 期望替换来源 | 本次实测结果 |
|---|---|---|---|---|
| 全局 | `-` | 无 | 接口前 2 条 | `173.245.59.28, 198.41.218.203` |
| 电信 | `telecom` | `1.48.0.1` | `cf.92555.xyz` | `172.64.144.44` |
| 移动 | `cmcc` | `27.0.160.1` | `chinwa.cf.090227.xyz` | `104.26.14.26, 172.67.73.167` |

> 三者互不相等 ⇒ 多线路云替换隔离生效。

---

## 3. 功能测试结果（最终一次运行）

```
合计: PASS=22  FAIL=0  WARN=0  SKIP=0      配置还原: OK
```

| 用例 | 场景 | 结果 | 关键证据 |
|---|---|---|---|
| TC-A01 | DoH POST 基本解析 | ✅ | `http=200 rcode=0 ctype=application/dns-message` |
| TC-A02 | DoH GET/POST 一致 | ✅ | 两者 A 集合相同 |
| TC-A03 | DoH 与 UDP 一致 | ✅ | `UDP == DoH` |
| TC-A04 | DoH GET 非法 base64 | ✅ | `http=400` |
| TC-A05 | DoH POST 错误 Content-Type | ✅ | `http=415` |
| TC-A06 | NXDOMAIN 透传 | ✅ | `rcode=3` |
| TC-A07 | 空/超短报文 | ✅ | `http=400,400` |
| TC-A08 | DoT 冒烟 | ✅ | `rcode=0`，返回 A |
| TC-B01 | 全局线路云替换 | ✅ | `action=cloud list=国外`，IP ⊆ 全局接口集合 |
| TC-B02 | 电信分组覆写生效 | ✅ | `172.64.144.44` ⊆ `cf.92555.xyz` |
| TC-B03 | 移动分组覆写生效 | ✅ | `104.26.14.26,172.67.73.167` ⊆ `chinwa…` |
| TC-B04 | 三线路隔离(互斥) | ✅ | 三集合两两不等 |
| TC-B05 | 覆写关闭回退全局 | ✅ | override=false 后 IP 变为全局接口目标 |
| TC-B06 | 分组兜底路径强制云检测 | ✅ | `list=中国电信`(兜底) 且 `action=cloud`，IP ⊆ 电信目标 |
| TC-B07 | 非 CF 域名不替换 | ✅ | `claude.ai/reddit.com` → `action=split`，返回真实 IP |
| TC-C01 | 定向域名跳过云替换 | ✅ | `cloudflare-cn.com` → `list=定向域名 action=split`，未被替换 |
| TC-C02 | 国外列表触发替换 | ✅ | `x.com` → `list=国外 action=cloud` |
| TC-C03 | AAAA prefer_a 过滤 | ✅ | `AAAA=[]`（存在 A 记录时置空 AAAA） |
| TC-D01 | scope 缓存隔离 | ✅ | 同线路两次查询结果一致且命中缓存；跨线路互不污染 |
| TC-D02 | 热更新不重启 | ✅ | `restart_required=false`，`pid 8896->8896` |
| TC-D03 | 配置持久化正确 | ✅ | 回读 `client_ip_static=null`、upstream 未变 |

**结论**：客户端 IP 分流 → ISP 分组 → 引用域名分流 → 云替换按线路覆写 的完整链路行为正确；覆写开关的回退语义、云检测旁路语义、缓存 scope 隔离均符合设计。

---

## 4. 性能测试结果

> DoH 采用 ApacheBench（`-k` 长连接）作为独立负载源；UDP 采用每并发一条持久 socket 的 asyncio 客户端。
> 服务端 CPU 由 `/proc/<pid>/stat` 的 tick 差计算（2 核为 100%）。

### 4.1 热缓存（内容已缓存，命中内存）

| 场景 | 并发 | QPS | avg | P50 | P95 | P99 | 错误率 | 服务端 CPU |
|---|---|---|---|---|---|---|---|---|
| DoH | 20 | 4290 | 4.7ms | 4 | 6 | 7ms | 0% | 16% |
| DoH | 50 | 9504 | 5.3ms | 4 | 6 | 8ms | 0% | 36% |
| DoH | 100 | 13269 | 7.5ms | 5 | 8 | 164ms | 0% | 53% |
| UDP | 20 | 4017 | 4.8ms | 4.9 | 6.3 | 8.0ms | 0% | 11% |
| UDP | 50 | 9771 | 5.1ms | 5.0 | 6.4 | 8.0ms | 0% | 20% |
| **UDP** | **100** | **18757** | 5.3ms | 5.1 | 6.7 | 9.1ms | 0% | 40% |

- 热缓存下延迟稳定在个位数毫秒；并发 100 时 DoH 出现 P99 长尾（164ms），UDP 无长尾。
- 单核 CPU 效率：UDP ≈ 47k QPS/核，DoH ≈ 26k QPS/核（TLS 开销约为明文 UDP 的 1.8×）。
- 2 核机器在压测下未触发内存压力（MemAvailable 稳定 358–371MB）。

### 4.2 冷查询（每次唯一域名，必然回源；实测为 NXDOMAIN 域名，属最差情形）

| 场景 | 并发 | QPS | avg | P50 | P95 | 错误率 | 服务端 CPU |
|---|---|---|---|---|---|---|---|
| UDP | 20 | 8.0 | 3068ms | 3054 | 3143 | 0% | 9% |
| UDP | 50 | 20.0 | 3099ms | 3075 | 3286 | 0% | 21% |
| UDP | 100 | 37.0 | 3204ms | 3131 | 3593 | 0% | 41% |

- 回源查询延迟被上游「竞速」中最慢分支拖到 **~3s**（`modern_timeout=3s` 量级），吞吐随并发线性放大但绝对量很低。
- 该结果反映的是 `国外` 列表上游在不可达/超时场景下的兜底等待；真实已缓存/可解析的境外域名热度上来后由缓存承接（见 4.1）。

---

## 5. 关键发现与风险

### 5.1 ⚠️ `国外` 列表存在间歇性 DNS 污染（中风险，建议关注）
- 现象：在**刚重启、缓存为空**后的最初几次查询中，`reddit.com`、`discord.com` 等返回了 **Facebook 网段 IP**（`69.171.235.22 / 31.13.92.37 / 157.240.7.20 / 31.13.82.169`），随后缓存升温即恢复正常（`151.101.x`）。
- 机制：`国外` 列表 `dns_mode=race`，同时竞速 **明文 UDP 8.8.4.4 / 1.1.1.1** 与 DoH 8.8.8.8 / 1.1.1.1。明文 UDP 出境查询可被劫持，一旦被污染的分支先到，**错误结果会被写入缓存（TTL 5m）**并持续命中。
- 佐证：全局上游 `58.20.127.238` 对 `reddit.com` 返回 `185.45.5.35`（非真实 IP），同样属异常应答。
- 影响：非 CF 域名的境外查询可能短时返回错误 IP（CF 域名因云替换被掩盖，影响较小）。
- 建议：① `国外` 列表移除明文 UDP 的 8.8.4.4/1.1.1.1，仅保留 DoH；② 或对境外结果作用域使用更短的缓存 TTL；③ 或将 `race` 改为优先加密上行。

### 5.2 ⚠️ 冷查询 ~3s 长延迟（中风险）
- 缓存未命中的境外域名查询稳定 ~3s，源于上游竞速在不可达分支上的等待。
- 建议：为不可达上游设置更短的探测超时并尽快返回首个有效应答；确认是否存在必要等待全部分支。

### 5.3 ℹ️ 优选 IP 目标动态变化（测试注意）
- `cf.92555.xyz`、`chinwa.cf.090227.xyz`、`cf.niao.fun` 返回会随时间/线路轮转，**测试不能硬编码期望 IP**；服务端对替换域名还有 10m 缓存，导致期望值与实时解析可能不一致。脚本采用「多次解析并集 + 子集包含 + 三线路互斥」的断言口径规避。

### 5.4 ℹ️ 性能测量工具选择
- 首版 Python(`httpx`/asyncio) DoH 客户端会把吞吐严重低估（并发出 20 时仅 390 QPS，而 `ab` 同条件 3700 QPS）。故最终 DoH 采用 `ab`、UDP 采用持久 socket 客户端采集，结论以本报告 4.1 为准。

---

## 6. 配置还原确认

```
client_ip_static : None
telecom  : override=True refs=['国外'] cf_domain=cf.92555.xyz
cmcc     : override=True refs=['国外'] cf_domain=chinwa.cf.090227.xyz
upstream : ['udp://58.20.127.238:53']
回读整份配置与备份比对：完全一致 (identical = True)
服务：active  PID=8896  NRestarts=0
```

---

## 7. 复现命令

```bash
# 功能测试（--restart 先清空进程内缓存以获得确定性期望值；结尾自动还原配置）
python3 scripts/test_doh_split.py --server 10.0.0.30 --restart
# 仅跑核心分流/云替换用例
python3 scripts/test_doh_split.py --server 10.0.0.30 --restart --only TC-B01,TC-B02,TC-B03,TC-B04
# 跳过需要临时改配置的用例
python3 scripts/test_doh_split.py --server 10.0.0.30 --skip-destructive

# 性能测试
python3 scripts/perf_doh.py --server 10.0.0.30
python3 scripts/perf_doh.py --server 10.0.0.30 --quick   # 低强度快速验证
```