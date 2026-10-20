# 🌐 dnsPorxy — 运营商感知的 DNS 代理与解析网关

自托管的递归 DNS 代理：全协议入站（UDP/TCP/DoT/DoH/DoH3）、运营商感知分流、云服务 IP 替换、本地域名篡改，并把每次查询的完整解析路径沉淀为可筛选、可统计的结构化日志。

配置全部存在本机 SQLite（`./data/config.db`），通过内置 Web 管理端可视化编辑，绝大多数改动**热更新、免重启**。

---

## 一、怎么部署

### 1.1 本地编译与运行

```bash
# 本地编译（输出 bin/dnsproxy）
go build -o bin/dnsproxy .

# 或使用 Makefile（输出 build/dnsproxy）
make build

# 交叉编译 Linux amd64（输出 build/dnsproxy-linux-amd64）
make build-linux

# 开发时直接跑
go run .
```

```bash
./bin/dnsproxy        # 或 go run .
```

程序**不接受命令行参数，也没有 YAML 配置文件**。两点必须注意：

- 配置的唯一来源是 `./data/config.db`（SQLite），程序**以当前工作目录为基准**读写 `./data/` 与 `./logs/`。因此要在固定目录下启动，否则会在不同目录各建一套库（systemd 单元里用 `WorkingDirectory` 固定了这一点）。
- 首次启动时 `./data/config.db` 不存在，程序用内置默认值建库：

| 项 | 默认值 |
|---|---|
| DNS 监听 | `:53`（同时开 UDP 与 TCP） |
| Web 管理端 | `:5380` |
| 上游 | 阿里 DoH、腾讯 DoH、腾讯 UDP |
| 分流列表 | 「定向域名」30 分钟刷新、「中国域名」24 小时刷新 |
| 缓存 | TTL 5 分钟 / 最多 5000 条 |

> 默认端口 53 是特权端口，非 root 运行会绑定失败。本地开发可先用 `sudo`，或先起在非特权端口、再进 Web 端改 `listen_port`。

启动后浏览器访问 `http://<主机>:5380` 进入管理端。

### 1.2 生产部署（systemd + 一键脚本）

生产环境用 systemd 守护，单元与安装脚本在 `scripts/service/`。

**首次部署（安装并启用 service 单元）：**

```bash
# 交叉编译
GOOS=linux GOARCH=amd64 go build -o build/dnsproxy-linux-amd64 .

# 上传二进制到目标机程序目录
scp build/dnsproxy-linux-amd64 root@<host>:/opt/dnsProxy/dnsproxy.new

# 安装 systemd 单元（会先备份已有的同名单元）
scp -r scripts/service root@<host>:/tmp/
ssh root@<host> 'bash /tmp/service/install_service.sh'
```

**后续升级（推荐：本地一键部署）：**

```bash
bash scripts/deploy.sh
```

`deploy.sh` 会依次：**交叉编译 linux/amd64 → 上传二进制与远端脚本 → 远端执行 `deploy_remote.sh`**。远端的 `deploy_remote.sh` 完成 **备份 → 覆盖 → 重启 → 自检**：

- 覆盖前打印待部署文件的 **sha256** 供手工核对；
- 先把现有二进制备份为同目录 `dnsproxy.bak.<时间戳>`，出错可据此回滚；
- `systemctl restart dnsproxy` 后等待端口就绪（启动要加载云 IP 段与分流列表，**约 5 秒**），再跑一轮自检（服务 is-active、UDP/TCP 53、Web 5380、`dig` 解析、管理端首页 200、`/api/logs` 200 等）。

`deploy.sh` 支持的环境变量（默认针对内置示例主机，换机器时改这些即可）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `DEPLOY_HOST` | `10.0.0.30` | 目标主机 |
| `DEPLOY_USER` / `DEPLOY_PORT` | `root` / `22` | 登录用户与 SSH 端口 |
| `DEPLOY_DIR` | `/opt/dnsProxy` | 远端部署目录 |
| `DEPLOY_KEY` | `~/.ssh/proxydns` | 私钥路径 |
| `DEPLOY_PASS` | 空 | 无密钥时回退密码认证（**只经环境变量传入，不入库**） |

**手动升级（不使用一键脚本时）：**

```bash
scp build/dnsproxy-linux-amd64 root@<host>:/opt/dnsProxy/dnsproxy.new
ssh root@<host> 'bash /opt/dnsProxy/deploy_remote.sh'
```

> `deploy_remote.sh` 里的程序目录（`/opt/dnsProxy`）与端口断言（`53` / `5380`）是主机相关的，换机器或改端口时需同步修改。
>
> **重启会有约 5 秒中断**（进程启动要先加载云 IP 段与分流列表，之后才绑定端口），请在低峰时段操作。

### 1.3 systemd 单元要点（`scripts/service/dnsproxy.service`）

- `WorkingDirectory=/opt/dnsProxy`，`ExecStart=/opt/dnsProxy/dnsproxy`（保证配置相对路径固定）；
- `Restart=always` / `RestartSec=3`，崩溃自动拉起；并有 `StartLimitBurst=5`（5 分钟内重启超 5 次进入 failed）防崩溃循环；
- `KillSignal=SIGTERM` + `TimeoutStopSec=30`（先优雅退出、冲刷解析日志，超时才强杀）；
- `LimitNOFILE=65535`（DNS 并发连接多）。

---

## 二、功能有哪些

### 2.1 入站协议（全协议，均可公网提供）

| 协议 | 说明 | 关键配置 |
|---|---|---|
| UDP / TCP | 经典 DNS，默认 `:53` | `listen_port` |
| DoT | DNS over TLS，默认 `:853` | `enable_dot` / `dot_addr` |
| DoH | DNS over HTTPS（HTTP/1.1 + HTTP/2），路径可配，支持经 CDN/WAF 接入 | `enable_doh` / `doh_addr` / `doh_path` |
| DoH3 | DNS over HTTP/3（QUIC），可配空闲超时/保活/0-RTT，并通过 Alt-Svc 引导客户端升级 | `enable_doh3` / `doh3_addr` / `doh3_quic_*` / `doh3_allow_0rtt` |

所有入站共用一套证书（`cert_store_dir`、`cert_default`），DoH/DoH3 与管理端 HTTPS 共用 `CertStore`。

### 2.2 上游与解析策略

- **多上游**：支持 UDP/TCP/DoT/DoH/DoH3 上游；`race`（并发竞速，取首个有效应答）或 `failover`（串行故障转移）两种模式；另有 `backup_dns` 兜底。
- **加密上游**：DoT 强制校验证书（`MinVersion=TLS1.2`、显式 SNI），DoH 同样校验证书，防链路旁路。
- **域名分流（split_lists）**：按列表顺序匹配域名，命中即使用该列表指定的上游、解析模式、ECS 策略与 IP 偏好；列表支持 URL 自动下载 + 定时刷新，可取反。
- **客户端分组**：按客户端真实 IP 归属**运营商分组（ISP）**或**自定义分组（IP/CIDR）**匹配；组内可引用某套分流策略组，并覆写上游与解析偏好（竞速/故障转移、清检测、EDNS）。
- **ECS（EDNS Client Subnet）**：命中分流时注入本地 ECS，并按需**剥离客户端自带 ECS**，避免共享缓存被不同客户端网段污染。
- **IP 偏好（ip_prefer）**：如 `only_a` 一律置空 AAAA、`prefer_a` 有 A 时置空 AAAA（本地回 NODATA）。
- **本地域名篡改（overrides）**：优先级最高，命中即返回，不走缓存与上游。
- **云服务 IP 替换**：自动检测 Cloudflare / AWS 网段并替换为可达 IP；支持**按运营商分组的多线路目标**（CF 域 / AWS 域 / CF API）并带覆写开关，配置改动热生效。

### 2.3 缓存

分片 LRU 缓存（16 shard，默认 TTL 5 分钟 / 最多 5000 条），TTL 按 RR 逐秒递减，回源用 `singleflight` 合并去重，并带异步刷新池。

### 2.4 解析日志与统计报表

每次查询记录：命中动作、分流列表名、实际应答上游、解析模式、ECS 处理、rcode、答案摘要、耗时，以及**来源维度**——

- 接入协议 `protocol`（UDP/TCP/DoT/DoH/DoH3）
- 来源类型 `source_kind`（外网 / 内网 / 未知，按客户端 IP 是否公网判定）
- 接入方式 `via`（直连 / 经代理）
- 归一化客户端 IP `client` 与运营商归属 `client_isp`

Web 端「解析日志」可按关键字、动作、类型、客户端、协议、来源类型、接入方式、**运营商**筛选；「统计报表」提供 Top 域名 / Top 客户端来源、按协议/来源类型分布、按天趋势与超时口径统计。日志存独立 SQLite（保留期与条数上限可配，自动清理，写入与解析主链路隔离）。

### 2.5 证书与管理端

- 证书：多证书、SNI 选择、热加载、上传、设置默认证书；Webhook 部署带 token 鉴权。
- 管理端：配置可视化编辑 + 热更新（区分“热字段/需重启字段”）、证书管理、解析日志与统计、手动更新单个分流列表、一键重启服务。
- 可观测：结构化日志（text/json）、panic 兜底 + 进程级恢复管理器、服务健康检查与统计。

### 2.6 运营

- **ISP 数据源**：可从 `source_base_url` 定时更新运营商网段库（`source_update_hours`）。
- **部署**：单二进制、零外部依赖（纯 Go SQLite），一键部署 + 自动备份回滚 + 部署后自检。

---

## 三、优缺点

### ✅ 优点

- **协议覆盖完整**：入站 UDP/TCP/DoT/DoH/**DoH3** 全支持，且加密上游出站，公网自建隐私解析门槛低。
- **运营商感知路由**：ISP 分组 + ECS 注入 + 分组级覆写，让不同运营商客户端都尽量拿到就近、准确的应答。
- **云替换与分流能力**：CF/AWS 网段替换（按运营商多线路）与域名分流的组合，实用性强、热生效。
- **可观测性强**：细粒度解析日志（含来源/协议/接入方式/运营商维度）+ 统计报表，能回答“这次查询到底走了哪条路”。
- **运维友好**：单二进制零外部依赖；配置集中在 SQLite 并可视化编辑；多数改动热更新免重启；证书热加载；`deploy.sh` 一键部署 + 自动备份回滚 + 自检。
- **自愈**：systemd `Restart=always` + 崩溃循环保护 + 进程内 panic 兜底。

### ⚠️ 缺点与短板

- **无 DNSSEC 校验**：当前仅把响应 AD 位清零，未做完整校验链，无法对“解析结果可信”做强承诺。
- **无速率限制 / 抗滥用弱**：入站无 QPS 与连接数上限，公网暴露时抗 DDoS 能力不足。
- **访问控制未落地**：`allow_acls` 配置项已定义但**尚未在解析路径生效**。
- **无鉴权与多租户**：DoH 端点无 token/API key，管理端无登录；无 profile 概念。
- **单点部署**：单机单实例，无多节点 / 主备 / Anycast；单机故障即服务中断。
- **性能缺少可证明性**：无压测基线，无 metrics / 健康探针；缓存容量固定 5000 条、无 packet cache。
- **存储定位**：解析日志用 SQLite 单写者，队列打满即丢弃（属“可丢弃”的可观测数据，不可当审计源）。
- **数据覆盖待补**：运营商库中联通分组与部分中国移动 IPv6 段覆盖不全。

---

## 四、解决哪些问题

- **运营商 DNS 劫持 / 明文污染**：加密上游（DoT/DoH/DoH3）+ 竞速 + 分流，绕开被劫持的本地解析；入站提供 DoH/DoH3，终端到网关这一段也不再明文裸露。
- **跨运营商解析不准确**：按客户端 IP 归属运营商分组，并结合 ECS 注入，让不同宽带用户都尽量得到就近应答。
- **云服务（Cloudflare / AWS）IP 不可达**：自动识别云网段并替换为可达 IP，解决“分到的 CF/AWS 地址连不上”的问题。
- **需要固定或覆写解析的域名**：本地域名篡改（override）最高优先级命中即回。
- **“查询到底走了哪条路”不可见**：结构化解析日志 + 统计报表，把动作、分流列表、上游、模式、ECS、耗时与来源维度全部落库并可按运营商等维度筛选。
- **多终端 / 多网络策略不统一**：一个网关集中配置，按运营商/自定义分组下发不同策略。
- **自建与隐私诉求**：单二进制自托管，配置与日志都在自己手里，可配保留期。

---

## 📁 数据文件（`./data/`）

| 文件 | 用途 |
|---|---|
| `config.db` | 配置库（唯一配置来源） |
| `query_log.db` | 解析日志库，独立存储；默认保留 3 天 / 最多 20 万条 |
| `designated.yaml`、`china_domains.yaml` | 各分流列表的域名清单；缺失时按列表里配置的 URL 自动下载 |
| `cf_mrs_file4.txt`、`cf_mrs_file6.txt`、`aws.txt` | 云服务 IP 段，用于云 IP 替换 |

配置的**唯一来源**是 `./data/config.db`：`settings` 表存整份配置 JSON，`overrides` 表存本地域名篡改。改配置只有一条路——Web 管理端 `PUT /api/config`，保存后分两类：

- **热字段**（上游、分流列表、ECS、A/AAAA 偏好档位、缓存时长、云替换目标等）：立即生效，`restart_required=false`；
- **重启字段**（`listen_port`、`web_addr`、`doh_path`、`log_format` 等）：已落库但需重启进程，`restart_required=true`（执行 `systemctl restart dnsproxy`）。

---

## 📊 项目结构

### `internal/` — 核心代码
- **config/**: 配置管理模块（`config.go` 内存模型、`json.go` JSON 双向映射、`store.go` SQLite 读写）
- **dns/**: DNS 处理核心逻辑（入站服务、上游连接池、缓存、分流、ECS、云替换、证书）
- **querylog/**: 解析日志库（SQLite + 异步批量写入 + 自动清理）
- **recovery/**: 启动编排与 panic 恢复
- **source/**: 运营商网段库更新
- **web/**: Web 管理端（`admin.html` 内嵌 + REST API）
- **utils/**: 通用工具函数

---

## 🤝 贡献

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request
