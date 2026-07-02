# AI-Burp 开发进度与交接文档

> **更新日期**: 2026-06-25
> **版本**: 4.0.0
> **用途**: 用于大模型上下文切换与开发交接

---

## 1. 项目概览

**AI-Burp** 是一个专为 AI 智能体设计的红队安全研究平台。

### 三种运行模式

| 模式 | 说明 | 入口 | 状态 |
|------|------|------|------|
| **CLI 模式** | 传统命令行，直接调用安全工具 | `aiburp <command>` | ✅ 可用 |
| **IDE 模式** | 被 Kiro/Cursor 等 IDE 调用，全部 JSON 输出 | `aiburp-ide <command>` | ✅ 可用 |
| **Agent 模式** | 内置 LLM 驱动的自主安全研究循环 | `aiburp-ide agent start <project>` | ✅ 可用 |

### 核心架构

```
┌────────────────────────────────────────────────────────────────────┐
│                        Agent 模式 (OODA 循环)                       │
│  LLMClient → ActionParser → SecurityAgent.run() → 行动 → 观察 → 更新  │
└────────────────────────────────────────────────────────────────────┘
                              │ 调用
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│  V4 Traffic Layer (统一协议模型)        V3 Core (HTTP 兼容)          │
│  ┌──────────────────────────┐    ┌──────────────────────────┐       │
│  │ TrafficEngine             │    │ AsyncBurp / SyncBurp     │       │
│  │  ├─ 16 ProtocolAdapters   │    │ VulnScanner              │       │
│  │  ├─ MultiChannelInjector  │    │ IntentAnalyzer           │       │
│  │  ├─ AttackChecklist (14D) │    │ KnowledgeBase            │       │
│  │  ├─ IntelAggregator       │    │ Payloads                 │       │
│  │  ├─ CDNBypass             │    └──────────────────────────┘       │
│  │  ├─ AssetExpander         │                                       │
│  │  ├─ JWTTool               │    Burp Suite Core                    │
│  │  ├─ ExploitManager        │    ┌──────────────────────────┐       │
│  │  └─ AttackChain           │    │ History / Repeater       │       │
│  └──────────────────────────┘    │ Intruder / Proxy / OOB   │       │
│                                   │ AuthManager / TrafficDiff│       │
│  Proxy System                    └──────────────────────────┘       │
│  ┌──────────────────────────┐                                       │
│  │ MiniClash / mihomo       │        PoC Framework                  │
│  │ Proxy Harvester          │        ┌──────────────────────────┐   │
│  │ Shodan Proxy Scanner     │        │ POCManager               │   │
│  │ Free Node Fetcher        │        │ nuclei2py Converter      │   │
│  │ OpSec ProxyGuard         │        │ GitHub PoC Fetcher       │   │
│  └──────────────────────────┘        └──────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. 已完成工作

### 2.1 V4 Unified Traffic Layer (`aiburp/traffic/`)

| 组件 | 文件 | 功能 |
|------|------|------|
| `TrafficEngine` | `engine.py` | 统一流量引擎入口，协议自动识别 + 路由 |
| `ProtocolAdapter` 基类 | `base.py` | 5 原语：Probe/Send/Reflect/OOB/State |
| 16 协议适配器 | `adapters/*.py` | HTTP/TCP/UDP/DNS/WebSocket/TLS/Redis/Docker/Kubelet/MySQL/SMB/SSH/FTP/SNMP/RMI |
| `MultiChannelInjector` | `injector.py` | 6 通道注入 (GET/POST/Cookie/Header/Host/Method) |
| `AttackChecklist` | `attack_checklist.py` | 14 维度系统攻击方法论 |
| `IntelAggregator` | `intel_aggregator.py` | 6 平台 OSINT 聚合 (Shodan/Censys/VT/OTX/SecurityTrails/MyIP.ms) |
| `CDNBypass` | `cdn_bypass.py` | 6 种 CDN 绕过方法找源 IP |
| `AssetExpander` | `asset_expander.py` | 子域名/旁站/C段/WHOIS 资产扩展 |
| `TrafficAnalyzer` | `traffic_analyzer.py` | 7 层 HTTP 被动流量分析 |
| `LogicVulnScanner` | `logic_vuln.py` | IDOR/越权/竞争条件扫描 |
| `JWTTool` | `jwt_tool.py` | JWT 解码/爆破/伪造 |
| `ExploitManager` | `exploits.py` | N-day 漏洞利用 (Log4j/Fastjson/Shiro/Spring) |
| `AttackChain` | `attack_chain.py` | 多步攻击链编排 |
| `WAFBypass` | `waf_bypass.py` | WAF 绕过引擎 |
| `ReverseShellGenerator` | `revshell.py` | 多语言反弹 Shell 生成 |
| `ReportGenerator` | `report_generator_v4.py` | V4 报告生成 |
| `GithubLeakScanner` | `github_leaks.py` | GitHub 泄露搜索 |
| `UploadScanner` | `upload_scan.py` | 文件上传漏洞扫描 |
| `SSRFExploit` | `ssrf_exploit.py` | SSRF 利用工具 |
| `DockerExploit` | `docker_exploit.py` | Docker/K8s RCE |
| `AntiTrace` | `anti_trace.py` | 反溯源分析 |

#### 注入器新增通道 (2026-06 实战驱动)

| 通道 | 说明 | 实战来源 |
|------|------|----------|
| CSRF Token 预抓取 | 自动提取表单 token，支持 phpMyAdmin 等认证绕过 | 12 个 phpMyAdmin 逼迫的 |
| Host 头注入检测 | `Host: evil.com` 注入 + 响应检测 | 上一轮建议的新攻击面 |
| HTTP 方法覆盖 | `X-HTTP-Method-Override` 等 header 测试 | 同上 |
| OpSec 安全闸门 | `verify_proxy()` 强制验证代理，拒绝裸奔 | 代理断了 5 次逼出来的 |

### 2.2 Agent 模式 (`agent.py`)

`SecurityAgent` — 自主 OODA 安全研究循环：

- **25+ 可用 action**：probe/scan/fuzz/finding/memory/think/complete + traffic_probe/traffic_scan/intel_lookup/asset_expand/cdn_bypass/github_leaks/check_unauth/jwt_analyze/logic_scan/exploit/revshell/traffic_analyze/attack_checklist/inject/full_audit
- LLM 支持：OpenAI (含自定义 base_url) + Anthropic Claude
- **精英猎人模式** — OODA 认知循环 + 14 维清单 + 假设驱动
- **OpSec 安全闸门** — Agent.run 启动前强制验证代理出口 IP
- **结构化认知输出** — mental_model/hypothesis/observation/update 作战日志格式

### 2.3 IDE 模式 CLI (`aiburp-ide`)

全部 JSON 输出，IDE 友好：

```bash
# 项目管理
aiburp-ide target <project_id> --type whitebox --name "CKFinder" --goal "RCE"
aiburp-ide status <project_id>
aiburp-ide prompt <project_id> --type [recovery|researcher|exhaustive|hacker|chaos|assumption]

# 发现管理
aiburp-ide finding add <project_id> --json '{"title":"...","severity":"high"}'
aiburp-ide finding list <project_id>

# 记忆管理
aiburp-ide memory add <project_id> code "内容" --file "file.php" --line 42
aiburp-ide memory search <project_id> "关键词"

# 探索追踪
aiburp-ide exploration add <project_id> "路径" blocked "原因"
aiburp-ide exploration pending <project_id> --add "待探索方向"

# 安全工具 (传统 HTTP)
aiburp-ide tool probe <url> <param> <value>
aiburp-ide tool scan <url> <param> <value> --types sqli,xss

# Agent 模式
aiburp-ide agent status
aiburp-ide agent start <project_id> --instruction "分析 RCE 可能性"

# V4 Traffic 层
aiburp-ide traffic probe <target> --protocol tcp
aiburp-ide traffic scan <target> --ports 22,80,443,3306,6379
aiburp-ide traffic check <target> --unauth
```

### 2.4 代理系统 (`proxy/` + `proxy_manager.py`)

| 组件 | 功能 |
|------|------|
| `ProxyManager` | 双模式 (MiniClash/mihomo + HTTP 池) |
| `ProxyHarvester` | 多源自动采集 (proxyscrape/免费列表) |
| `ShodanProxyScanner` | Shodan 扫描 SOCKS5 代理节点 |
| `FreeNodeFetcher` | 免费代理节点爬取 |
| `ProxyGuard` | OpSec 守卫 — 强制代理 + 出口 IP 验证 |
| 三层后备 | mihomo → harvester → 直连 (永不裸奔) |

### 2.5 Burp Suite 风格核心 (`core/`)

| 组件 | 功能 |
|------|------|
| `History` | SQLite 后端请求/响应存储，HAR/Burp XML 导入导出 |
| `Repeater` | 请求重放 + 参数修改 |
| `Intruder` | 批量 Fuzzing + 智能停止条件 |
| `Proxy` | MITM 代理 (mitmproxy 基) |
| `OOB` | Interactsh 外带检测 |
| `AuthManager` | 多账户管理 (IDOR 测试) |
| `TrafficDiff` | 跨请求流量对比 |
| `ParamAnalyzer` | 参数类型/风险评分 |

### 2.6 PoC 框架 (`pocs/`)

| 组件 | 功能 |
|------|------|
| `POCManager` | PoC 加载/执行管理器 |
| `nuclei2py` | Nuclei YAML → Python 模板转换器 (27KB) |
| `GitHubFetcher` | GitHub PoC 自动采集 |
| 内置 PoC | CMS 漏洞 / 错误配置 / 信息泄露 |

### 2.7 精英猎人实战脚本

| 脚本 | 功能 |
|------|------|
| `huntaid.py` | 单目标 OODA 深度测试脚本 + ProxyGuard |
| `huntaid_batch.py` | 25 域名批量探测（/ 存活 / 指纹 / 高危路径 / 端口）|

实战验证目标：blastzone 站群（25 域名，12 phpMyAdmin，4 WordPress，共享主机）

---

## 3. 项目结构

```
ai-burp/
├── aiburp/                        # 主源码包 (111 .py 文件)
│   ├── __init__.py                # 包导出 (V3 + V4 合并入口)
│   ├── __main__.py                # CLI 入口
│   ├── cli.py                     # 原始 CLI (111KB)
│   ├── ide_cli.py                 # IDE 模式 CLI (36KB)
│   ├── agent.py                   # Agent 模式 (76KB, 25+ actions)
│   ├── burp.py                    # V3 HTTP 引擎 (AsyncBurp/SmartBurp)
│   ├── sync_wrapper.py            # 同步包装器
│   ├── prompts.py                 # Prompt 模板库 (61KB)
│   ├── orchestrator.py            # 安全编排器
│   ├── memory.py                  # RAG 记忆管理
│   ├── payloads.py                # Payload 加载器
│   ├── detectors.py               # 漏洞检测器
│   ├── stealth.py                 # WAF 规避
│   ├── intel.py                   # 智能层 (KnowledgeBase)
│   ├── constants.py               # 常量/签名
│   ├── proxy_manager.py           # V4 代理管理器
│   ├── core/                      # Burp Suite 风格核心 (16 文件)
│   ├── traffic/                   # ⭐ V4 统一流量层 (44 文件)
│   │   ├── engine.py              # TrafficEngine 入口
│   │   ├── injector.py            # 多通道注入器 (40KB)
│   │   ├── attack_checklist.py    # 14 维攻击清单 (35KB)
│   │   ├── adapters/              # 16 协议适配器
│   │   ├── ... (20+ 子模块)       # 情报/CDN/资产/JWT/利用/报告
│   ├── proxy/                     # 代理基础设施 (14 文件)
│   ├── plugins/                   # 插件生态 (11 漏洞扫描器 + 侦察)
│   └── pocs/                      # PoC 框架 + nuclei 转换器
├── payloads/                      # 132 payload 文件
├── tests/                         # 20 测试文件 (393 用例)
├── reports/                       # 实战评估报告
├── docs/                          # 文档 + 归档
├── huntaid.py                     # 精英猎人脚本
├── huntaid_batch.py               # 批量域名扫描
├── setup.py                       # 包安装
├── requirements.txt               # 依赖
├── Dockerfile                     # Docker 构建
├── .env                           # API 密钥 (已配置)
└── README.md / ARCHITECTURE.md    # 文档
```

---

## 4. 测试状态

| 维度 | 状态 |
|------|------|
| 测试文件数 | 20 |
| 测试用例数 | 393 |
| 通过率 | ~97% (通过 ≈385/393) |
| 已知失败 | 7 个 hypothesis + SQLite deadline 超时 (非代码 bug) |
| 超时 | 1 个 (test_tcp_closed_port_degrade 需联网) |

### 已知测试问题

1. **hypothesis deadline 过紧** — 7 个 `test_traffic_manager_*` 测试使用 SQLite + hypothesis，200ms 默认 deadline 不够。**解法**：加 `@settings(deadline=None)` 或 `deadline=5000`。
2. **test_tcp_closed_port_degrade** — 尝试连接真实关闭端口，跑久了会超时。**解法**：用 `free_port` fixture 替代。

---

## 5. 已排除的攻击面 (实战验证)

来自 blastzone 站群 25 域名的系统性验证：

| 攻击面 | 目标 | 结论 |
|--------|------|------|
| SQLi (store.aspx) | blastzone.org | 数字验证白名单，关闭 |
| SQLi (MediaWiki) | nar.org api.php | 参数化查询，关闭 |
| IDOR | nar.org clubs/{id} | 路径级验证，关闭 |
| phpMyAdmin CVE | 12 站 | v5.2.3 无未修复 CVE |
| Host 头注入 | blastzone.org | Cloudflare 拦截 |
| 方法覆盖 | blastzone.org | 服务器忽略 override 头 |
| Blue Iris 路径穿越 | 173.209.174.233 | 重定向登录 |
| WordPress 插件 | ashleywestmark 等 | 版本已修复已知 CVE |

---

## 6. 待开发/优化方向

### P0: 稳定性
- [ ] 修复 flaky hypothesis 测试 deadline（加 `deadline=None`）
- [ ] 修复 test_tcp_closed_port_degrade 超时（使用 free_port fixture）

### P1: 凭据层面的突破
- [ ] 弱密码爆破引擎 (针对 phpMyAdmin 12 站同源场景)
- [ ] 针对性字典生成 (域名/公司名组合)
- [ ] 密码复用检测模块

### P2: 供应链攻击能力
- [ ] 共享主机面板漏洞利用
- [ ] 管理后台入口发现 + 弱密码
- [ ] WHM/cPanel 漏洞检测

### P3: 流量层面的非常规入口
- [ ] "所有流量走 Burp 采集让 LLM 决策"闭环
- [ ] 智能流量采集 → LLM 分析 → 自动注入攻击
- [ ] 业务逻辑漏洞自动化发现

### P4: 工程优化
- [ ] `cli.py` 拆分 (111KB 太长)
- [ ] API 参考文档
- [ ] mem0 向量搜索集成
- [ ] 代码摄取功能
- [ ] CI/CD 集成 (GitHub Actions)
- [ ] `huntaid.py` / `huntaid_batch.py` 模块化入库

---

## 7. 环境配置

### 安装

```bash
cd ai-burp
pip install -e .              # 核心
pip install -e .[full]        # 全部可选协议库
```

### LLM 配置 (.env)

```env
# OpenAI (含第三方兼容 API)
OPENAI_API_BASE=https://api.mortis.edu.kg
OPENAI_API_KEY=sk-xxx
AIBURP_LLM_MODEL=gpt-4

# 或 Anthropic
# ANTHROPIC_API_KEY=sk-ant-xxx

# 情报 API Keys (已配置)
SHODAN_API_KEY=xxx
CENSYS_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
OTX_API_KEY=xxx
```

---

## 8. 如何继续开发

1. **直接使用**: `aiburp-ide` / `aiburp` / `python huntaid.py`
2. **Agent 模式**: 需 `.env` 中有 LLM API Key（已配好 OpenAI）
3. **跑测试**: `pytest tests/ -v`（忽略已知 deadline 失败）
4. **优先修复**: 测试稳定性 → 凭据突破口 → 供应链方向
5. **实战记录**: 见 `reports/blastzone_FINAL_v2_report.md`

---

## 9. 开发时间线

| 时期 | 版本 | 主要工作 |
|------|------|----------|
| 2025-12 | v3.0 | V3 核心引擎 + CLI |
| 2026-01 | v3.3 | IDE 模式 + Agent 模式 + RAG 记忆 |
| 2026-04~05 | v4.0-alpha | V4 Traffic Layer + 16 协议适配器 |
| 2026-06-23~25 | v4.0.0 | 精英猎人实战 (blastzone) + 注入器增强 + 代理系统 + OpSec |

---

*文档最后更新: 2026-06-25 | 版本: 4.0.0*
