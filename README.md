# AI-Burp V4: ALL-IN-TRAFFIC 红队作战平台

> **"Tools for collection, AI for decision-making, Agents for evolution."**
>
> V4: 所有流量接口都能成为渗透起点 —— HTTP/HTTPS/TCP/DNS/Redis/Docker/K8s/WebSocket/UDP/TLS/SNMP/MySQL/RMI/SMB

AI-Burp 不仅仅是一个渗透测试工具包，它是一个专为 **AI 智能体 (AI Agents)** 设计的高性能、具有语义感知能力的红队作战系统。

## 🆕 V4 新特性：ALL-IN-TRAFFIC

V4 把攻击面从 Web 一层撑到了**全流量**：

| 能力 | 说明 |
|------|------|
| **13 个协议** | HTTP/TCP/DNS/Redis/Docker/Kubelet/WebSocket/UDP/TLS/SNMP/MySQL/RMI/SMB |
| **统一流量引擎** | `TrafficEngine` 一个入口，自动路由到对应协议 adapter |
| **一键未授权检测** | Redis/Docker/K8s/MySQL/SMB/SNMP 的 RCE 路径自动识别 |
| **批量资产扫描** | `scan_cidr("10.0.0.0/24")` 自动扫 26 个高危端口 |
| **AI 语义分析** | `IntentAnalyzer.analyze_response` 给任意协议响应打攻击意图标签 |
| **CLI + Agent** | 命令行直接用，Agent 可自主调用多协议探测 |

**快速试一下：**

```bash
# 多协议探活 (自动路由: 6379->redis, 443->http, 3306->mysql)
aiburp-ide traffic probe 10.0.0.1:6379

# 批量扫描一个网段
aiburp-ide traffic scan 10.0.0.0/24 --text --high-value-only

# 一键未授权检测
aiburp-ide traffic check 10.0.0.1:2375
```

📖 **[V4 迁移指南](V4_MIGRATION_GUIDE.md)** — V3 用户必读

---

## 🆕 IDE 模式 (Kiro/Cursor 集成)

AI-Burp 现在支持 **IDE 模式**，专为 Kiro、Cursor 等 AI IDE 设计。所有命令输出 JSON 格式，方便 IDE 解析。

### 安装

```bash
cd ai-burp
pip install -e .
```

### 快速开始

```bash
# 设置审计目标
aiburp-ide target ckfinder --type whitebox --name "CKFinder" --goal "RCE"

# 获取恢复 Prompt (用于 IDE 上下文)
aiburp-ide prompt ckfinder

# 查看项目状态
aiburp-ide -p status ckfinder

# 添加发现
aiburp-ide finding add ckfinder --json '{"title":"Path Traversal","severity":"high"}'

# 存储代码记忆
aiburp-ide memory add ckfinder code "function upload() {...}" --file "upload.php" --line 42

# 搜索记忆
aiburp-ide memory search ckfinder "upload"

# 探测参数
aiburp-ide tool probe "https://target.com/api" id 1

# 漏洞扫描
aiburp-ide tool scan "https://target.com/api" id 1 --types sqli,xss
```

### Agent 模式 (可选)

配置 LLM 后可启用自主审计：

```bash
# 检查 LLM 配置
aiburp-ide agent status

# 启动自主审计
aiburp-ide agent start ckfinder --instruction "分析文件上传功能的 RCE 可能性"
```

环境变量 (`.env`):
```env
OPENAI_API_BASE=https://api.openai.com/v1
OPENAI_API_KEY=sk-xxx
AIBURP_LLM_MODEL=gpt-4
```

---

## 🌟 V3 核心特性 (Agent-Native)

- **⚡ 全异步超高并发**: 基于 `AsyncBurp` 引擎，实现毫秒级的漏洞探测与批量 Fuzz。
- **🧠 语义预分析 (IntentAnalyzer)**: 自动理解接口业务意图（#AUTH, #DB, #UPLOAD），精准出牌。
- **👁️ 全局知识库 (Intelligence Layer)**: 跨请求、跨接口的资产记忆，支持自动化的**漏洞链串联 (Vulnerability Chaining)**。
- **⚖️ 智能决策闭环 (Decision System)**: 每一项高价值发现都会生成结构化的 `Decision` 报告，等待 AI 逻辑调度。

## 📚 深度文档 (V3 推荐)

- **[AI 驾驶员手册](./DOC_V3_AI_OPERATOR.md)**: **必读！** 教 AI 如何控制本系统进行自主渗透。
- **[架构规格书](./DOC_V3_ARCH_SPEC.md)**: v3 异步引擎与智力层的深度技术实现。
- **[重构计划](./REFACTOR_V3_AUTONOMOUS.md)**: V3 的演进线路图与核心设计理念。

---

## 🚀 快速启动

### 异步模式 (推荐)

```python
import asyncio
from aiburp import AsyncSmartBurp

async def autonomous_mission():
    async with AsyncSmartBurp(project="op_phoenix") as burp:
        # AI 只需下达一个指令，系统自动完成意图分析与全漏洞扫描
        decision = await burp.smart_scan("https://target.com/api/user", "id", "1")
        
        # 结果是结构化的 JSON，专为 LLM 解析设计
        print(decision.suggestion)

asyncio.run(autonomous_mission())
```

### 同步模式 (兼容旧代码)

```python
from aiburp import SyncBurp, Burp  # Burp 是 SyncBurp 的别名

with SyncBurp(project="test", delay=1.0) as burp:
    # GET 请求
    r = burp.get("https://target.com/api?id=1")
    print(f"{r.status}/{r.length}b {r.time_ms}ms")
    
    # POST JSON
    r = burp.post("https://target.com/api", json={"key": "value"})
    
    # 批量 Fuzz
    results = burp.fuzz("https://target.com/api?id=§", ["'", '"', "1 OR 1=1"])
    for r in results:
        if r.is_interesting:
            print(f"⚠️ {r.payload}: {r.error}")
```

### V4 TrafficEngine (多协议统一入口)

```python
from aiburp.traffic import TrafficEngine, TrafficRequest

async with TrafficEngine() as engine:
    # 自动协议识别: 6379 -> redis
    r = await engine.probe("10.0.0.1:6379")
    print(r.banner, r.tags)

    # 批量端口扫描
    results = await engine.scan("10.0.0.1", ports=[22,80,443,3306,6379])

    # 一键未授权检测
    r = await engine.check_unauth("10.0.0.1:2375")  # Docker
    if r.ok: print(f"未授权: {r.anomalies}")

    # 全维度攻击清单 (14维方法论)
    from aiburp.traffic import AttackChecklist
    checklist = AttackChecklist(requests.Session())
    report = checklist.run("https://target.com/page?id=1")

    # 多通道参数注入 (六通道: GET/POST/Cookie/Header/Host/Method)
    from aiburp.traffic import MultiChannelInjector
    inj = MultiChannelInjector(requests.Session())
    findings = inj.scan_all("https://target.com/page?id=1")
```

### 内置 Payload

```python
from aiburp import SQLI, XSS, SSTI, LFI, SSRF, CMDi

SQLI.quick          # SQL注入快速检测 (7个)
SQLI.auth_bypass    # 认证绕过 (167个)
SQLI.time_based     # 时间盲注
XSS.quick           # XSS快速检测
SSTI.quick          # 模板注入
LFI.quick           # 文件包含
```

### Response 关键属性

| 属性 | 说明 | 示例 |
|------|------|------|
| `r.status` | 状态码 | 200, 403, 500 |
| `r.length` | 响应长度 | 1234 |
| `r.time_ms` | 响应时间(ms) | 150.5 |
| `r.body` | 响应内容 | `"<html>..."` |
| `r.error` | 检测到的错误类型 | `"mysql"`, `"mssql"`, `""` |
| `r.blocked` | 是否被WAF拦截 | True/False |
| `r.is_interesting` | 是否值得关注 | True/False |
| `r.tags` | 语义标签 (V3) | `["DB", "AUTH"]` |

---

## CLI 使用

```bash
# 探测参数
aiburp probe "https://target.com/api" --param id --value 1

# 漏洞扫描
aiburp scan "https://target.com/api?id=1" --type sqli

# 批量 Fuzz
aiburp fuzz "https://target.com/api?id=§" --payloads "' OR 1=1" "1 AND 1=2"

# 查看所有命令
aiburp --help
```

---

## 🔒 代理系统 (OpSec 强制)

所有对外流量**强制走代理**，绝不直连目标 — 这是红队第一原则。

| 组件 | 说明 |
|------|------|
| **MiniClash/mihomo 集成** | `ProxyGuard` 自动启动 mihomo，配好 SOCKS5 代理 |
| **自动代理采集** | proxyscrape + Shodan 扫描 SOCKS5 节点，自动验证存活 |
| **三层后备** | mihomo → harvester 节点池 → 直连 (代码层验证出口 IP) |
| **OpSec 闸门** | `verify_proxy()` 在 Agent.run 前强制验证，出口 IP 不一致则拒绝 |

```python
from huntaid import ProxyGuard
guard = ProxyGuard()
S = guard.session  # 拿到已配代理的 Session
# 所有请求走代理
r = S.get("https://target.com/admin")
guard.rotate()     # 手动轮换节点
guard.close()
```

## 🎯 精英猎人模式

用于对真实资产做深度 Red Team 评估，基于 OODA 认知循环 (Observe-Orient-Decide-Act)：

```bash
python huntaid.py                          # 单目标深度测试
python huntaid_batch.py                     # 25 域名批量探测
```

输出：结构化作战日志 (mental_model/hypothesis/observation/update) + JSON+Markdown 报告。

## V4 高级组件

| 组件 | 说明 |
|------|------|
| **AttackChecklist** | 14 维度系统攻击方法论 |
| **MultiChannelInjector** | 6 通道注入 (GET/POST/Cookie/Header/Host 注入/方法覆盖) |
| **CSRF Token 预抓取** | 自动提取表单 token，支持 phpMyAdmin 认证绕过 |
| **IntelAggregator** | 6 平台情报聚合 (Shodan/Censys/VT/OTX/SecurityTrails) |
| **AssetExpander** | 子域名/旁站/C段/WHOIS 资产扩展 |
| **CDNBypass** | 6 种方法找源 IP |
| **JWTTool** | JWT 解码/爆破/伪造 |
| **ExploitManager** | N-day 漏洞利用 (Log4j/Fastjson/Shiro/Spring) |
| **GithubLeakScanner** | GitHub 泄露搜索 |
| **LogicVulnScanner** | IDOR/越权/竞争条件 |
| **AttackChain** | 多步攻击链编排 |
| **OOBChannel** | Interactsh 外带检测 |

---

## V2 迁移指南

V3 统一了 API，旧代码只需少量修改：

```python
# V2 (仍然可用，但建议迁移)
from aiburp import Burp  # 现在是 SyncBurp 的别名

# V3 推荐
from aiburp import AsyncBurp, SyncBurp
```

旧的 `Burp` 类已移至 `aiburp._legacy.burp_v2`，通过别名保持兼容。

### 6. 常见错误避免

```python
# ❌ 错误: history 是属性不是方法
burp.history(10)

# ✅ 正确
burp.history.recent(10)

# ❌ 错误: post 不支持直接传 dict
burp.post(url, {"key": "val"})

# ✅ 正确: 用 json= 参数
burp.post(url, json={"key": "val"})
burp.send("POST", url, json={"key": "val"})
```

### 7. 其他常用技巧

```python
# with 语句自动关闭
with Burp(project="test", delay=1.5) as burp:
    r = burp.send("GET", url)
# 自动调用 burp.close()

# probe 支持 POST
report = burp.probe(url, "username", "test", method="POST")

# 自定义 Cookie
burp.send("GET", url, headers={"Cookie": "session=xxx"})

# 检查 payload 是否反射
r = burp.send("GET", url + "?q=<test>", check="<test>")
if r.reflects:
    print("XSS 可能!")
```

---

## 目录

1. [安装](#安装)
2. [快速开始](#快速开始)
3. [发送请求](#发送请求)
4. [历史管理](#历史管理)
5. [批量 Fuzz](#批量-fuzz)
6. [智能探测](#智能探测)
7. [内置 Payload](#内置-payload)
8. [漏洞扫描器](#漏洞扫描器)
9. [完整示例](#完整示例)
10. [API 参考](#api-参考)
11. [核心模块 (Burp Suite 风格)](#核心模块-burp-suite-风格)
    - [Repeater - 请求重放](#repeater---请求重放)
    - [Intruder - 批量攻击](#intruder---批量攻击)
    - [History - 流量历史](#history---流量历史)
12. [高级功能模块](#高级功能模块)
    - [MITM 代理 - 流量拦截](#mitm-代理---流量拦截)
    - [认证会话管理](#认证会话管理)
    - [子域名枚举](#子域名枚举)
    - [DNS 验证](#dns-验证)
    - [资产侦察](#资产侦察)
    - [OOB 外带检测](#oob-外带检测)
    - [自动发现](#自动发现)
    - [智能自动扫描](#智能自动扫描)
13. [CLI 命令参考](#cli-命令参考)

---

## 安装

```bash
# 在 Docker 容器中已预装
# 本地安装:
pip install httpx
```

---

## 快速开始

```python
from aiburp import Burp

# 创建实例
burp = Burp(project="my_test", delay=1.5)

# 发送请求
r = burp.send("GET", "https://example.com/api?id=1")
print(r)  # [200] 1234b 150ms

# 查看历史
print(f"已发送 {burp.history.count()} 个请求")

# 关闭
burp.close()
```

---

## 发送请求

### 方法一: send() - 推荐

```python
from aiburp import Burp

burp = Burp(project="test", delay=1.5)

# GET 请求
r = burp.send("GET", "https://target.com/api?id=1")

# POST JSON 数据
r = burp.send("POST", "https://target.com/api/login", 
              json={"username": "admin", "password": "test"})

# POST Form 数据
r = burp.send("POST", "https://target.com/api/login",
              data="username=admin&password=test")

# 自定义 Headers
r = burp.send("GET", "https://target.com/api",
              headers={"Authorization": "Bearer token123"})

# 检查响应
print(r.status)    # 200
print(r.length)    # 1234
print(r.time_ms)   # 150.5
print(r.body)      # 响应内容
print(r.error)     # 检测到的错误类型 (mysql, oracle, etc.)
print(r.blocked)   # 是否被 WAF 拦截

burp.close()
```

### 方法二: get() / post()

```python
# GET
r = burp.get("https://target.com/api?id=1")

# POST JSON
r = burp.post("https://target.com/api", json={"key": "value"})

# POST Form
r = burp.post("https://target.com/api", data="key=value")
```

### Response 对象属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `status` | int | HTTP 状态码 |
| `length` | int | 响应长度 (bytes) |
| `time_ms` | float | 响应时间 (毫秒) |
| `body` | str | 响应内容 |
| `headers` | dict | 响应头 |
| `error` | str | 检测到的错误类型 |
| `blocked` | bool | 是否被 WAF 拦截 |
| `reflects` | bool | payload 是否反射 |
| `is_interesting` | bool | 是否值得关注 |

---

## 历史管理

所有请求自动记录到 `burp.history`：

```python
from aiburp import Burp

burp = Burp(project="test")

# 发送一些请求
burp.send("GET", "https://target.com/api?id=1")
burp.send("POST", "https://target.com/api", json={"test": "data"})

# ========== 查询历史 ==========

# 请求总数
count = burp.history.count()
print(f"总共 {count} 个请求")

# 最近 N 条
recent = burp.history.recent(10)
for r in recent:
    print(f"{r.method} {r.url} -> {r.status}")

# 所有请求
all_requests = burp.history.all()

# 触发错误的请求
errors = burp.history.errors()
for r in errors:
    print(f"错误: {r.url} -> {r.error}")

# 有趣的请求 (错误或反射)
interesting = burp.history.interesting()

# 被拦截的请求
blocked = burp.history.blocked()

# ========== 保存和清空 ==========

# 保存到文件
burp.history.save("my_history.json")

# 清空历史
burp.history.clear()

# 统计摘要
summary = burp.history.summary()
print(summary)
# {'total': 10, 'errors': 2, 'blocked': 1, 'interesting': 3}

burp.close()
```

---

## 批量 Fuzz

使用 `fuzz()` 方法批量测试 payload：

```python
from aiburp import Burp, SQLI

burp = Burp(project="fuzz_test", delay=1.5)

# URL 中用 § 标记注入点
url = "https://target.com/api?id=§"

# 使用内置 payload
results = burp.fuzz(url, SQLI.quick)

# 查看结果
for r in results:
    print(f"{r.payload:30s} -> {r.status}/{r.length}b")
    
    # 检查是否有趣
    if r.is_interesting:
        print(f"  ⚠️ 发现异常: error={r.error}, blocked={r.blocked}")

# 自定义 payload
my_payloads = ["'", "\"", "1 OR 1=1", "1' OR '1'='1"]
results = burp.fuzz(url, my_payloads)

burp.close()
```

### fuzz() 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | str | 必填 | 包含 § 标记的 URL |
| `payloads` | list | 必填 | payload 列表 |
| `marker` | str | "§" | 替换标记 |
| `stop_on_block` | bool | True | 被拦截 3 次后停止 |

---

## 智能探测

使用 `probe()` 自动分析参数特征：

```python
from aiburp import Burp

burp = Burp(project="probe_test", delay=1.5)

# 探测参数
report = burp.probe(
    url="https://target.com/api",
    param="id",
    value="1"
)

# 查看报告
print(report)
# 基线: 200/1234b
# WAF: 无
# 类型: 数字, 引号: none
# ⚠️ 触发错误: ['单引号']
# 🔍 响应变化: ['双引号', 'AND关键字']
# 建议: 5 个 payload

# 访问报告属性
print(report.baseline)    # (200, 1234)
print(report.waf)         # "" 或 "cloudflare"
print(report.is_numeric)  # True/False
print(report.quote)       # "single", "double", "none"
print(report.errors)      # {"单引号": "mysql"}
print(report.blocked)     # ["模板"]
print(report.changed)     # ["双引号"]
print(report.payloads)    # 建议的 payload 列表

burp.close()
```

---

## 内置 Payload

```python
from aiburp import SQLI, XSS, SSTI, LFI, SSRF, CMDi, Bypass

# ========== SQL 注入 ==========
SQLI.quick           # 快速检测 (7个)
SQLI.time_based      # 时间盲注
SQLI.error_based     # 报错注入
SQLI.auth_bypass     # 认证绕过 (167个)
SQLI.union           # UNION 注入

# ========== XSS ==========
XSS.quick            # 快速检测
XSS.polyglot         # 多态 payload
XSS.bypass           # 绕过 payload

# ========== SSTI ==========
SSTI.quick           # 快速检测
SSTI.jinja2          # Jinja2 模板
SSTI.freemarker      # Freemarker 模板

# ========== LFI ==========
LFI.quick            # 快速检测
LFI.linux            # Linux 路径
LFI.windows          # Windows 路径

# ========== SSRF ==========
SSRF.quick           # 快速检测
SSRF.cloud           # 云元数据

# ========== 命令注入 ==========
CMDi.quick           # 快速检测
CMDi.linux           # Linux 命令
CMDi.windows         # Windows 命令

# ========== WAF 绕过 ==========
# 生成绕过变体
variants = Bypass.apply("' OR 1=1--", "cloudflare")
for v in variants:
    print(v)
```

---

## 漏洞扫描器

使用 `VulnScanner` 进行全面扫描：

```python
from aiburp import Burp, VulnScanner

burp = Burp(project="scan_test", delay=1.5)
scanner = VulnScanner(burp)

# 扫描单个参数
findings = scanner.scan(
    url="https://target.com/api",
    param="id",
    value="1",
    types=["sqli", "xss"]  # 指定扫描类型
)

# 扫描所有类型
findings = scanner.scan_all(
    url="https://target.com/api",
    param="id", 
    value="1"
)

# 查看结果
for f in findings:
    print(f"[{f.severity}] {f.vuln_type}: {f.title}")
    print(f"  Payload: {f.payload}")
    print(f"  Evidence: {f.evidence}")

# 生成报告
report = scanner.report(findings)
print(report)

burp.close()
```

---

## 完整示例

### 示例 1: 测试登录 API

```python
from aiburp import Burp, SQLI

burp = Burp(project="login_test", delay=1.5)

url = "https://target.com/api/login"

# 1. 先发正常请求获取基线
baseline = burp.send("POST", url, json={
    "username": "test",
    "password": "test123"
})
print(f"基线: {baseline.status}/{baseline.length}b")

# 2. 测试 SQL 注入
for payload in SQLI.auth_bypass[:20]:  # 测试前 20 个
    r = burp.send("POST", url, json={
        "username": payload,
        "password": "test"
    })
    
    # 检查响应差异
    if r.status != baseline.status or abs(r.length - baseline.length) > 50:
        print(f"⚠️ 异常: {payload}")
        print(f"   响应: {r.status}/{r.length}b (基线: {baseline.status}/{baseline.length}b)")
    
    if r.error:
        print(f"🔥 错误: {payload} -> {r.error}")

# 3. 保存历史
burp.history.save("login_test.json")
print(f"测试完成，共 {burp.history.count()} 个请求")

burp.close()
```

### 示例 2: SSTI 测试

```python
from aiburp import Burp, SSTI

burp = Burp(project="ssti_test", delay=1.5)

url = "https://target.com/api/template"

# 测试 SSTI
for payload in SSTI.quick:
    r = burp.send("POST", url, json={"template": payload})
    
    # 检查是否执行了模板
    if "49" in r.body:  # {{7*7}} = 49
        print(f"🔥 SSTI 确认: {payload}")
        print(f"   响应包含计算结果!")
    
    if r.status == 400 or r.status == 500:
        print(f"⚠️ 异常响应: {payload} -> {r.status}")

burp.close()
```

### 示例 3: 参数探测 + Fuzz

```python
from aiburp import Burp, SQLI

burp = Burp(project="full_test", delay=1.5)

# 1. 探测参数
report = burp.probe("https://target.com/search", "q", "test")
print(report)

# 2. 根据探测结果选择 payload
if report.errors:
    print("发现错误，使用报错注入 payload")
    payloads = SQLI.error_based
elif report.is_numeric:
    print("数字参数，使用数字注入 payload")
    payloads = ["1 AND 1=1", "1 AND 1=2", "1 OR 1=1"]
else:
    print("字符串参数，使用字符串注入 payload")
    payloads = SQLI.quick

# 3. Fuzz
results = burp.fuzz("https://target.com/search?q=§", payloads)

# 4. 分析结果
interesting = [r for r in results if r.is_interesting]
print(f"发现 {len(interesting)} 个有趣的响应")

for r in interesting:
    print(f"  {r.payload}: {r.error or r.status}")

burp.close()
```

---

## API 参考

### Burp 类

```python
Burp(
    project: str = "default",   # 项目名 (用于保存历史)
    delay: float = 1.0,         # 请求间隔 (秒)
    timeout: float = 30.0,      # 超时时间 (秒)
    cookies: dict = None,       # 默认 Cookie
    headers: dict = None        # 默认 Headers
)
```

### 方法列表

| 方法 | 说明 |
|------|------|
| `send(method, url, json=, data=, headers=)` | 发送请求 (推荐) |
| `get(url, headers=)` | GET 请求 |
| `post(url, json=, data=, headers=)` | POST 请求 |
| `probe(url, param, value)` | 智能探测参数 |
| `fuzz(url, payloads, marker="§")` | 批量 Fuzz |
| `close()` | 关闭连接 |

### history 属性

| 方法 | 说明 |
|------|------|
| `history.count()` | 请求数量 |
| `history.recent(n)` | 最近 n 条 |
| `history.all()` | 所有请求 |
| `history.errors()` | 触发错误的请求 |
| `history.interesting()` | 有趣的请求 |
| `history.blocked()` | 被拦截的请求 |
| `history.save(filename)` | 保存到文件 |
| `history.clear()` | 清空历史 |
| `history.summary()` | 统计摘要 |

---

---

## 核心模块 (Burp Suite 风格)

AI-Burp 的 `core` 模块提供了类似 Burp Suite 的核心功能：

- **History** - 流量历史管理
- **Repeater** - 请求重放和修改
- **Intruder** - 批量攻击测试

### 导入方式

```python
from aiburp.core import History, Repeater, Intruder, Request, Response
```

---

## Repeater - 请求重放

类似 Burp Suite 的 Repeater，可以修改请求参数后重放：

```python
from aiburp.core import History, Repeater

# 创建 History 和 Repeater
history = History(project="my_test")
repeater = Repeater(history=history, delay=1.5)

# ========== 方式1: 从 History 获取请求重放 ==========

# 假设 History 中有 ID=123 的请求
resp = repeater.send(request_id=123)
print(f"原始响应: {resp.status}/{resp.length}b")

# 修改参数后重放
resp = repeater.send(
    request_id=123,
    modify={
        "params": {"id": "1'"},  # 修改参数
    }
)
print(f"修改后响应: {resp.status}/{resp.length}b")

# ========== 方式2: 直接发送 Request 对象 ==========

from aiburp.core import Request

# 创建请求
req = Request(
    method="POST",
    url="https://target.com/api/login",
    headers={"Content-Type": "application/json"},
    body='{"username": "admin", "password": "test"}'
)

# 发送
resp = repeater.send(request=req)

# 修改后重放
resp = repeater.send(
    request=req,
    modify={
        "params": {"username": "admin'--"},
        "headers": {"X-Custom": "test"},
    }
)

# ========== 方式3: 发送原始 HTTP 请求 ==========

raw_request = """POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin", "password": "test"}"""

resp = repeater.send_raw(raw_request, base_url="https://target.com")

# ========== 响应对比 ==========

# 发送两个请求
resp1 = repeater.send(request_id=123)
resp2 = repeater.send(request_id=123, modify={"params": {"id": "1'"}})

# 对比差异
diff = repeater.diff(resp1, resp2)
print(f"状态码变化: {diff['status_changed']}")
print(f"长度差异: {diff['length_diff']}b")
print(f"时间差异: {diff['time_diff']}ms")
print(f"新异常: {diff['new_anomalies']}")

# ========== 基线对比测试 ==========

# 批量测试 payload，与基线对比
results = repeater.compare_baseline(
    request=req,
    param="username",
    payloads=["'", "\"", "admin'--", "1 OR 1=1"]
)

for r in results:
    print(f"{r['payload']:20s} -> 状态变化:{r['status_changed']}, 长度差:{r['length_diff']}")

repeater.close()
```

### Repeater 方法

| 方法 | 说明 |
|------|------|
| `send(request=, request_id=, modify=)` | 发送/重放请求 |
| `send_raw(raw, base_url)` | 发送原始 HTTP 请求 |
| `diff(resp1, resp2)` | 对比两个响应 |
| `compare_baseline(request, payloads, param)` | 基线对比测试 |
| `test_param(request_id, param, payload)` | 测试单个参数 |

### modify 参数

```python
modify = {
    "params": {"id": "1'"},           # 修改 URL/Body 参数
    "headers": {"Cookie": "xxx"},     # 修改请求头
    "body": '{"new": "body"}',        # 替换整个 body
    "method": "POST",                 # 修改请求方法
}
```

---

## Intruder - 批量攻击

类似 Burp Suite 的 Intruder，批量发送 payload 并分析结果：

```python
from aiburp.core import History, Intruder

history = History(project="my_test")
intruder = Intruder(history=history, delay=1.5)

# ========== 基本攻击 ==========

report = intruder.attack(
    request_id=123,           # 从 History 获取请求
    param="id",               # 要测试的参数
    payloads=["'", "\"", "1 OR 1=1", "1' OR '1'='1"],
    stop_on="anomaly",        # 发现异常就停止
)

# 查看报告
print(f"测试: {report.tested}/{report.total}")
print(f"基线: {report.baseline_status}/{report.baseline_length}b")
print(f"发现: {report.interesting_count} 个有趣的响应")

# 遍历结果
for r in report.results:
    if r.is_interesting:
        print(f"⚠️ {r.payload}")
        print(f"   状态: {r.status}, 长度: {r.length}b")
        print(f"   异常: {r.anomalies}")
        print(f"   反射: {r.reflects}")

# ========== 停止条件 ==========

# 发现任何异常就停
report = intruder.attack(request_id=123, param="id", payloads=payloads, stop_on="anomaly")

# 发现数据库错误就停
report = intruder.attack(request_id=123, param="id", payloads=payloads, stop_on="error")

# 发现反射就停
report = intruder.attack(request_id=123, param="id", payloads=payloads, stop_on="reflect")

# 被 WAF 拦截就停
report = intruder.attack(request_id=123, param="id", payloads=payloads, stop_on="block")

# 不停，测完所有
report = intruder.attack(request_id=123, param="id", payloads=payloads, stop_on=None)

# ========== 测试多个参数 ==========

results = intruder.attack_multiple_params(
    request_id=123,
    params=["id", "name", "page"],  # 要测试的参数列表
    payloads=["'", "\"", "1 OR 1=1"],
    stop_on="anomaly",
)

for param, report in results.items():
    print(f"参数 {param}: {report.interesting_count} 个发现")

# ========== 快速测试 (内置 payload) ==========

# SQL 注入快速测试
result = intruder.quick_test(request_id=123, param="id", test_type="sqli")

# XSS 快速测试
result = intruder.quick_test(request_id=123, param="name", test_type="xss")

# SSTI 快速测试
result = intruder.quick_test(request_id=123, param="template", test_type="ssti")

# LFI 快速测试
result = intruder.quick_test(request_id=123, param="file", test_type="lfi")

intruder.close()
```

### Intruder 方法

| 方法 | 说明 |
|------|------|
| `attack(request_id, param, payloads, stop_on)` | 批量攻击 |
| `attack_multiple_params(request_id, params, payloads)` | 测试多个参数 |
| `quick_test(request_id, param, test_type)` | 快速测试 (内置 payload) |

### AttackResult 属性

| 属性 | 说明 |
|------|------|
| `payload` | 测试的 payload |
| `status` | 响应状态码 |
| `length` | 响应长度 |
| `time_ms` | 响应时间 |
| `anomalies` | 检测到的异常列表 |
| `reflects` | payload 是否反射 |
| `status_changed` | 状态码是否变化 |
| `length_diff` | 与基线的长度差异 |
| `time_diff` | 与基线的时间差异 |
| `is_interesting` | 是否值得关注 |

---

## History - 流量历史

持久化存储所有请求，支持查询和分析：

```python
from aiburp.core import History, Request

history = History(project="my_test")

# ========== 添加请求 ==========

req = Request(
    method="GET",
    url="https://target.com/api?id=1",
    headers={"User-Agent": "Mozilla/5.0"}
)
req_id = history.add(req)
print(f"添加请求 ID: {req_id}")

# ========== 查询请求 ==========

# 获取单个请求
req = history.get(id=123)

# 列出请求
requests = history.list(
    host="target.com",      # 按 host 筛选
    method="POST",          # 按方法筛选
    has_params=True,        # 只要有参数的
    limit=100,              # 返回数量
)

# 搜索
requests = history.search("password")  # 搜索 URL/body/响应

# 统计
count = history.count()
hosts = history.hosts()

# ========== 标签管理 ==========

history.tag(id=123, tags=["sqli", "interesting"], note="发现 SQL 注入")

# ========== 导入导出 ==========

# 导入 HAR 文件
history.import_har("burp_export.har")

# 导入 Burp XML
history.import_burp_xml("burp_export.xml")

# 导出 JSON
history.export_json("history.json")

# 导出 HAR
history.export_har("history.har")

# ========== 攻击面分析 ==========

surface = history.attack_surface()
print(f"端点: {len(surface['endpoints'])}")
print(f"ID 参数: {surface['params_by_type']['id_params']}")
print(f"文件参数: {surface['params_by_type']['file_params']}")
print(f"URL 参数: {surface['params_by_type']['url_params']}")

# ========== 清理 ==========

history.clear()  # 清空所有
history.clear(host="target.com")  # 清空指定 host
history.dedupe()  # 去重
```

---

## 完整工作流示例

```python
from aiburp.core import History, Repeater, Intruder, Request

# 1. 创建组件
history = History(project="pentest_target")
repeater = Repeater(history=history, delay=1.5)
intruder = Intruder(history=history, delay=1.5)

# 2. 添加初始请求到 History
req = Request(
    method="POST",
    url="https://target.com/api/login",
    headers={"Content-Type": "application/json"},
    body='{"username": "test", "password": "test123"}'
)
req_id = history.add(req)
print(f"请求 ID: {req_id}")

# 3. 用 Repeater 测试单个 payload
resp = repeater.send(request_id=req_id)
print(f"基线: {resp.status}/{resp.length}b")

resp = repeater.send(
    request_id=req_id,
    modify={"params": {"username": "admin'--"}}
)
print(f"测试: {resp.status}/{resp.length}b, 异常: {resp.anomalies}")

# 4. 用 Intruder 批量测试
report = intruder.attack(
    request_id=req_id,
    param="username",
    payloads=["'", "\"", "admin'--", "' OR '1'='1", "admin' AND '1'='1"],
    stop_on="error",
)

print(f"\n=== Intruder 报告 ===")
print(f"测试: {report.tested}/{report.total}")
for r in report.results:
    mark = "⚠️" if r.is_interesting else "  "
    print(f"{mark} {r.payload:20s} -> {r.status}/{r.length}b {r.anomalies}")

# 5. 分析攻击面
surface = history.attack_surface()
print(f"\n=== 攻击面 ===")
print(f"端点数: {len(surface['endpoints'])}")

# 6. 保存结果
history.export_json("pentest_history.json")

# 7. 清理
repeater.close()
intruder.close()
```

---

## 自动检测的异常类型

Repeater 和 Intruder 会自动检测以下异常：

### 数据库错误
| 异常类型 | 说明 |
|----------|------|
| `mysql_error` | MySQL 错误 |
| `postgresql_error` | PostgreSQL 错误 |
| `mssql_error` | MSSQL 错误 |
| `oracle_error` | Oracle 错误 |
| `sqlite_error` | SQLite 错误 |
| `access_error` | Access/JET 错误 |

### 代码错误
| 异常类型 | 说明 |
|----------|------|
| `php_warning` | PHP 警告 |
| `php_error` | PHP 错误 |
| `asp_error` | ASP/VBScript 错误 |
| `python_traceback` | Python 堆栈跟踪 |
| `stack_trace` | 通用堆栈跟踪 |

### 安全相关
| 异常类型 | 说明 |
|----------|------|
| `path_disclosure` | 路径泄露 |
| `blocked` | 被 WAF 拦截 |
| `waf_cloudflare` | Cloudflare WAF |
| `waf_akamai` | Akamai WAF |
| `waf_imperva` | Imperva WAF |


---

## 高级功能模块

以下是 AI-Burp 的高级功能模块，提供更专业的渗透测试能力。

---

## MITM 代理 - 流量拦截

类似 Burp Suite 的代理功能，拦截和分析 HTTPS 流量：

```python
from aiburp.mitm_proxy_v2 import Interceptor, start_proxy

# 快速启动
interceptor = start_proxy(port=8888, filter_hosts=["target.com"])

# 浏览器设置代理 127.0.0.1:8888
# 访问 http://mitm.it 安装 CA 证书

# 获取捕获的数据
endpoints = interceptor.get_endpoints()      # 发现的 API 端点
sensitive = interceptor.get_sensitive_endpoints()  # 敏感端点
params = interceptor.get_params()            # 所有参数
stats = interceptor.get_stats()              # 统计信息

# 导出数据
interceptor.export("captured.json")

# 打印摘要
interceptor.print_summary()

# 停止
interceptor.stop()
```

### 交互模式

```bash
python -m aiburp.mitm_proxy_v2 --port 8888 --filter target.com -i

# 命令:
#   stats  - 显示统计
#   eps    - 显示端点
#   sens   - 显示敏感端点
#   params - 显示参数
#   export - 导出数据
#   quit   - 退出
```

---

## 认证会话管理

管理多个认证会话，支持自动登录和 Cookie 导入：

```python
from aiburp.session import SessionManager

sm = SessionManager(project="my_test")

# ========== 自动登录 ==========
session = sm.login(
    login_url="https://target.com/login",
    username="admin",
    password="test123",
    save_as="admin_session"
)

# ========== 导入 Cookie ==========
session = sm.import_cookie(
    "PHPSESSID=xxx; token=yyy",
    save_as="session1"
)

# ========== 导入 Token ==========
session = sm.import_token(
    "eyJhbGciOiJIUzI1NiIs...",
    save_as="api_token",
    token_type="bearer"
)

# ========== 从 Burp 导入 ==========
session = sm.import_from_burp("burp_cookies.json", save_as="burp_session")

# ========== 使用会话 ==========
session = sm.load("admin_session")

from aiburp import Burp
burp = Burp()
# 使用 Cookie
burp.send("GET", "https://target.com/api", 
          headers={"Cookie": session.get_cookie_string()})

# ========== 会话管理 ==========
sessions = sm.list_sessions()      # 列出所有会话
sm.check_validity(session)         # 检查有效性
sm.delete("old_session")           # 删除会话

# ========== 导出会话 ==========
print(sm.export("admin_session", format="cookie"))  # Cookie 字符串
print(sm.export("admin_session", format="curl"))    # curl 命令
print(sm.export("admin_session", format="python"))  # Python 代码
```

---

## 子域名枚举

智能子域名发现，支持通配符检测：

```python
from aiburp.subdomain import SubdomainEnum, enum_subdomains

# 快速枚举
report = enum_subdomains("example.com")
print(report)

# 详细使用
enum = SubdomainEnum("example.com")

# 检测 DNS 通配符
wildcard = enum.detect_wildcard()
if wildcard.has_wildcard:
    print(f"⚠️ 检测到通配符: {wildcard.wildcard_ip}")

# 枚举子域名
report = enum.enumerate()
print(f"发现 {report.total_real} 个真实域名")

# 深度枚举 (包含三级子域名)
report = enum.deep_enumerate()

# 从 CT Logs 获取
ct_domains = enum.get_ct_domains()

# 只获取真实域名
real_domains = enum.get_real_domains()
for r in real_domains:
    print(f"{r.domain} -> {r.ip} ({r.title})")
```

---

## DNS 验证

检测 DNS 通配符和保留 IP 段：

```python
from aiburp.dns_validator import DNSValidator, validate_dns

# 快速验证
result = validate_dns("sub.example.com")
print(f"IP: {result.local_ip}, 类型: {result.ip_type}")
print(f"是否真实: {result.is_real}")

# 详细使用
validator = DNSValidator()

# 检测通配符
wildcard = validator.detect_wildcard("example.com")
if wildcard.has_wildcard:
    print(f"通配符 IP: {wildcard.wildcard_ip}")

# 过滤真实域名
domains = ["sub1.example.com", "sub2.example.com", "fake.example.com"]
real, fake = validator.filter_real_domains(domains)
print(f"真实: {real}")
print(f"假的: {fake}")

# 批量分析
report = validator.analyze_subdomain_batch(domains)
print(f"真实域名: {len(report['real'])}")
print(f"保留IP: {len(report['reserved_ip'])}")
```

---

## 资产侦察

批量扫描 IP 段，发现 Web 资产：

```python
from aiburp import Burp
from aiburp.recon import AssetRecon

burp = Burp()
recon = AssetRecon(burp, max_workers=50)

# 扫描 /24 网段
result = recon.scan_range("192.168.1.0/24")
print(f"存活: {result.alive_hosts}")
print(f"ASP 站点: {len(result.asp_sites)}")
print(f"PHP 站点: {len(result.php_sites)}")
print(f"电商站点: {len(result.ecom_sites)}")

# 测试发现的资产
result = recon.test_assets(result, test_sqli=True)
print(f"发现漏洞: {len(result.vulns)}")

# 扫描多个网段
result = recon.scan_ranges(["192.168.1.0/24", "192.168.2.0/24"])

# 生成拓扑报告
topology = recon.generate_topology(result)
print(topology)
```

---

## OOB 外带检测

使用 Interactsh 进行带外检测：

```python
from aiburp.core.oob import OOBManager, InteractshClient

# 简单使用
with OOBManager() as oob:
    # 生成带标记的 URL
    ssrf_url = oob.generate("ssrf-test")
    sqli_url = oob.generate("sqli-dns")
    
    print(f"SSRF URL: {ssrf_url}")
    # 发送包含 URL 的 payload...
    
    # 检查回调
    if oob.check("ssrf-test", timeout=30):
        print("🔥 SSRF 确认!")

# 详细使用
client = InteractshClient()
url = client.get_url()
http_url = client.get_http_url()

# 发送 payload 后轮询检查
callbacks = client.poll(timeout=30)
for cb in callbacks:
    print(f"收到回调: {cb.protocol} from {cb.remote_address}")

client.deregister()
```

---

## 自动发现

自动爬取页面，发现表单和参数：

```python
from aiburp import Burp
from aiburp.detectors import AutoDiscovery

burp = Burp()
discovery = AutoDiscovery(burp)

# 发现所有可测试参数
params = discovery.discover("https://target.com", depth=2)
for p in params:
    print(f"[{p.method}] {p.url} -> {p.param}={p.value}")

# 发现表单
forms = discovery.discover_forms("https://target.com/login")
for form in forms:
    print(f"[{form.method}] {form.action}")
    print(f"  参数: {list(form.params.keys())}")

# 发现带参数的链接
links = discovery.discover_links("https://target.com")
for link in links:
    print(link)
```

---

## 智能自动扫描

根据站点类型自动选择扫描策略：

```python
from aiburp import Burp
from aiburp.detectors import AutoScanner

burp = Burp()
scanner = AutoScanner(burp)

# 智能扫描 (自动识别站点类型)
report = scanner.scan("https://target.com", smart=True)
print(report)

# 指定扫描深度
report = scanner.scan("https://target.com", depth="full")  # quick/normal/full

# 指定测试类型
report = scanner.scan(
    "https://target.com",
    types=["sqli", "xss", "lfi"],
    test_headers=True,
    test_cookies=True
)

# 查看发现
for finding in scanner.findings:
    print(f"[{finding.confidence}] {finding.vuln_type}: {finding.evidence}")
```

### 站点类型识别

AutoScanner 会自动识别以下站点类型并调整策略：

| 站点类型 | 测试策略 |
|----------|----------|
| `iot` | 跳过注入测试 (IoT 设备) |
| `banking` | 轻量扫描，只测 SQLi |
| `admin` | 全面扫描 (SQLi/XSS/LFI) |
| `pos` | 重点 SQL 注入 |
| `api` | 接口测试 (SQLi/XSS) |
| `ecommerce` | 业务逻辑 (SQLi/XSS/IDOR) |

---

## CLI 命令参考

AI-Burp 提供丰富的命令行工具：

```bash
# 自动扫描 (推荐)
aiburp auto-scan https://target.com --depth full

# 智能探测
aiburp probe https://target.com/api id 1

# 漏洞扫描
aiburp scan https://target.com/api id 1 --types sqli xss

# 深度分析
aiburp deep-analyze https://target.com/login username test --post

# 目录发现
aiburp dirfuzz https://target.com --wordlist common

# XSS 检测
aiburp xss-scan https://target.com/search q test --deep

# 源码泄露检测
aiburp leak-scan https://target.com

# MSSQL 数据提取
aiburp mssql-extract https://target.com/product.asp pid 1

# 资产侦察
aiburp recon 192.168.1.0/24 --test

# 子域名收集
aiburp subdomain example.com --verify

# POC 扫描
aiburp poc-scan https://target.com --tags wordpress

# 端口扫描
aiburp portscan 192.168.1.1 --ports top100

# 认证管理
aiburp auth login https://target.com/login -u admin -p test --save session1
aiburp auth list
aiburp auth check session1

# 高性能 Fuzz
aiburp ffuzz "https://target.com/FUZZ" -w common -c 100
```

---

## 更新日志

### v0.17.0 (2025-12-25)
- 新增 `send()` 方法，支持 `json=` 参数
- `history` 改为属性，支持 `.count()`, `.recent()` 等方法
- `post()` 支持 `json=` 参数
- 完善文档，添加高级功能模块文档

### v0.16.0
- MITM 代理模块 (mitm_proxy_v2)
- 认证会话管理 (session)

### v0.13.0
- POC 扫描系统
- 子域名枚举
- DNS 验证

### v0.12.0
- MSSQL 数据提取
- 资产侦察模块

---

## 核心原则

1. **AI 是大脑，工具是手脚** - 工具只执行，AI 决策
2. **一切流量皆记录** - 所有请求都进 History
3. **最小影响，最大证明** - 证明漏洞存在即可
4. **Low Touch** - 单线程，1-2 秒延迟，模拟正常流量
