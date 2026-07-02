# AI-Burp V3 完整指南 (面向 AI)

## 一、架构概览

```
aiburp/
├── burp.py              # V3 核心: AsyncBurp, AsyncSmartBurp, IntentAnalyzer
├── sync_wrapper.py      # 同步包装器: SyncBurp, SyncSmartBurp
├── intel.py             # 智能层: KnowledgeBase, AttackGraph, VulnerabilityChainer
├── stealth.py           # 隐身模块: StealthClient, AdaptiveRateLimiter
├── detectors.py         # 统一检测器: AsyncVulnScanner, SQLi/XSS/SSRF/CMDi/LFI/SSTI
├── payloads.py          # Payload 加载器: SQLI, XSS, LFI, SSRF, CMDi, SSTI, Bypass
├── session.py           # 会话管理: SessionManager, 自动登录, Cookie 导入
├── browser.py           # 浏览器模块: BrowserBurp (Playwright)
├── discovery.py         # 目录发现: DirFuzzer, 403 绕过
├── recon.py             # 资产侦察: AssetRecon
├── param_discover.py    # 参数发现: ParamDiscoverer, GraphQL/WebSocket/SourceMap
├── core/
│   ├── proxy.py         # MITM 代理 (mitmproxy)
│   ├── history.py       # 流量存储 (SQLite)
│   ├── repeater.py      # 请求重放, SQLi/XSS 测试
│   ├── intruder.py      # 批量 Fuzz
│   ├── traffic_diff.py  # 流量对比分析
│   ├── auth_manager.py  # 多账户管理, JWT 刷新
│   └── oob.py           # Interactsh OOB 检测
└── plugins/recon/
    ├── waf_detect.py    # WAF 检测 + 13 个绕过字典
    └── traffic_analyzer.py  # 深度流量分析
```

---

## 二、核心模块详解

### 2.1 AsyncBurp / SyncBurp (burp.py, sync_wrapper.py)

**用途**: HTTP 请求引擎，支持异步和同步两种模式

```python
from aiburp import SyncBurp, AsyncBurp

# 同步模式 (推荐新手)
burp = SyncBurp(project="target", delay=1.0)
r = burp.get("https://target.com/api")
r = burp.post("https://target.com/login", data={"user": "admin"})

# 异步模式 (高性能)
async with AsyncBurp(project="target") as burp:
    r = await burp.get("https://target.com")
```

**关键方法**:
- `get(url, params, headers)` - GET 请求
- `post(url, data, json, headers)` - POST 请求
- `request(method, url, **kwargs)` - 通用请求
- `probe(url)` - 智能探测 (自动发现参数、检测漏洞)

---

### 2.2 StealthClient (stealth.py) ⭐ WAF 规避

**用途**: JA3 指纹伪装 + 自适应限速，绕过 WAF/Bot 检测

```python
from aiburp import StealthClient, AdaptiveRateLimiter, BROWSER_PROFILES

# 使用 Chrome 120 指纹
client = StealthClient(profile="chrome_120")
r = await client.get("https://target.com")

# 随机指纹
client = StealthClient(profile="random")

# 自适应限速 (遇到 429 自动退避)
limiter = AdaptiveRateLimiter(base_delay=1.0, max_delay=60.0)
client = StealthClient(rate_limiter=limiter)

# 轮换指纹
client.rotate_profile()
```

**可用指纹**: `chrome_120`, `chrome_119`, `firefox_121`, `safari_17`, `edge_120`, `random`

**AdaptiveRateLimiter 特性**:
- 遇到 429/503 自动指数退避
- 解析 `Retry-After` 头
- 成功后逐步恢复速度

---

### 2.3 WAFDetector (plugins/recon/waf_detect.py) ⭐ WAF 检测

**用途**: 检测 WAF 类型 + 获取对应绕过 payload

```python
from aiburp.plugins.recon.waf_detect import WAFDetector

detector = WAFDetector()
result = detector.detect("https://target.com", aggressive=True)

if result.detected:
    print(f"WAF: {result.waf_name}, 置信度: {result.confidence}")
    
    # 获取绕过 payload
    payloads = detector.get_bypass_payloads(result.waf_name)
```

**支持的 WAF**: Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva

**13 个绕过字典**:
| 字典名 | 数量 | 用途 |
|--------|------|------|
| cloudflare | 39 | Cloudflare 专用 |
| aws_waf | 27 | AWS WAF 专用 |
| modsecurity | 43 | ModSecurity 专用 |
| akamai | 17 | Akamai 专用 |
| imperva | 17 | Imperva 专用 |
| unicode | 47 | Unicode 编码绕过 |
| http_smuggling | 48 | HTTP 走私 |
| waf_encoding | 31 | 编码绕过 |
| waf_keywords | 42 | 关键字绕过 |
| waf_space | 13 | 空格绕过 |
| waf_quotes | 14 | 引号绕过 |
| waf_advanced | 49 | 高级绕过 |
| exotic | 61 | 特殊技巧 |

---

### 2.4 ParamDiscoverer (param_discover.py) ⭐ 深度参数发现

**用途**: 从 JS/HTML 中挖掘 API 端点、敏感信息、隐藏参数

```python
from aiburp.param_discover import ParamDiscoverer

pd = ParamDiscoverer(timeout=10, max_js=20)
result = pd.discover("https://target.com", depth=1, analyze_js=True)

# 发现的端点
for ep in result.endpoints:
    print(f"[{ep.method}] {ep.url} (来源: {ep.source})")

# JS 中的敏感信息
for secret in result.js_secrets:
    print(f"[{secret.type}] {secret.value[:50]}...")

# GraphQL 端点
for gql in result.graphql_endpoints:
    print(f"GraphQL: {gql['url']}, Introspection: {gql['introspection']}")

# WebSocket URL
for ws in result.websocket_urls:
    print(f"WebSocket: {ws}")

# Source Map 泄露
for sm in result.source_maps:
    print(f"SourceMap: {sm['map_url']}, 可访问: {sm['accessible']}")

# 探测隐藏参数
hidden = pd.probe_hidden_params("https://target.com/api", params=["debug", "admin", "test"])
```

**发现能力**:
- JS 中的 API 端点 (fetch, axios, $.ajax)
- 敏感信息 (api_key, token, password, AWS 密钥, 内网 IP)
- GraphQL 端点 + Introspection 检测
- WebSocket URL
- Source Map 泄露
- 隐藏参数探测


---

### 2.5 TrafficAnalyzer (plugins/recon/traffic_analyzer.py)

**用途**: 从 History 中深度分析流量，提取攻击面

```python
from aiburp.plugins.recon.traffic_analyzer import TrafficAnalyzer, analyze_traffic

analyzer = TrafficAnalyzer(history, base_url="https://target.com")
result = analyzer.analyze_all()

# 发现的端点
print(result.endpoints)

# 各来源的参数
print(result.params_from_js)    # JS 中发现
print(result.params_from_html)  # HTML 表单
print(result.params_from_json)  # JSON 响应
print(result.all_params)        # 全部参数

# 隐藏表单字段
print(result.hidden_fields)

# 敏感信息
print(result.secrets)
```

---

### 2.6 History (core/history.py) ⭐ 流量存储

**用途**: SQLite 存储所有请求，支持查询、导入导出

```python
from aiburp.core import History

history = History(project="target")

# 添加请求
req_id = history.add(request)

# 查询
requests = history.list(host="target.com", method="POST", limit=100)
request = history.get(id=123)

# 搜索
results = history.search("password")

# 攻击面分析
surface = history.attack_surface()
print(surface["params_by_type"]["id_params"])  # 可能的 IDOR
print(surface["params_by_type"]["file_params"]) # 可能的 LFI

# 导入/导出
history.import_har("export.har")
history.import_burp_xml("burp.xml")
history.export_json("history.json")
```

---

### 2.7 Proxy (core/proxy.py) ⭐ MITM 代理

**用途**: 拦截浏览器流量，自动记录到 History

```python
from aiburp.core.proxy import Proxy, ProxyConfig, InterceptRule

config = ProxyConfig(port=8080)
proxy = Proxy(history, config)

# 添加拦截规则
proxy.add_rule(InterceptRule(
    name="api_only",
    path_pattern=r"/api/",
    tags=["api"]
))

# 设置作用域
proxy.scope(["target.com", "api.target.com"])
proxy.exclude(["google.com"])

# 启动
proxy.start()
# 配置浏览器代理到 127.0.0.1:8080

# 停止
proxy.stop()
```

---

### 2.8 Repeater (core/repeater.py) ⭐ 请求重放

**用途**: 重放请求、修改参数、检测漏洞

```python
from aiburp.core import Repeater

repeater = Repeater(history, timeout=30, delay=1.0)

# 重放请求
resp = repeater.send(request_id=123)

# 修改参数重放
resp = repeater.send(request_id=123, modify={"params": {"id": "1'"}})

# SQL 注入测试
result = repeater.test_sqli(request, param="id")
if result.vulnerable:
    print(f"SQLi! Payload: {result.payload}, Evidence: {result.evidence}")

# XSS 测试
result = repeater.test_xss(request, param="q")

# 自定义 Fuzz
fuzz_result = repeater.fuzz(request, param="id", payloads=["'", "\"", "1 OR 1=1"])
for r in fuzz_result.results:
    if r.is_interesting:
        print(f"{r.payload}: {r.anomalies}")
```

---

### 2.9 Intruder (core/intruder.py) ⭐ 批量测试

**用途**: 批量 Fuzz，支持停止条件

```python
from aiburp.core import Intruder

intruder = Intruder(history, timeout=30, delay=1.0)

# 批量测试
report = intruder.attack(
    request_id=123,
    param="id",
    payloads=["'", "1 OR 1=1", "1 AND 1=2"],
    stop_on="anomaly"  # 发现异常就停
)

# 查看结果
for r in report.results:
    if r.is_interesting:
        print(f"{r.payload}: status={r.status}, anomalies={r.anomalies}")

# 快速测试 (内置 payload)
result = intruder.quick_test(request_id=123, param="id", test_type="sqli")
```

**stop_on 选项**: `anomaly`, `error`, `reflect`, `block`, `None`

---

### 2.10 TrafficDiff (core/traffic_diff.py)

**用途**: 对比历史流量，发现隐藏参数和异常

```python
from aiburp.core.traffic_diff import TrafficDiff

diff = TrafficDiff(history)

# 对比同一 URL 的历史请求
result = diff.diff_by_url("https://target.com/api/users")
print(result.inconsistent_params)  # 不一致出现的参数
print(result.anomalies)            # 异常请求

# 发现隐藏参数
hidden = diff.discover_hidden_params("https://target.com/api/users")

# 跨端点分析
cross = diff.cross_endpoint_analysis(["/api/users", "/api/admin"])
print(cross.potential_issues)  # 潜在问题
```

---

### 2.11 SessionManager (session.py) ⭐ 会话管理

**用途**: 保存/加载认证会话，自动登录

```python
from aiburp.session import SessionManager

sm = SessionManager(project="target")

# 自动登录
session = sm.login(
    login_url="https://target.com/login",
    username="admin",
    password="password",
    save_as="admin_session"
)

# 导入 Cookie
sm.import_cookie("PHPSESSID=xxx; token=yyy", save_as="session1")

# 导入 Token
sm.import_token("eyJhbGciOiJIUzI1NiIs...", save_as="jwt_session", token_type="bearer")

# 加载会话
session = sm.load("admin_session")

# 检查有效性
if sm.check_validity(session, check_url="https://target.com/dashboard"):
    print("会话有效")

# 导出
curl_cmd = sm.export("admin_session", format="curl")
```

---

### 2.12 AuthManager (core/auth_manager.py) ⭐ 多账户管理

**用途**: 多账户切换，IDOR 测试，JWT 自动刷新

```python
from aiburp.core.auth_manager import AuthManager

auth = AuthManager()

# 添加账户
auth.add_account("admin", cookies={"session": "xxx"}, role="admin")
auth.add_account("user", headers={"Authorization": "Bearer yyy"}, role="user")

# 切换账户
auth.switch("admin")

# 注入认证到请求
request = auth.inject(request)

# 为所有账户生成请求 (IDOR 测试)
requests = auth.inject_for_all(request)

# JSON API 登录
auth.login_json(
    url="https://target.com/api/login",
    data={"username": "admin", "password": "pass"},
    token_path="data.access_token"
)

# 保存/加载
auth.save("auth.json")
auth.load("auth.json")
```

---

### 2.13 OOBManager (core/oob.py) ⭐ 外带检测

**用途**: Interactsh OOB 检测 (SSRF/XXE/RCE 确认)

```python
from aiburp.core.oob import OOBManager, InteractshClient

# 简化用法
with OOBManager() as oob:
    # 生成带标记的 URL
    ssrf_url = oob.generate("ssrf-test")
    
    # 发送 payload 后检查
    if oob.check("ssrf-test", timeout=10):
        print("SSRF 确认!")

# 完整用法
client = InteractshClient()
url = client.get_http_url(prefix="test")
# 发送 payload...
callbacks = client.poll(timeout=30)
for cb in callbacks:
    print(f"{cb.protocol} from {cb.remote_address}")
```


---

### 2.14 BrowserBurp (browser.py) ⭐ 浏览器自动化

**用途**: Playwright 驱动，AI 的"眼睛"和"手"

```python
from aiburp import BrowserBurp

with BrowserBurp(project="target", headless=True) as browser:
    # 访问页面
    view = browser.see("https://target.com/login")
    print(view.forms)   # 表单列表
    print(view.links)   # 链接列表
    print(view.inputs)  # 输入框列表
    
    # 操作页面
    browser.fill("#username", "admin")
    browser.fill("#password", "password")
    view = browser.click("#login-btn")
    
    # 截图
    screenshot_b64 = browser.screenshot()
    
    # 执行 JS
    title = browser.eval("document.title")
    
    # Cookie 操作
    cookies = browser.get_cookies()
    browser.set_cookies([{"name": "test", "value": "123", "domain": "target.com"}])
```

---

### 2.15 DirFuzzer (discovery.py) ⭐ 目录发现 + 403 绕过

**用途**: 目录爆破，智能 403 绕过

```python
from aiburp.discovery import DirFuzzer, bypass403_command

fuzzer = DirFuzzer(burp, threads=10)

# 目录爆破
report = fuzzer.fuzz(
    url="https://target.com",
    wordlist="quick",      # quick/common/asp/sensitive
    extensions=[".php", ".asp"],
    bypass=True,           # 尝试绕过 401/403
    combo_mode=True        # 目录+文件组合
)

print(report.found_dirs)
print(report.sensitive)

# 403 绕过
bypass403_command(burp, "https://target.com/admin", aggressive=True)
```

**403 绕过技术**:
- 路径后缀: `/`, `/.`, `/..;/`, `.json`, `.css`
- 路径前缀: `../`, `..;/`, `%2e/`
- Header: `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`
- HTTP 方法: POST, HEAD, OPTIONS

---

### 2.16 VulnScanner / AsyncVulnScanner (detectors.py)

**用途**: 统一漏洞扫描器

```python
from aiburp import AsyncVulnScanner, VulnScanner

# 异步
scanner = AsyncVulnScanner(burp)
findings = await scanner.scan(url, param, value, types=["sqli", "xss"])

# 同步
scanner = VulnScanner(burp)
findings = scanner.scan_all(url, param, value)

for f in findings:
    print(f"[{f.confidence}] {f.vuln_type}: {f.evidence}")
```

**支持的漏洞类型**: `sqli`, `xss`, `ssrf`, `cmdi`, `lfi`, `ssti`

---

### 2.17 Payloads (payloads.py)

**用途**: 按需加载 Payload

```python
from aiburp import Payloads, SQLI, XSS, LFI, SSRF, CMDi, SSTI, Bypass

# 快速 payload
payloads = SQLI.quick
payloads = XSS.quick

# 完整 payload
payloads = SQLI.time_based
payloads = SQLI.error_based
payloads = SQLI.union
payloads = SQLI.auth_bypass
payloads = SQLI.waf_bypass

# 策略选择
payloads = SQLI.select(db_type="mysql", injection_type="time", has_waf=True)

# WAF 绕过变体
variants = Bypass.apply("' OR 1=1", waf_type="cloudflare")
```

---

### 2.18 KnowledgeBase + AttackGraph (intel.py) ⭐ 智能层

**用途**: 跨请求记忆 + 漏洞链分析

```python
from aiburp import KnowledgeBase, VulnerabilityChainer, AttackGraph

# 知识库
kb = KnowledgeBase(project="target")
kb.add("credential", "admin:Gjj534$jjf", source_url="https://target.com/config")
kb.add("internal_ip", "192.168.1.100", source_url="https://target.com/api")

# 查询
creds = kb.get_by_type("credential")
results = kb.query("admin")

# 漏洞链分析
chainer = VulnerabilityChainer(kb)
suggestions = chainer.suggest_next_steps(findings)
for s in suggestions:
    print(f"{s['action']}: {s['reason']} (优先级: {s['priority']})")

# 攻击图路径搜索
graph = AttackGraph()
paths = graph.find_paths("ssrf", max_depth=3)
for path in paths:
    print(" -> ".join([f"{n}({r})" for n, r in path]))
```

**预定义攻击链**:
- SSRF → 内网扫描 → Redis RCE
- SQLi → 文件读取 → 凭据提取 → RCE
- LFI → 日志投毒 → RCE
- 凭据 → 提权 → 横向移动

---

## 三、典型工作流

### 3.1 深度爬取 + 参数发现

```python
from aiburp import BrowserBurp, StealthClient
from aiburp.param_discover import ParamDiscoverer
from aiburp.plugins.recon.traffic_analyzer import TrafficAnalyzer

# 1. 浏览器爬取 (流量自动记录到 History)
with BrowserBurp(project="target") as browser:
    view = browser.see("https://target.com")
    for link in view.links[:20]:
        browser.see(link.href)

# 2. 参数发现
pd = ParamDiscoverer()
result = pd.discover("https://target.com", analyze_js=True)

# 3. 流量分析
analyzer = TrafficAnalyzer(browser.history)
analysis = analyzer.analyze_all()

# 4. 汇总攻击面
all_params = result.params_found | analysis.all_params
```

### 3.2 WAF 绕过测试

```python
from aiburp import StealthClient, AdaptiveRateLimiter
from aiburp.plugins.recon.waf_detect import WAFDetector

# 1. 检测 WAF
detector = WAFDetector()
waf = detector.detect("https://target.com", aggressive=True)

# 2. 获取绕过 payload
if waf.detected:
    payloads = detector.get_bypass_payloads(waf.waf_name)
    
# 3. 使用隐身客户端
limiter = AdaptiveRateLimiter(base_delay=2.0)
async with StealthClient(profile="chrome_120", rate_limiter=limiter) as client:
    for payload in payloads:
        r = await client.get(f"https://target.com/search?q={payload}")
        if r["status"] != 403:
            print(f"绕过成功: {payload}")
```

### 3.3 IDOR 批量测试

```python
from aiburp.core.auth_manager import AuthManager
from aiburp import SyncBurp

auth = AuthManager()
auth.add_account("admin", cookies={"session": "admin_token"}, role="admin")
auth.add_account("user", cookies={"session": "user_token"}, role="user")

burp = SyncBurp()

# 获取 admin 的资源
auth.switch("admin")
admin_req = burp.get("https://target.com/api/users/1")

# 用 user 账户访问
auth.switch("user")
user_req = auth.inject(admin_req)
r = burp.send(user_req)

if r.status == 200:
    print("IDOR 确认!")
```


---

## 四、关键常量

### SQL 错误模式 (constants.py)
```python
SQL_ERRORS = {
    "mysql": ["SQL syntax.*MySQL", "Warning.*mysql_", ...],
    "postgresql": ["PostgreSQL.*ERROR", "pg_query", ...],
    "mssql": ["Microsoft.*ODBC", "SQL Server", ...],
    "oracle": ["ORA-\\d{5}", ...],
    "sqlite": ["SQLite.*error", ...],
}
```

### WAF 签名 (constants.py)
```python
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid"],
    "akamai": ["akamai", "x-akamai"],
    "imperva": ["incap_ses", "visid_incap"],
    ...
}
```

---

## 五、导入速查

```python
# V3 核心
from aiburp import AsyncBurp, SyncBurp, AsyncSmartBurp, SyncSmartBurp

# 隐身模块
from aiburp import StealthClient, AdaptiveRateLimiter, BROWSER_PROFILES

# 智能层
from aiburp import KnowledgeBase, VulnerabilityChainer, AttackGraph, DependencyInjector

# 检测器
from aiburp import AsyncVulnScanner, VulnScanner, Finding
from aiburp import SQLiDetector, XSSDetector, SSRFDetector, CMDiDetector, LFIDetector, SSTIDetector

# Payload
from aiburp import Payloads, SQLI, XSS, LFI, SSRF, CMDi, SSTI, Bypass

# 核心模块
from aiburp.core import History, Repeater, Intruder
from aiburp.core.proxy import Proxy, ProxyConfig
from aiburp.core.traffic_diff import TrafficDiff
from aiburp.core.auth_manager import AuthManager
from aiburp.core.oob import OOBManager, InteractshClient

# 浏览器
from aiburp import BrowserBurp

# 发现模块
from aiburp.param_discover import ParamDiscoverer
from aiburp.discovery import DirFuzzer
from aiburp.recon import AssetRecon

# 会话
from aiburp.session import SessionManager

# WAF
from aiburp.plugins.recon.waf_detect import WAFDetector

# 流量分析
from aiburp.plugins.recon.traffic_analyzer import TrafficAnalyzer
```

---

**文档版本**: V3.0.0 | **更新日期**: 2025-12-29
