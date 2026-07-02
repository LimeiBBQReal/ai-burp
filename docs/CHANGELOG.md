# AI-Burp Changelog

## v0.17.0 (2025-12-25)

### API 统一与简化

解决的问题：API 不一致，`history` 是方法而不是属性，`send` 方法缺失，`json` 参数不支持。

#### 重大改进

1. **统一请求方法 `send()`**
   - 新增 `burp.send(method, url, json=, data=, headers=)` 方法
   - 支持 `json=` 参数直接发送 JSON 数据
   - 自动设置 `Content-Type: application/json`

2. **History 重构为属性**
   - `burp.history` 现在是 `HistoryList` 对象，不是方法
   - `burp.history.count()` - 请求数量
   - `burp.history.recent(n)` - 最近 n 条
   - `burp.history.errors()` - 所有错误
   - `burp.history.save()` - 保存到文件
   - `burp.history.clear()` - 清空

3. **post() 方法增强**
   - 支持 `json=` 参数: `burp.post(url, json={"key": "val"})`

4. **文档更新**
   - README 完全重写，添加 API 速查表
   - 添加完整使用示例

#### 迁移指南

```python
# 旧 API (v0.16.0)
burp.history(10)           # 方法调用
burp.post(url, data=json.dumps({"key": "val"}), headers={"Content-Type": "application/json"})

# 新 API (v0.17.0)
burp.history.recent(10)    # 属性访问
burp.post(url, json={"key": "val"})  # 直接传 json
burp.send("POST", url, json={"key": "val"})  # 推荐使用 send
```

---

## v0.18.0 (2025-12-24)

### 认证会话管理 (Auth Session)

解决的问题：测试认证后功能时，需要手动处理 Cookie/Token，无法保存和复用认证状态。

#### 新增功能

1. **SessionManager** - 会话管理器
   - 保存/加载认证会话 (Cookie/Token/Headers)
   - 自动登录并保存会话
   - 从浏览器/Burp 导入 Cookie
   - 会话有效性检测
   - 多会话管理

2. **auth 子命令** - CLI 认证管理
   - `auth login` - 自动登录并保存会话
   - `auth import-cookie` - 从 Cookie 字符串导入
   - `auth import-token` - 导入 Bearer/Basic Token
   - `auth import-burp` - 从 Burp Suite 导出文件导入
   - `auth list` - 列出所有保存的会话
   - `auth show` - 显示会话详情
   - `auth delete` - 删除会话
   - `auth check` - 检查会话有效性
   - `auth export` - 导出会话 (cookie/curl/python/burp 格式)

3. **Burp 类增强**
   - `set_session()` - 设置认证会话
   - `clear_session()` - 清除当前会话
   - `get_session_info()` - 获取当前会话信息
   - 请求自动携带会话 Cookie 和 Headers

4. **request 命令增强**
   - 新增 `--session` 参数，使用保存的会话发送请求

### 报告生成器 (Report Generator)

解决的问题：当前只有简单的文本输出，缺少专业的渗透测试报告。

#### 新增功能

1. **ReportGenerator** - 报告生成器
   - `generate_html()` - 生成专业 HTML 报告
   - `generate_md()` - 生成 Markdown 报告
   - `generate_json()` - 生成 JSON 报告
   - 漏洞按严重性排序
   - 请求/响应证据
   - 修复建议

2. **report 子命令** - CLI 报告生成
   - `report generate --format html -o report.html`
   - `report generate --format md -o report.md`
   - `report generate --format json -o report.json`

#### 使用示例

```bash
# 生成 HTML 报告
aiburp report generate --format html -o report.html --title "渗透测试报告" --target https://target.com

# 从 JSON 文件加载漏洞发现
aiburp report generate --format html -o report.html --findings findings.json
```

### 智能 Payload 生成器 (Smart Payload)

解决的问题：当前 payload 是静态的，无法根据上下文自动调整，遇到 WAF 时效率低下。

#### 新增功能

1. **SmartPayloadGenerator** - 智能 Payload 生成器
   - `detect_waf()` - WAF 检测与识别
   - `generate_bypass_payloads()` - 生成 WAF 绕过 payload
   - `adaptive_fuzz()` - 自适应 fuzz

2. **WAF 检测支持**
   - Cloudflare
   - Akamai
   - AWS WAF
   - Imperva
   - Sucuri
   - ModSecurity
   - F5 BIG-IP
   - Fortinet
   - Barracuda
   - Citrix

3. **waf-detect 命令** - WAF 检测
   - `aiburp waf-detect https://target.com`

4. **smart-fuzz 命令** - 智能 Fuzz
   - `aiburp smart-fuzz https://target.com/search q test --type sqli`

#### 使用示例

```bash
# 检测 WAF
aiburp waf-detect https://target.com

# 智能 Fuzz (自动检测 WAF 并绕过)
aiburp smart-fuzz https://target.com/search q test --type sqli --max 50
```

### 批量目标管理 (Target Manager)

解决的问题：多目标测试时缺少统一管理，无法批量操作。

#### 新增功能

1. **TargetManager** - 目标管理器
   - `import_urls()` - 导入目标列表
   - `add_url()` - 添加单个目标
   - `check_alive()` - 检查存活状态
   - `fingerprint_all()` - 批量指纹识别
   - `scan_all()` - 批量漏洞扫描
   - `export()` - 导出结果

2. **targets 子命令** - CLI 目标管理
   - `targets import urls.txt` - 导入目标
   - `targets add https://target.com` - 添加目标
   - `targets list` - 列出目标
   - `targets check` - 检查存活
   - `targets fingerprint` - 指纹识别
   - `targets scan --types sqli xss` - 漏洞扫描
   - `targets export -o results.json` - 导出结果
   - `targets clear` - 清空目标

#### 使用示例

```bash
# 导入目标
aiburp targets import urls.txt

# 检查存活
aiburp targets check --threads 10

# 批量指纹识别
aiburp targets fingerprint --threads 5

# 批量漏洞扫描
aiburp targets scan --types sqli xss

# 导出结果
aiburp targets export -o results.json --format json
```

#### Python API 示例

```python
from aiburp.target_manager import TargetManager

tm = TargetManager("heritage")
tm.import_urls("urls.txt")
tm.check_alive(threads=10)
tm.fingerprint_all()
tm.scan_all(types=["sqli", "xss"])
tm.print_summary()
tm.export("results.json")
```

---

## v0.17.0 (2025-12-23)

### 字典系统大幅扩展

解决的问题：原有字典太少 (quick 只有 30 行)，无法满足实际渗透测试需求。

#### 新增字典

| 字典名 | 行数 | 说明 |
|--------|------|------|
| `medium` | 20,115 | SecLists raft-small-directories |
| `large` | 4,749 | SecLists common |
| `full` | 2,032,840 | 合并大字典 |
| `seclists` | 4,749 | SecLists common (别名) |
| `raft-dirs` | 20,115 | SecLists raft-small-directories |
| `raft-files` | 11,424 | SecLists raft-small-files |
| `quickhits` | 2,563 | SecLists quickhits (敏感文件) |
| `backup` | 334 | 备份文件字典 |
| `fuzz` | 5,366 | bo0om fuzz 字典 |

#### 新增功能

- `--list-wordlists` 参数：列出所有可用字典及行数
- 字典路径自动检测和友好提示

#### 使用示例

```bash
# 列出所有可用字典
aiburp dirfuzz --list-wordlists

# 使用大字典扫描
aiburp dirfuzz https://target.com --wordlist large

# 使用敏感文件字典
aiburp dirfuzz https://target.com --wordlist quickhits
```

---

## v0.16.0 (2025-12-23)

### 新增功能

新增完整的 HTTPS 流量拦截器，类似 Burp Suite 的代理功能。

#### HTTPS 流量拦截器 (`mitm_proxy_v2.py`)

解决的问题：现代 SPA 应用使用 HTTPS，简单的 HTTP 代理无法解密流量。需要 MITM 代理来完整捕获 API 请求和响应。

新增功能：
- `Interceptor` - HTTPS 流量拦截器主类
- `TrafficCapture` - mitmproxy 插件，捕获请求/响应
- `start_interceptor()` - 快速启动拦截器
- `interactive_mode()` - 交互式命令行界面
- 完整的 HTTPS 解密
- 自动 API 端点发现
- 敏感参数自动标记 (password, token, pin, otp 等)
- 认证端点识别
- 请求/响应完整记录
- JSON 导出功能
- 实时流量显示

使用示例：
```python
from aiburp import Interceptor, start_interceptor

# 启动拦截器
interceptor = start_interceptor(port=8888, filter_hosts=["heritageibt.com"])

# 浏览器设置:
# 1. 代理: 127.0.0.1:8888
# 2. 访问 http://mitm.it 安装 CA 证书
# 3. 开始浏览目标网站

# 获取捕获的数据
endpoints = interceptor.get_endpoints()           # 所有端点
sensitive = interceptor.get_sensitive_endpoints() # 敏感端点
params = interceptor.get_params()                 # 参数列表

# 打印摘要
interceptor.print_summary()

# 导出数据
interceptor.export("captured.json")

# 停止
interceptor.stop()
```

命令行使用：
```bash
# 基本模式
python -m aiburp.mitm_proxy_v2 -p 8888 -f heritageibt.com

# 交互模式
python -m aiburp.mitm_proxy_v2 -i -f heritageibt.com

# 自动导出
python -m aiburp.mitm_proxy_v2 -p 8888 -f target.com -o captured.json
```

交互模式命令：
- `stats` - 显示统计信息
- `eps` - 显示发现的端点
- `sens` - 显示敏感端点
- `params` - 显示所有参数
- `export` - 导出数据
- `clear` - 清除数据
- `quit` - 退出

### 依赖

需要安装 mitmproxy：
```bash
pip install mitmproxy
```

---

## v0.15.0 (2025-12-23)

### 新增功能

新增代理模块和 JS 分析器，用于自动采集 SPA 应用的 API 端点和参数。

#### 代理服务器模块 (`proxy.py`)

解决的问题：现代 SPA 应用（如 Angular/React）的 API 端点难以通过静态分析完全发现，需要拦截实际流量。

新增功能：
- `ProxyServer` - HTTP 代理服务器
- `start_proxy()` - 快速启动代理
- 自动提取 API 端点
- 自动提取 URL 参数和 Body 参数
- 敏感参数标记（password, token 等）
- Host 过滤功能
- 静态资源自动排除
- 实时打印捕获的请求
- 导出 JSON 报告

使用示例：
```python
from aiburp import ProxyServer, start_proxy

# 启动代理
proxy = start_proxy(port=8888, filter_hosts=["target.com"])

# 浏览器设置代理 127.0.0.1:8888，操作目标网站...

# 获取数据
endpoints = proxy.get_endpoints()
params = proxy.get_params()
proxy.print_summary()
proxy.export("api_map.json")
proxy.stop()
```

#### MITM 代理模块 (`mitm_proxy.py`)

新增功能：
- `MitmProxy` - HTTPS 解密代理（需要 mitmproxy 库）
- `JsApiExtractor` - JS 文件 API 提取器
- `extract_api_from_js()` - 从 URL 自动提取 API

JS 分析器使用示例：
```python
from aiburp import JsApiExtractor, extract_api_from_js

# 方式1: 分析 URL
result = extract_api_from_js("https://target.com/app/")
print(result["endpoints"])
print(result["params"])

# 方式2: 分析本地 JS 文件
extractor = JsApiExtractor()
with open("main.js") as f:
    extractor._analyze_js(f.read())
print(extractor.endpoints)
print(extractor.params)
```

### 实战应用

在 Heritage Bank 测试中，通过 JS 分析发现：
- 33 个 `/customer/*` API 端点
- 语音命令 API (`/customer/voiceCommand/*`)
- 166 个路由路径
- 敏感参数：password, pin, code, email 等

---

## v0.14.0 (2025-12-22)

### 新增功能

基于 Heritage IBT 实战经验，新增 DNS 验证和子域名枚举模块。

#### DNS 验证模块 (`dns_validator.py`)

解决的问题：在 Heritage IBT 测试中发现，目标配置了 DNS 通配符，导致任何子域名都能解析，且所有 IP 都在 IANA 保留段 (198.18.0.0/15)。这导致大量"假"域名被误认为真实资产。

新增功能：
- `DNSValidator` - DNS 验证器类
- `check_wildcard()` - 检测 DNS 通配符配置
- `validate_dns()` - 验证单个域名真实性
- `filter_real()` - 批量过滤真实域名
- IANA 保留 IP 段识别 (RFC 2544 等)
- 多 DNS 服务器对比验证
- 蜜罐/欺骗环境检测

使用示例：
```python
from aiburp import DNSValidator, check_wildcard, validate_dns

# 检测 DNS 通配符
wildcard = check_wildcard("example.com")
if wildcard.has_wildcard:
    print(f"⚠️ 检测到通配符! IPs: {wildcard.resolved_ips}")

# 验证域名
result = validate_dns("sub.example.com")
if result.is_reserved_ip:
    print(f"⚠️ IP 在保留段: {result.ip_type}")

# 批量分析
validator = DNSValidator()
report = validator.analyze_subdomain_batch(domains)
```

#### 子域名枚举模块 (`subdomain.py`)

新增功能：
- `SubdomainEnum` - 智能子域名枚举器
- `enum_subdomains()` - 快速枚举函数
- 自动检测 DNS 通配符
- 占位页面识别和过滤
- 多级子域名支持 (二级、三级)
- CT Logs 查询集成
- 真实域名 vs 假域名区分

使用示例：
```python
from aiburp import SubdomainEnum, enum_subdomains

# 快速枚举
report = enum_subdomains("example.com")
print(f"真实域名: {len(report.real_domains)}")
print(f"占位页面: {len(report.placeholder_domains)}")

# 深度枚举 (包含三级子域名)
enum = SubdomainEnum("example.com")
report = enum.deep_enumerate()

# 获取 CT Logs 域名
ct_domains = enum.get_ct_domains()
```

### 实战经验总结

1. **DNS 通配符检测很重要** - 在爆破子域名前先检测通配符，避免浪费时间
2. **保留 IP 段识别** - 198.18.0.0/15 是基准测试 IP 段，不应该在生产环境使用
3. **占位页面过滤** - "under development" 等占位页面应该被过滤
4. **HTTP 验证** - DNS 解析成功不代表有真实服务，需要 HTTP 验证

---

## v0.13.0 (2025-12-20)

### 新增功能

- `compare_headers()` - HTTP 头对比
- `scan_github_repo()` - GitHub 仓库敏感信息扫描
- `discover_params()` - 参数发现
- `discover_hidden_apis()` - 隐藏 API 发现

---

## v0.12.0 (2025-12-15)

### 新增功能

- `MSSQLExtractor` - MSSQL 数据提取器
- `AssetRecon` - 资产侦察模块

---

## v0.11.0 及更早版本

- 核心 Burp 类
- Payload 加载器
- 漏洞检测器 (SQLi, XSS, SSRF, CMDi, LFI, SSTI)
